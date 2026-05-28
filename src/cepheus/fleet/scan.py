"""``cepheus fleet scan`` — analyze every pod in a cluster."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from cepheus.config import CepheusConfig
from cepheus.engine.analyzer import analyze
from cepheus.importers.podspec import posture_from_podspec
from cepheus.models.result import AnalysisResult

logger = logging.getLogger("cepheus.fleet")


class FleetScanError(RuntimeError):
    """Raised when the fleet scanner cannot enumerate the cluster — kubectl
    missing, kubeconfig invalid, apiserver unreachable, etc. Distinct from
    a per-pod analyzer error (recorded in ``PodReport.error`` and surfaced
    in the report rather than crashing the run)."""


@dataclass
class PodReport:
    """The analyzer result for a single pod, plus enough Kubernetes
    metadata to identify it in a diff. ``error`` is set when the
    importer or analyzer rejected the spec; in that case ``chains``,
    ``total_techniques_checked``, and ``techniques_matched`` are 0."""

    namespace: str
    name: str
    node: str | None
    labels: dict[str, str] = field(default_factory=dict)
    chain_ids: list[str] = field(default_factory=list)
    critical_chain_count: int = 0
    high_chain_count: int = 0
    medium_chain_count: int = 0
    low_chain_count: int = 0
    top_chain_score: float = 0.0
    techniques_matched: int = 0
    total_techniques_checked: int = 0
    error: str | None = None

    @classmethod
    def from_analysis(
        cls,
        *,
        namespace: str,
        name: str,
        node: str | None,
        labels: dict[str, str],
        result: AnalysisResult,
    ) -> PodReport:
        sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for c in result.chains:
            sev = c.severity.value if hasattr(c.severity, "value") else str(c.severity)
            if sev in sev_count:
                sev_count[sev] += 1
        top_score = max((c.composite_score for c in result.chains), default=0.0)
        return cls(
            namespace=namespace,
            name=name,
            node=node,
            labels=dict(labels or {}),
            chain_ids=[c.id for c in result.chains],
            critical_chain_count=sev_count["critical"],
            high_chain_count=sev_count["high"],
            medium_chain_count=sev_count["medium"],
            low_chain_count=sev_count["low"],
            top_chain_score=top_score,
            techniques_matched=result.techniques_matched,
            total_techniques_checked=result.total_techniques_checked,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "namespace": self.namespace,
            "name": self.name,
            "node": self.node,
            "labels": self.labels,
            "chain_ids": self.chain_ids,
            "severity_counts": {
                "critical": self.critical_chain_count,
                "high": self.high_chain_count,
                "medium": self.medium_chain_count,
                "low": self.low_chain_count,
            },
            "top_chain_score": self.top_chain_score,
            "techniques_matched": self.techniques_matched,
            "total_techniques_checked": self.total_techniques_checked,
            "error": self.error,
        }


@dataclass
class FleetReport:
    """A snapshot of every pod's posture at a point in time."""

    cluster_context: str | None
    pod_count: int
    error_count: int
    pods: list[PodReport]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "cluster_context": self.cluster_context,
            "pod_count": self.pod_count,
            "error_count": self.error_count,
            "pods": [p.to_dict() for p in self.pods],
        }


def _kubectl_get_pods(
    *,
    namespace: str | None,
    selector: str | None,
    context: str | None,
    kubeconfig: str | None,
    kubectl_bin: str = "kubectl",
    timeout: float = 60.0,
) -> dict:
    """Run ``kubectl get pods -o json`` with the given filters and return
    the parsed response. Raises ``FleetScanError`` on any failure that
    prevents enumeration — the caller cannot proceed without a pod list."""
    if shutil.which(kubectl_bin) is None:
        raise FleetScanError(
            f"{kubectl_bin!r} not found in PATH — fleet operations require kubectl. "
            "Install kubectl and ensure your kubeconfig points at the target cluster."
        )

    cmd: list[str] = [kubectl_bin]
    if kubeconfig:
        cmd += ["--kubeconfig", kubeconfig]
    if context:
        cmd += ["--context", context]
    cmd += ["get", "pods", "-o", "json"]
    if namespace:
        cmd += ["--namespace", namespace]
    else:
        cmd += ["--all-namespaces"]
    if selector:
        cmd += ["--selector", selector]
    cmd += ["--field-selector", "status.phase=Running"]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise FleetScanError(f"kubectl get pods timed out after {timeout}s") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise FleetScanError(f"kubectl invocation failed: {type(exc).__name__}: {exc}") from exc

    if proc.returncode != 0:
        raise FleetScanError(f"kubectl exited {proc.returncode}: {proc.stderr.strip() or '(no stderr)'}")

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise FleetScanError(f"kubectl returned non-JSON: {exc}") from exc


def _analyze_pod(item: dict, cfg: CepheusConfig) -> PodReport:
    """Convert a single ``kubectl get pods -o json`` entry into a
    PodReport. Per-pod errors are captured in ``PodReport.error`` rather
    than raised — a single malformed pod must not abort the entire scan
    of a cluster that may have thousands of pods."""
    # kubectl can in principle return a pod whose ``spec`` / ``metadata``
    # / ``status`` field is a non-dict (e.g. a partial-deletion record,
    # or a future API surface we don't know about yet). Coerce each
    # field to a dict up-front so the rest of this function can use
    # plain ``.get()`` calls without crashing. A non-dict field is also
    # a structural error worth recording — surface it via ``error`` so
    # the caller can diff it rather than silently swallowing the pod.
    metadata_raw = item.get("metadata")
    metadata = metadata_raw if isinstance(metadata_raw, dict) else {}
    spec_raw = item.get("spec")
    spec = spec_raw if isinstance(spec_raw, dict) else {}
    status_raw = item.get("status")
    status = status_raw if isinstance(status_raw, dict) else {}
    namespace = metadata.get("namespace", "")
    name = metadata.get("name", "")
    node = spec.get("nodeName") or status.get("nominatedNodeName")
    labels = metadata.get("labels") or {}

    if not isinstance(spec_raw, dict):
        return PodReport(
            namespace=namespace,
            name=name,
            node=node,
            labels=labels,
            error=f"spec is not a JSON object (got {type(spec_raw).__name__})",
        )

    if not spec:
        return PodReport(
            namespace=namespace,
            name=name,
            node=node,
            labels=labels,
            error="missing spec (likely pod still being initialized)",
        )

    try:
        posture = posture_from_podspec(spec, namespace=namespace, pod_name=name)
        result = analyze(posture, cfg)
    except Exception as exc:  # noqa: BLE001
        # KEEP the per-pod failure visible in the report — silently
        # dropping it would let a single broken pod hide a real
        # change in the diff. A broad catch is deliberate here: the
        # module's contract is total per-pod isolation so one malformed
        # pod can't abort a scan of a cluster with thousands of pods.
        # The error is recorded (and logged), never swallowed.
        logger.warning("fleet scan: pod %s/%s analyze failed: %s", namespace, name, exc)
        return PodReport(
            namespace=namespace,
            name=name,
            node=node,
            labels=labels,
            error=f"{type(exc).__name__}: {exc}",
        )

    return PodReport.from_analysis(
        namespace=namespace,
        name=name,
        node=node,
        labels=labels,
        result=result,
    )


def scan_cluster(
    *,
    namespace: str | None = None,
    selector: str | None = None,
    context: str | None = None,
    kubeconfig: str | None = None,
    parallel: int = 8,
    cfg: CepheusConfig | None = None,
    kubectl_bin: str = "kubectl",
) -> FleetReport:
    """Enumerate matching pods via kubectl and analyze each one. Returns
    a FleetReport that can be serialized via ``to_dict()`` and then
    diffed against a later snapshot.

    Args:
        namespace: Limit scan to one namespace; default scans all namespaces.
        selector: Label selector passed to ``kubectl --selector`` (e.g.,
            ``"app=api,tier=backend"``).
        context: kubeconfig context to use; default is the current context.
        kubeconfig: Override kubeconfig path; default is the user's KUBECONFIG / ~/.kube/config.
        parallel: Number of pods analyzed concurrently. Each pod's analysis
            is CPU-bound (no I/O), so the sweet spot is roughly equal to
            the number of CPUs available — 8 is a sensible default that
            works on most laptops and CI runners.
        cfg: CepheusConfig override; defaults to the standard config.
        kubectl_bin: Override kubectl binary path (for testing / unusual installs).
    """
    cfg = cfg or CepheusConfig()
    raw = _kubectl_get_pods(
        namespace=namespace,
        selector=selector,
        context=context,
        kubeconfig=kubeconfig,
        kubectl_bin=kubectl_bin,
    )

    items = raw.get("items") or []
    workers = max(1, min(parallel, max(1, len(items))))

    if workers == 1:
        reports = [_analyze_pod(item, cfg) for item in items]
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cepheus-fleet") as pool:
            reports = list(pool.map(lambda x: _analyze_pod(x, cfg), items))

    error_count = sum(1 for r in reports if r.error)
    return FleetReport(
        cluster_context=context,
        pod_count=len(reports),
        error_count=error_count,
        pods=reports,
    )
