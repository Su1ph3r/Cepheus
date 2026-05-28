"""Kubernetes ValidatingAdmissionWebhook server.

Runs an HTTPS server (stdlib ``ThreadingHTTPServer`` + ``ssl``) that
accepts ``AdmissionReview`` v1 requests for Pod resources, builds a
synthetic ``ContainerPosture`` via ``cepheus.importers.podspec``, runs
the analyzer + chain construction, evaluates configured gates, and
returns an allow/deny verdict in an AdmissionReview response.

Why stdlib not a framework: an admission webhook is a low-volume,
single-endpoint service. ThreadingHTTPServer handles a few hundred
QPS easily — well above what kube-apiserver throws at a single
webhook — and we keep cepheus install-size at zero new runtime deps.

Threat model + hardening:
  * TLS required (kube-apiserver refuses cleartext webhooks).
  * Request body capped to 1 MB — typical Pod specs are <50 KB; a
    larger body is almost certainly an attack or misconfiguration.
  * AdmissionReview parsing strictly typed: bad shape → 400, not a
    500 traceback that leaks internals to the caller.
  * Fail-open behaviour is configurable. Default is FAIL-OPEN (allow
    on internal error) — matching ValidatingWebhookConfiguration's
    ``failurePolicy: Ignore`` semantics. Operators who want fail-closed
    set ``--fail-policy fail`` and configure the webhook config
    accordingly.
  * Health probes (``/healthz``, ``/readyz``) plain-HTTP on a separate
    port so kubelet doesn't need the webhook's TLS cert.
"""

from __future__ import annotations

import json
import logging
import ssl
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from cepheus.config import CepheusConfig
from cepheus.engine.analyzer import analyze
from cepheus.engine.baseline import diff as baseline_diff
from cepheus.engine.baseline import load_baseline
from cepheus.importers.podspec import _parse_kernel_version, posture_from_podspec
from cepheus.models.posture import KernelInfo
from cepheus.models.technique import TechniqueCategory
from cepheus.server.k8s_client import NodeKernelCache
from cepheus.server.notifiers import AdmissionEvent, NotifierConfig, notify

logger = logging.getLogger("cepheus.admission")

# 1 MB cap on the request body. Real Pod specs are <50 KB; this is a
# DoS shield, not a feature constraint.
_MAX_BODY_BYTES = 1 * 1024 * 1024

# Categories the admission webhook gates on. Kernel CVEs and verifier
# outcomes are runtime-only — a PodSpec has no kernel version, no
# /proc reachability, no live container to probe — so including them
# in admission decisions produces false positives that block legitimate
# pods. Operators can run `cepheus verify` against the running pod
# AFTER admission for the runtime-side check.
_PODSPEC_EVALUABLE_CATEGORIES = frozenset(
    {
        TechniqueCategory.CAPABILITY,
        TechniqueCategory.MOUNT,
        TechniqueCategory.RUNTIME,
        TechniqueCategory.COMBINATORIAL,
        TechniqueCategory.INFO_DISCLOSURE,
    }
)

# Severity ordering identical to cli.py — keep in sync.
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Per-pod policy label. Lets workload owners opt INTO weaker enforcement
# without operators having to rewrite the ValidatingWebhookConfiguration's
# NamespaceSelector for every exception. The cluster admin can still
# require the absence of this label via OPA / Kyverno; the webhook
# itself trusts whoever can `kubectl apply` a pod to also set this
# label honestly (which they can already do for other Pod fields like
# securityContext).
_POLICY_LABEL = "cepheus.io/policy"
_POLICY_SKIP = "skip"
_POLICY_WARN = "warn"
_POLICY_ENFORCE = "enforce"
_VALID_POLICIES = frozenset({_POLICY_SKIP, _POLICY_WARN, _POLICY_ENFORCE})


def _pod_policy(metadata: dict) -> str:
    """Resolve the per-pod policy from labels. Default ``enforce`` —
    absent label means the existing gate behaviour. Unknown values fall
    back to ``enforce`` rather than silently weakening the gate; logged
    by the caller."""
    labels = metadata.get("labels") or {}
    raw = labels.get(_POLICY_LABEL)
    if raw is None:
        return _POLICY_ENFORCE
    raw = str(raw).strip().lower()
    if raw not in _VALID_POLICIES:
        return _POLICY_ENFORCE
    return raw


@dataclass
class AdmissionConfig:
    """Runtime configuration for the admission server. Built from CLI
    flags at startup; passed unchanged to each request handler."""

    # Gate config — at least one must be active, else the server only logs.
    max_severity: str | None = None  # one of low/medium/high/critical
    baseline_path: Path | None = None
    fail_on_new: bool = False

    # Operational config.
    include_kernel_cves: bool = False  # kernel CVEs are PodSpec-unevaluable; opt-in
    fail_open_on_error: bool = True  # internal errors → allow (Kubernetes default)
    config: CepheusConfig | None = None  # analyzer config

    # Loaded once at startup so per-request work doesn't re-read disk.
    baseline_identities: Any = None

    # Background cache of cluster kernel versions sourced from the K8s
    # apiserver. When present AND include_kernel_cves is True, each
    # admission is evaluated against EVERY distinct kernel currently
    # in the cluster — a pod is denied if it produces a critical chain
    # under any kernel it could plausibly land on. When None (the
    # default), kernel CVE chains are dropped from the gate decision
    # because the PodSpec carries no kernel info.
    node_kernel_cache: NodeKernelCache | None = None

    # Outbound notification config. When the webhook denies a pod (or
    # admits one in warn mode), an event is dispatched to each enabled
    # channel. POSTs happen on daemon threads so the admission
    # decision is never blocked on the notifier.
    notifier_config: NotifierConfig | None = None


def _evaluable_chains(chains: list, include_kernel_cves: bool) -> list:
    """Filter chains down to those whose every step is in a category
    the admission webhook can evaluate from a PodSpec alone."""
    if include_kernel_cves:
        return chains
    return [
        c
        for c in chains
        if all(s.technique is not None and s.technique.category in _PODSPEC_EVALUABLE_CATEGORIES for s in c.steps)
    ]


def _gate_decision(
    chains: list,
    cfg: AdmissionConfig,
) -> tuple[bool, str]:
    """Apply the configured gates to a chain list. Returns
    (allowed, reason). ``reason`` is the operator-facing message that
    accompanies a deny verdict — kubectl shows this verbatim to the
    user attempting `kubectl apply`."""
    evaluable = _evaluable_chains(chains, cfg.include_kernel_cves)

    # Severity gate
    if cfg.max_severity is not None:
        gate_rank = _SEVERITY_RANK[cfg.max_severity]
        offenders = [c for c in evaluable if _SEVERITY_RANK[c.severity.value] >= gate_rank]
        if offenders:
            top = offenders[0]
            top_tech = top.steps[0].technique.id if top.steps else "?"
            return False, (
                f"Cepheus admission gate (severity={cfg.max_severity}) blocked: "
                f"{len(offenders)} chain(s) at severity >= {cfg.max_severity} "
                f"(top: {top_tech}, score={top.composite_score:.2f}). "
                f"Run `cepheus analyze` against this PodSpec for full details."
            )

    # Baseline regression gate
    if cfg.fail_on_new and cfg.baseline_identities is not None:
        diff = baseline_diff(evaluable, cfg.baseline_identities)
        if diff.has_regressions:
            new_ids = [c.steps[0].technique.id for c in diff.new[:3] if c.steps]
            return False, (
                f"Cepheus admission gate (--fail-on-new) blocked: "
                f"{len(diff.new)} chain(s) introduced vs. baseline "
                f"(first 3: {', '.join(new_ids)})."
            )

    return True, ""


def _build_response(
    uid: str,
    *,
    allowed: bool,
    message: str = "",
) -> dict:
    """Construct the AdmissionReview response payload Kubernetes expects.

    Per the AdmissionResponse spec:
      * ``status`` carries the denial reason on ALLOWED=false — surfaced
        to the user via ``kubectl apply`` error output.
      * ``warnings: []string`` carries non-fatal warnings on
        ALLOWED=true — surfaced to the user via ``kubectl`` warnings
        header. We use this for fail-open admit-with-warning so the
        user sees that Cepheus admitted the pod despite hitting an
        internal error.
    """
    response: dict[str, Any] = {
        "uid": uid,
        "allowed": allowed,
    }
    if message:
        if allowed:
            response["warnings"] = [message]
        else:
            response["status"] = {
                "code": HTTPStatus.FORBIDDEN,
                "message": message,
            }
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": response,
    }


def _handle_admission(body: bytes, cfg: AdmissionConfig) -> tuple[int, dict]:
    """Pure function for the admission decision — separated from HTTP
    plumbing so unit tests don't need to spin up a real server."""
    try:
        review = json.loads(body)
    except json.JSONDecodeError as exc:
        return HTTPStatus.BAD_REQUEST, {
            "error": f"Invalid JSON: {exc}",
        }

    request = review.get("request") or {}
    uid = request.get("uid", "")
    if not uid:
        return HTTPStatus.BAD_REQUEST, {"error": "AdmissionReview.request.uid is required"}

    obj = request.get("object") or {}
    kind = obj.get("kind") or request.get("kind", {}).get("kind", "")
    if kind != "Pod":
        # Defensive: the ValidatingWebhookConfiguration should already
        # scope to Pods only, but if a misconfigured rule hits us with
        # a Deployment / etc., admit it (we have nothing useful to say).
        logger.debug("Ignoring non-Pod admission (kind=%s, uid=%s)", kind, uid)
        return HTTPStatus.OK, _build_response(uid, allowed=True)

    metadata = obj.get("metadata") or {}
    spec = obj.get("spec") or {}
    if not spec:
        return HTTPStatus.OK, _build_response(uid, allowed=True)

    policy = _pod_policy(metadata)
    if policy == _POLICY_SKIP:
        # Operator-sanctioned bypass — skip analysis entirely. Logged so
        # an auditor can still see WHICH pods opted out.
        logger.info(
            "admission SKIP uid=%s ns=%s name=%s (label %s=skip)",
            uid,
            metadata.get("namespace", ""),
            metadata.get("name") or metadata.get("generateName", ""),
            _POLICY_LABEL,
        )
        return HTTPStatus.OK, _build_response(uid, allowed=True)

    try:
        # When node-kernel lookup is configured AND the operator has
        # opted into kernel-CVE gating, evaluate the pod against every
        # distinct kernel currently in the cluster and union the chain
        # set. Without a cache (default), or with kernel CVEs disabled,
        # we run the analyzer once with empty kernel info — the existing
        # PodSpec-evaluable categories still match correctly.
        kernels: list[str | None] = [None]
        if cfg.node_kernel_cache is not None and cfg.include_kernel_cves:
            snapshot = cfg.node_kernel_cache.snapshot()
            if snapshot.kernel_versions:
                kernels = sorted(snapshot.kernel_versions)

        # Parse the PodSpec ONCE. Per-kernel work then is only the
        # KernelInfo swap + analyzer call — capability/mount/namespace
        # extraction is identical across kernels and re-running it N
        # times during a rolling kernel upgrade pegs admission latency
        # under tight webhook timeoutSeconds.
        base_posture = posture_from_podspec(
            spec,
            namespace=metadata.get("namespace") or request.get("namespace"),
            pod_name=metadata.get("name") or metadata.get("generateName"),
            kernel_version=None,
        )

        chain_buckets: list = []
        for kernel_version in kernels:
            if kernel_version:
                major, minor, patch = _parse_kernel_version(kernel_version)
                posture = base_posture.model_copy(
                    update={
                        "kernel": KernelInfo(
                            version=kernel_version,
                            major=major,
                            minor=minor,
                            patch=patch,
                        )
                    }
                )
            else:
                posture = base_posture
            result = analyze(posture, cfg.config or CepheusConfig())
            chain_buckets.append(result.chains)
        all_chains = _union_chains(chain_buckets)
        allowed, reason = _gate_decision(all_chains, cfg)
    except (ValueError, KeyError, json.JSONDecodeError, ValidationError) as exc:
        # Data-shape errors from the PodSpec or analyzer input. These
        # are KNOWN failure modes (a malformed admission body, a
        # PodSpec field with the wrong type, a baseline that diverged
        # from the technique DB). Apply the configured fail-open /
        # fail-closed policy — that's exactly what the policy exists
        # to handle.
        logger.warning(
            "Admission analysis: bad input for uid=%s: %s: %s",
            uid,
            type(exc).__name__,
            exc,
        )
        if cfg.fail_open_on_error:
            return HTTPStatus.OK, _build_response(
                uid,
                allowed=True,
                message=f"Cepheus internal error (fail-open): {type(exc).__name__}",
            )
        return HTTPStatus.OK, _build_response(
            uid,
            allowed=False,
            message=f"Cepheus internal error (fail-closed): {type(exc).__name__}: {exc}",
        )
    except (AttributeError, TypeError):
        # Programming bug — analyzer contract violated or attribute
        # access on a None / wrong type. Do NOT silently fail-open;
        # this is the failure mode the fail-open policy is most
        # likely to mask in production. Re-raise so the HTTP handler
        # returns 500 and the kube-apiserver applies its OWN
        # failurePolicy (which the operator chose deliberately).
        logger.exception(
            "Admission analyzer programming error for uid=%s — this is a bug",
            uid,
        )
        raise

    if allowed:
        logger.info(
            "admission ALLOW uid=%s ns=%s name=%s chains=%d policy=%s",
            uid,
            metadata.get("namespace", ""),
            metadata.get("name") or metadata.get("generateName", ""),
            len(all_chains),
            policy,
        )
        return HTTPStatus.OK, _build_response(uid, allowed=True)

    # Disallowed under current gate config — but warn-mode downgrades
    # the deny to an admit-with-warning. The reason text still goes
    # through as a kubectl warning header, so the user sees the would-be
    # violation immediately but the pod is admitted.
    ns = metadata.get("namespace", "")
    pod_name = metadata.get("name") or metadata.get("generateName", "")
    if policy == _POLICY_WARN:
        logger.warning(
            "admission WARN uid=%s ns=%s name=%s reason=%s (label %s=warn)",
            uid,
            ns,
            pod_name,
            reason,
            _POLICY_LABEL,
        )
        _dispatch_notification(cfg, "WARN", ns, pod_name, reason, uid, len(all_chains))
        return HTTPStatus.OK, _build_response(
            uid,
            allowed=True,
            message=f"Cepheus (warn mode): {reason}",
        )

    logger.warning(
        "admission DENY uid=%s ns=%s name=%s reason=%s",
        uid,
        ns,
        pod_name,
        reason,
    )
    _dispatch_notification(cfg, "DENY", ns, pod_name, reason, uid, len(all_chains))
    return HTTPStatus.OK, _build_response(uid, allowed=False, message=reason)


def _dispatch_notification(
    cfg: AdmissionConfig,
    decision: str,
    namespace: str,
    pod_name: str,
    reason: str,
    uid: str,
    chain_count: int,
) -> None:
    """Send a denial / warning event to configured outbound channels.

    Wrapped in a broad try/except so a notifier bug — bad credentials,
    DNS failure, malformed URL — never blocks an admission decision.
    A failed notification is logged at WARNING and dropped; the
    pod's allow/deny status is unaffected.
    """
    if cfg.notifier_config is None or not cfg.notifier_config.any_enabled:
        return
    try:
        notify(
            AdmissionEvent(
                decision=decision,
                namespace=namespace,
                pod_name=pod_name,
                reason=reason,
                uid=uid,
                chain_count=chain_count,
            ),
            cfg.notifier_config,
        )
    except Exception as exc:  # noqa: BLE001
        # Notifier dispatch must never propagate — logged and swallowed.
        logger.warning("notifier dispatch failed: %s: %s", type(exc).__name__, exc)


def _cache_unhealthy_reason(cfg: AdmissionConfig) -> str | None:
    """Return a non-empty reason string when the node-kernel cache is
    in a state that should make ``/readyz`` fail, else None.

    Only flagged when the operator explicitly opted into kernel-CVE
    gating (``include_kernel_cves`` AND a configured cache): in any
    other config, kernel CVEs are deliberately not gated and a stale
    cache is irrelevant.

    Two unhealthy conditions:
      * Initial fetch never succeeded (``last_refresh_at == 0``) AND
        we have no kernel data — the webhook would silently admit
        without gating kernel CVEs.
      * Last refresh failed AND the snapshot age exceeds three
        refresh intervals — long enough to be confident the failure
        is sustained, short enough to surface before a kernel CVE
        is bypassed via a stale-allow list.
    """
    cache = cfg.node_kernel_cache
    if cache is None or not cfg.include_kernel_cves:
        return None
    snap = cache.snapshot()
    if snap.last_refresh_at == 0 and not snap.kernel_versions:
        return f"node-kernel cache has no usable snapshot (last_error={snap.last_error!r})"
    if snap.last_error and (time.time() - snap.last_refresh_at) > 3 * cache.refresh_interval_sec:
        return f"node-kernel cache refresh failing for >3 intervals (last_error={snap.last_error!r})"
    return None


def _union_chains(buckets: list) -> list:
    """De-duplicate chains across multiple analyzer runs (one per
    cluster kernel version), keyed on ``chain.id`` — the canonical
    chain identity already used by the analyzer's own per-run dedup
    (see ``engine.analyzer:138``).

    Kernel-specific techniques produce different chain ids per
    kernel (their id includes the kernel-CVE technique id, which
    differs by kernel version), so they survive dedup naturally.
    Non-kernel chains produce identical ids across kernels and
    collapse to one entry — which is correct: the same
    capability/mount finding shouldn't be reported N times just
    because the cluster has N distinct kernels.

    Using ``chain.id`` rather than a (top_id, rounded_score,
    severity) tuple is structurally safer: chain.id encodes the
    full ordered technique-id set, so chains that differ in any
    step survive dedup, and float-rounding collisions are
    impossible.
    """
    if not buckets:
        return []
    if len(buckets) == 1:
        return list(buckets[0])
    seen: set[str] = set()
    out = []
    for bucket in buckets:
        for chain in bucket:
            if chain.id in seen:
                continue
            seen.add(chain.id)
            out.append(chain)
    return out


class AdmissionHandler(BaseHTTPRequestHandler):
    """HTTPS handler for /validate (admission) and /healthz, /readyz
    (kubelet probes)."""

    # Reduce default access-log noise — we log admission decisions
    # explicitly via the module logger.
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        logger.debug("%s - - [%s] %s", self.address_string(), self.log_date_time_string(), format % args)

    def _reply(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            # Liveness: is the process responsive? Cache state is not
            # a liveness concern — a broken cache doesn't justify
            # killing the pod (which would lose the last-known kernel
            # snapshot the cache is still serving).
            self._reply(HTTPStatus.OK, b"ok\n", content_type="text/plain")
            return
        if self.path == "/readyz":
            cfg: AdmissionConfig = self.server.cepheus_config  # type: ignore[attr-defined]
            unhealthy_reason = _cache_unhealthy_reason(cfg)
            if unhealthy_reason is not None:
                body = json.dumps({"ready": False, "reason": unhealthy_reason}).encode("utf-8") + b"\n"
                # 503 propagates to the ValidatingWebhookConfiguration's
                # ``failurePolicy``; operators with ``failurePolicy: Fail``
                # will see admissions blocked while the cache is
                # unhealthy — which matches the security intent of
                # opting into kernel-CVE gating in the first place.
                self._reply(HTTPStatus.SERVICE_UNAVAILABLE, body)
                return
            self._reply(HTTPStatus.OK, b"ok\n", content_type="text/plain")
            return
        self._reply(HTTPStatus.NOT_FOUND, b'{"error":"not found"}\n')

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/validate":
            self._reply(HTTPStatus.NOT_FOUND, b'{"error":"not found"}\n')
            return

        # Reject obviously-too-large bodies before reading them into memory.
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._reply(HTTPStatus.BAD_REQUEST, b'{"error":"invalid Content-Length"}\n')
            return
        if content_length <= 0:
            self._reply(HTTPStatus.BAD_REQUEST, b'{"error":"empty body"}\n')
            return
        if content_length > _MAX_BODY_BYTES:
            self._reply(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, b'{"error":"body too large"}\n')
            return

        body = self.rfile.read(content_length)

        cfg: AdmissionConfig = self.server.cepheus_config  # type: ignore[attr-defined]
        status, payload = _handle_admission(body, cfg)
        self._reply(status, json.dumps(payload).encode("utf-8") + b"\n")


def serve(
    cfg: AdmissionConfig,
    *,
    bind_addr: str = "0.0.0.0",  # noqa: S104 — webhooks must accept from kube-apiserver
    port: int = 8443,
    cert_file: str | Path,
    key_file: str | Path,
    health_port: int | None = 8080,
) -> None:
    """Start the admission server. Blocks the calling thread.

    The webhook listens on TLS at ``port``; an optional plaintext-HTTP
    health server runs on ``health_port`` so kubelet probes don't need
    the webhook's TLS cert. Set ``health_port=None`` to disable the
    plaintext probes (and have kubelet hit ``/healthz`` over TLS — works
    fine if kubelet trusts the webhook's CA).

    Args:
        cfg: Validated AdmissionConfig — gate settings, optional
            preloaded baseline, fail-open vs fail-closed.
        bind_addr: Bind address (default 0.0.0.0). Override to bind
            to a single interface for tighter network isolation.
        port: TLS port. Webhook configurations must reference this
            port via the Service / clientConfig.
        cert_file: Path to PEM-encoded TLS certificate. Must include
            the full chain if applicable.
        key_file: Path to PEM-encoded private key.
        health_port: Optional plaintext HTTP port for ``/healthz`` and
            ``/readyz``. Pass ``None`` to disable.
    """
    server = ThreadingHTTPServer((bind_addr, port), AdmissionHandler)
    server.cepheus_config = cfg  # type: ignore[attr-defined]

    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    # TLS 1.2 minimum — kube-apiserver supports 1.2+ since k8s 1.10.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    health_thread: threading.Thread | None = None
    health_server: ThreadingHTTPServer | None = None
    if health_port is not None:
        health_server = ThreadingHTTPServer((bind_addr, health_port), AdmissionHandler)
        health_server.cepheus_config = cfg  # type: ignore[attr-defined]
        # Health server intentionally NOT TLS — kubelet probes default to plain HTTP.

        def _serve_health() -> None:
            logger.info("admission health server listening on %s:%d", bind_addr, health_port)
            health_server.serve_forever()

        health_thread = threading.Thread(target=_serve_health, daemon=True, name="cepheus-health")
        health_thread.start()

    node_cache_state = "off"
    if cfg.node_kernel_cache is not None:
        snap = cfg.node_kernel_cache.snapshot()
        node_cache_state = f"on (kernels={sorted(snap.kernel_versions)})"
    logger.info(
        "admission webhook listening on https://%s:%d "
        "(max_severity=%s baseline=%s fail_on_new=%s node_kernel_cache=%s)",
        bind_addr,
        port,
        cfg.max_severity,
        cfg.baseline_path,
        cfg.fail_on_new,
        node_cache_state,
    )
    try:
        server.serve_forever()
    finally:
        server.shutdown()
        server.server_close()
        if health_server is not None:
            # shutdown() unblocks the daemon thread's serve_forever loop;
            # server_close() releases the listening socket so the health
            # port is freed on graceful shutdown rather than lingering
            # bound until the process actually exits.
            health_server.shutdown()
            health_server.server_close()
            if health_thread is not None:
                health_thread.join(timeout=5.0)
        if cfg.node_kernel_cache is not None:
            cfg.node_kernel_cache.stop()


def load_admission_config(
    *,
    max_severity: str | None,
    baseline_path: Path | None,
    fail_on_new: bool,
    include_kernel_cves: bool,
    fail_open_on_error: bool,
    node_kernel_cache: NodeKernelCache | None = None,
    notifier_config: NotifierConfig | None = None,
) -> AdmissionConfig:
    """Build + validate an AdmissionConfig at startup.

    Loads the baseline once if provided so per-request work doesn't hit
    the filesystem; raises ValueError on a malformed baseline so the
    process exits at startup rather than failing every admission
    request silently.
    """
    cfg = AdmissionConfig(
        max_severity=max_severity,
        baseline_path=baseline_path,
        fail_on_new=fail_on_new,
        include_kernel_cves=include_kernel_cves,
        fail_open_on_error=fail_open_on_error,
        config=CepheusConfig(),
        node_kernel_cache=node_kernel_cache,
        notifier_config=notifier_config,
    )

    if max_severity is not None and max_severity not in _SEVERITY_RANK:
        raise ValueError(f"max_severity must be one of {sorted(_SEVERITY_RANK)}; got {max_severity!r}")

    if fail_on_new and baseline_path is None:
        raise ValueError("--fail-on-new requires --baseline")

    if node_kernel_cache is not None and not include_kernel_cves:
        # Configuring the cache without enabling kernel-CVE gating is
        # almost certainly a mistake — the cache wastes apiserver
        # round-trips with no effect on admission decisions. Log loud
        # so the operator notices, but don't fail startup (the
        # combination is still well-defined, just useless).
        logger.warning(
            "node_kernel_cache configured but --include-kernel-cves is OFF — "
            "the cache will refresh in the background but kernel CVE chains "
            "will still be dropped from gate decisions"
        )

    if baseline_path is not None:
        cfg.baseline_identities = load_baseline(baseline_path)
        logger.info("loaded baseline from %s: %d identities", baseline_path, len(cfg.baseline_identities))

    return cfg
