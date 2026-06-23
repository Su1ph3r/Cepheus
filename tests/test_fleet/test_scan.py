"""Tests for cepheus.fleet.scan — kubectl-driven multi-pod analysis."""

from __future__ import annotations

import json
import subprocess

import pytest

from cepheus.fleet.scan import (
    FleetScanError,
    PodReport,
    _analyze_pod,
    _kubectl_get_pods,
    scan_cluster,
)


def _pod_item(
    *,
    namespace: str,
    name: str,
    privileged: bool = False,
    host_path: bool = False,
    labels: dict | None = None,
) -> dict:
    spec: dict = {
        "containers": [
            {
                "name": "app",
                "image": "busybox",
                "securityContext": {"privileged": privileged},
            }
        ]
    }
    if host_path:
        spec["containers"][0]["volumeMounts"] = [{"name": "host", "mountPath": "/host"}]
        spec["volumes"] = [{"name": "host", "hostPath": {"path": "/"}}]
    return {
        "metadata": {"namespace": namespace, "name": name, "labels": labels or {}},
        "spec": {**spec, "nodeName": "node-1"},
        "status": {"phase": "Running"},
    }


def test_fleet_scan_error_importable_from_package_root():
    """The CLI's `fleet scan` command does
    `from cepheus.fleet import FleetScanError, scan_cluster`. Guard that
    the package root re-exports the exception so the command's error
    handler is reachable rather than crashing with ImportError."""
    from cepheus.fleet import FleetScanError as PackageFleetScanError

    assert PackageFleetScanError is FleetScanError


def test_analyze_pod_runs_and_returns_metadata():
    """Smoke test that the importer + analyzer round-trip works and
    populates the report fields. Exact chain counts depend on the
    technique DB; tested relatively in test_analyze_pod_privileged_pod_yields_critical_chain."""
    from cepheus.config import CepheusConfig

    item = _pod_item(namespace="prod", name="api-1")
    item["spec"]["containers"][0]["securityContext"] = {
        "privileged": False,
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "runAsNonRoot": True,
        "runAsUser": 1000,
        "capabilities": {"drop": ["ALL"]},
    }
    item["spec"]["automountServiceAccountToken"] = False

    report = _analyze_pod(item, CepheusConfig())
    assert isinstance(report, PodReport)
    assert report.namespace == "prod"
    assert report.name == "api-1"
    assert report.node == "node-1"
    assert report.error is None
    assert report.total_techniques_checked == 72


def test_analyze_pod_privileged_pod_yields_critical_chain():
    from cepheus.config import CepheusConfig

    item = _pod_item(namespace="dev", name="bad-pod", privileged=True, host_path=True)
    report = _analyze_pod(item, CepheusConfig())
    assert report.error is None
    assert report.critical_chain_count >= 1
    assert report.top_chain_score > 0


def test_analyze_pod_captures_per_pod_errors_without_raising():
    from cepheus.config import CepheusConfig

    # Force the importer to choke by giving it a non-dict spec.
    bad = {"metadata": {"namespace": "x", "name": "y", "labels": {}}, "spec": "not-a-dict"}
    report = _analyze_pod(bad, CepheusConfig())
    assert report.error is not None
    assert report.namespace == "x"
    assert report.name == "y"


def test_kubectl_missing_raises_fleet_scan_error(monkeypatch):
    monkeypatch.setattr("cepheus.fleet.scan.shutil.which", lambda _: None)
    with pytest.raises(FleetScanError, match="not found in PATH"):
        _kubectl_get_pods(namespace=None, selector=None, context=None, kubeconfig=None, kubectl_bin="kubectl")


def test_kubectl_nonzero_exit_raises(monkeypatch):
    monkeypatch.setattr("cepheus.fleet.scan.shutil.which", lambda _: "/usr/bin/kubectl")

    def _fake_run(*a, **kw):
        return subprocess.CompletedProcess(args=a[0], returncode=1, stdout="", stderr="forbidden")

    monkeypatch.setattr("cepheus.fleet.scan.subprocess.run", _fake_run)
    with pytest.raises(FleetScanError, match="forbidden"):
        _kubectl_get_pods(namespace=None, selector=None, context=None, kubeconfig=None, kubectl_bin="kubectl")


def test_kubectl_non_json_raises(monkeypatch):
    monkeypatch.setattr("cepheus.fleet.scan.shutil.which", lambda _: "/usr/bin/kubectl")

    def _fake_run(*a, **kw):
        return subprocess.CompletedProcess(args=a[0], returncode=0, stdout="not-json", stderr="")

    monkeypatch.setattr("cepheus.fleet.scan.subprocess.run", _fake_run)
    with pytest.raises(FleetScanError, match="non-JSON"):
        _kubectl_get_pods(namespace=None, selector=None, context=None, kubeconfig=None, kubectl_bin="kubectl")


def test_scan_cluster_end_to_end(monkeypatch):
    """Drive scan_cluster end-to-end with a faked kubectl response."""
    items = [
        _pod_item(namespace="default", name="hardened"),
        _pod_item(namespace="default", name="risky", privileged=True, host_path=True),
    ]
    items[0]["spec"]["containers"][0]["securityContext"] = {
        "privileged": False,
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "runAsNonRoot": True,
        "runAsUser": 1000,
        "capabilities": {"drop": ["ALL"]},
    }
    items[0]["spec"]["automountServiceAccountToken"] = False

    fake_response = {"items": items}

    monkeypatch.setattr("cepheus.fleet.scan.shutil.which", lambda _: "/usr/bin/kubectl")

    def _fake_run(*a, **kw):
        return subprocess.CompletedProcess(args=a[0], returncode=0, stdout=json.dumps(fake_response), stderr="")

    monkeypatch.setattr("cepheus.fleet.scan.subprocess.run", _fake_run)

    report = scan_cluster(parallel=2)
    assert report.pod_count == 2
    assert report.error_count == 0
    by_name = {p.name: p for p in report.pods}
    # The hardened pod still produces some chains (anything with a SA
    # token mount + reachable apiserver fires k8s_service_account, etc.),
    # but it must have strictly fewer critical chains and a strictly
    # lower top score than the privileged/host-path pod. Relative
    # comparison is robust against future technique-DB additions.
    assert by_name["hardened"].critical_chain_count < by_name["risky"].critical_chain_count
    assert by_name["hardened"].top_chain_score < by_name["risky"].top_chain_score
    assert by_name["risky"].critical_chain_count >= 1


def test_scan_cluster_serializable(monkeypatch):
    """The to_dict() output must be JSON-serializable so it can be written
    to disk and later re-read by `cepheus fleet diff`."""
    fake_response = {"items": [_pod_item(namespace="ns", name="p1")]}
    monkeypatch.setattr("cepheus.fleet.scan.shutil.which", lambda _: "/usr/bin/kubectl")
    monkeypatch.setattr(
        "cepheus.fleet.scan.subprocess.run",
        lambda *a, **kw: subprocess.CompletedProcess(
            args=a[0], returncode=0, stdout=json.dumps(fake_response), stderr=""
        ),
    )
    report = scan_cluster(parallel=1)
    blob = json.dumps(report.to_dict())
    parsed = json.loads(blob)
    assert parsed["pod_count"] == 1
    assert parsed["pods"][0]["namespace"] == "ns"
