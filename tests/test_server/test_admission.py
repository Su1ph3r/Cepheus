"""Tests for cepheus.server.admission — the AdmissionReview handler.

Focus on the pure ``_handle_admission(body, cfg)`` function rather than
the HTTP/TLS plumbing — no need to spin up a real server (and the TLS
cert handling is too tedious to test cleanly). The HTTP wrapper is
straightforward stdlib code; the handler is where the analyzer decision
lives.
"""

from __future__ import annotations

import json
from http import HTTPStatus

from cepheus.server.admission import (
    AdmissionConfig,
    _handle_admission,
    load_admission_config,
)


# --- helpers --------------------------------------------------------


def _admission_review(uid: str, pod_spec: dict, *, namespace: str = "default", name: str = "test-pod") -> bytes:
    """Build an AdmissionReview v1 request body for a Pod CREATE."""
    return json.dumps(
        {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": uid,
                "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "namespace": namespace,
                "object": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": name, "namespace": namespace},
                    "spec": pod_spec,
                },
                "operation": "CREATE",
            },
        }
    ).encode("utf-8")


def _hardened_spec() -> dict:
    return {
        "containers": [
            {
                "name": "app",
                "securityContext": {
                    "privileged": False,
                    "capabilities": {"drop": ["ALL"]},
                    "readOnlyRootFilesystem": True,
                },
            }
        ],
        "automountServiceAccountToken": False,
    }


def _privileged_hostpath_spec() -> dict:
    return {
        "containers": [
            {
                "name": "app",
                "securityContext": {"privileged": True},
                "volumeMounts": [{"name": "host", "mountPath": "/host"}],
            }
        ],
        "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
        "hostPID": True,
    }


# --- happy paths ----------------------------------------------------


def test_hardened_pod_admitted_under_critical_gate():
    cfg = AdmissionConfig(max_severity="critical")
    body = _admission_review("uid-1", _hardened_spec())
    status, resp = _handle_admission(body, cfg)
    assert status == HTTPStatus.OK
    assert resp["response"]["allowed"], resp["response"].get("status", {}).get("message")
    assert resp["response"]["uid"] == "uid-1"
    assert resp["apiVersion"] == "admission.k8s.io/v1"


def test_privileged_hostpath_pod_denied_under_critical_gate():
    cfg = AdmissionConfig(max_severity="critical")
    body = _admission_review("uid-2", _privileged_hostpath_spec())
    status, resp = _handle_admission(body, cfg)
    assert status == HTTPStatus.OK
    assert not resp["response"]["allowed"]
    msg = resp["response"]["status"]["message"]
    assert "severity=critical" in msg or "severity >= critical" in msg
    assert resp["response"]["status"]["code"] == HTTPStatus.FORBIDDEN


def test_no_gate_configured_admits_everything():
    """With no max_severity and no baseline, the server logs but
    never denies."""
    cfg = AdmissionConfig()  # nothing configured
    body = _admission_review("uid-3", _privileged_hostpath_spec())
    _status, resp = _handle_admission(body, cfg)
    assert resp["response"]["allowed"]


def test_non_pod_kind_admitted_unconditionally():
    """ValidatingWebhookConfiguration should already scope to Pods, but
    if a misconfigured rule routes a Deployment to us we admit it
    silently rather than crashing."""
    body = json.dumps(
        {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "uid-4",
                "kind": {"group": "apps", "version": "v1", "kind": "Deployment"},
                "object": {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "x"},
                    "spec": {"template": {"spec": _privileged_hostpath_spec()}},
                },
            },
        }
    ).encode("utf-8")
    cfg = AdmissionConfig(max_severity="critical")
    _status, resp = _handle_admission(body, cfg)
    assert resp["response"]["allowed"]


# --- error paths ----------------------------------------------------


def test_invalid_json_returns_400():
    cfg = AdmissionConfig()
    status, resp = _handle_admission(b"this is not json", cfg)
    assert status == HTTPStatus.BAD_REQUEST
    assert "error" in resp


def test_missing_uid_returns_400():
    cfg = AdmissionConfig()
    body = json.dumps({"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": {}}).encode("utf-8")
    status, resp = _handle_admission(body, cfg)
    assert status == HTTPStatus.BAD_REQUEST


def test_internal_error_fail_open_admits_with_warning(monkeypatch):
    """If the analyzer crashes for any reason and fail_open_on_error
    is True (default), the pod is admitted with a warning message
    surfaced via the AdmissionResponse `warnings` array (kubectl
    renders these in its output)."""
    cfg = AdmissionConfig(max_severity="critical", fail_open_on_error=True)

    def boom(*_a, **_kw):
        raise RuntimeError("synthetic analyzer failure")

    monkeypatch.setattr("cepheus.server.admission.analyze", boom)

    body = _admission_review("uid-5", _hardened_spec())
    status, resp = _handle_admission(body, cfg)
    assert status == HTTPStatus.OK
    assert resp["response"]["allowed"]
    # Per AdmissionResponse spec: ALLOWED=true uses `warnings` (not `status`)
    # for non-fatal messages.
    assert "warnings" in resp["response"]
    assert any("fail-open" in w for w in resp["response"]["warnings"])


def test_internal_error_fail_closed_denies(monkeypatch):
    cfg = AdmissionConfig(max_severity="critical", fail_open_on_error=False)

    def boom(*_a, **_kw):
        raise RuntimeError("synthetic analyzer failure")

    monkeypatch.setattr("cepheus.server.admission.analyze", boom)

    body = _admission_review("uid-6", _hardened_spec())
    status, resp = _handle_admission(body, cfg)
    assert status == HTTPStatus.OK
    assert not resp["response"]["allowed"]
    assert "fail-closed" in resp["response"]["status"]["message"]


# --- kernel-CVE filter --------------------------------------------


def test_kernel_cve_does_not_trigger_admission_deny_by_default():
    """Kernel CVEs are PodSpec-unevaluable and would false-positive
    on every pod without --include-kernel-cves. The default filter
    must drop them from gate evaluation."""
    # Use a hardened spec — analyzer will still match some kernel CVEs
    # via confidence_if_absent. Gate must NOT deny.
    cfg = AdmissionConfig(max_severity="critical")
    body = _admission_review("uid-7", _hardened_spec())
    _status, resp = _handle_admission(body, cfg)
    assert resp["response"]["allowed"], resp["response"].get("status", {}).get("message")


# --- load_admission_config -----------------------------------------


def test_load_admission_config_rejects_unknown_severity():
    import pytest

    with pytest.raises(ValueError, match="max_severity"):
        load_admission_config(
            max_severity="extreme",
            baseline_path=None,
            fail_on_new=False,
            include_kernel_cves=False,
            fail_open_on_error=True,
        )


def test_load_admission_config_rejects_fail_on_new_without_baseline():
    import pytest

    with pytest.raises(ValueError, match="--fail-on-new requires --baseline"):
        load_admission_config(
            max_severity=None,
            baseline_path=None,
            fail_on_new=True,
            include_kernel_cves=False,
            fail_open_on_error=True,
        )


def test_load_admission_config_with_baseline(tmp_path):
    """A real baseline file should load cleanly at startup."""
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "chains": [
                    {
                        "id": "c1",
                        "steps": [{"technique": {"id": "cap_sys_admin_mount"}}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    cfg = load_admission_config(
        max_severity="critical",
        baseline_path=baseline,
        fail_on_new=True,
        include_kernel_cves=False,
        fail_open_on_error=True,
    )
    assert cfg.baseline_identities is not None
    assert len(cfg.baseline_identities) >= 1
