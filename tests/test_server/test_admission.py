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
    """A data-shape error (ValueError — malformed PodSpec, bad
    technique DB entry, etc.) with fail_open_on_error=True (default)
    admits the pod with a warning surfaced via the AdmissionResponse
    `warnings` array. Programming-bug exception types (AttributeError,
    TypeError) deliberately do NOT take this path — they re-raise
    so the apiserver applies its own failurePolicy."""
    cfg = AdmissionConfig(max_severity="critical", fail_open_on_error=True)

    def boom(*_a, **_kw):
        raise ValueError("malformed analyzer input")

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
        raise ValueError("malformed analyzer input")

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


def test_load_admission_config_warns_when_cache_set_without_kernel_cves(caplog):
    """If the operator wires up a node-kernel cache but leaves
    --include-kernel-cves off, the cache is dead weight. Startup must
    warn loudly so the operator notices the misconfiguration without
    having to read source code."""
    from cepheus.server.k8s_client import NodeKernelCache

    class _NoopClient:
        def list_nodes(self):
            return []

    cache = NodeKernelCache(_NoopClient(), refresh_interval_sec=3600.0)
    try:
        with caplog.at_level("WARNING", logger="cepheus.admission"):
            load_admission_config(
                max_severity="critical",
                baseline_path=None,
                fail_on_new=False,
                include_kernel_cves=False,
                fail_open_on_error=True,
                node_kernel_cache=cache,
            )
        assert any("node_kernel_cache configured" in r.message for r in caplog.records)
    finally:
        cache.stop()


def test_handle_admission_runs_analyzer_per_kernel_when_cache_populated(monkeypatch):
    """With a populated kernel cache + --include-kernel-cves, the
    handler must invoke the analyzer once per distinct kernel and
    union the chain set. Verifies the kernel_version kwarg propagates
    through posture_from_podspec."""
    from cepheus.engine.analyzer import AnalysisResult
    from cepheus.server.k8s_client import CacheSnapshot, NodeKernelCache

    captured_kernels: list = []

    def fake_analyze(posture, _config):
        captured_kernels.append(posture.kernel.version)
        # Return an empty AnalysisResult so the gate decision is a clean
        # ALLOW — we're verifying the call shape, not gate semantics.
        return AnalysisResult(posture=posture, chains=[])

    monkeypatch.setattr("cepheus.server.admission.analyze", fake_analyze)

    class _FakeCache:
        def __init__(self, kernels):
            self._snap = CacheSnapshot(
                kernel_versions=frozenset(kernels),
                last_refresh_at=1.0,
            )

        def snapshot(self):
            return self._snap

        def stop(self):
            pass

    # Use the real NodeKernelCache class as the type for the config
    # field — _FakeCache duck-types its snapshot() method.
    cfg = AdmissionConfig(
        max_severity="critical",
        include_kernel_cves=True,
        node_kernel_cache=_FakeCache({"5.15.0-76-generic", "6.1.0-13-amd64"}),  # type: ignore[arg-type]
    )
    body = _admission_review("uid-8", _hardened_spec())
    status, resp = _handle_admission(body, cfg)
    assert status == HTTPStatus.OK
    assert resp["response"]["allowed"]
    # One analyzer call per distinct kernel, in sorted order.
    assert captured_kernels == ["5.15.0-76-generic", "6.1.0-13-amd64"]

    # Sanity: NodeKernelCache import is the public surface even though
    # the test uses a duck-type substitute.
    assert NodeKernelCache is not None


def test_handle_admission_falls_back_to_no_kernel_when_cache_empty(monkeypatch):
    """If the cache exists but the snapshot has zero kernels (initial
    fetch failed, or all nodes still bootstrapping), the handler must
    NOT iterate an empty list — it must run the analyzer once with
    no kernel info, same as if no cache were configured."""
    from cepheus.engine.analyzer import AnalysisResult
    from cepheus.server.k8s_client import CacheSnapshot

    captured_kernels: list = []

    def fake_analyze(posture, _config):
        captured_kernels.append(posture.kernel.version)
        return AnalysisResult(posture=posture, chains=[])

    monkeypatch.setattr("cepheus.server.admission.analyze", fake_analyze)

    class _EmptyCache:
        def snapshot(self):
            return CacheSnapshot(kernel_versions=frozenset(), last_error="initial fetch pending")

        def stop(self):
            pass

    cfg = AdmissionConfig(
        max_severity="critical",
        include_kernel_cves=True,
        node_kernel_cache=_EmptyCache(),  # type: ignore[arg-type]
    )
    body = _admission_review("uid-9", _hardened_spec())
    _status, resp = _handle_admission(body, cfg)
    assert resp["response"]["allowed"]
    # Single call, kernel.version is the empty string default.
    assert captured_kernels == [""]


def test_handle_admission_reraises_attributeerror_not_fail_open(monkeypatch):
    """Programming bugs (AttributeError/TypeError from a refactor) MUST
    NOT be silently fail-opened with only a warning header — that
    failure mode is exactly what the broad-except previously hid. By
    re-raising, the HTTP handler returns 500, and the kube-apiserver
    applies its own failurePolicy (which the operator chose
    deliberately for that scenario)."""
    cfg = AdmissionConfig(max_severity="critical", fail_open_on_error=True)

    def boom(*_a, **_kw):
        raise AttributeError("synthetic refactor bug")

    monkeypatch.setattr("cepheus.server.admission.analyze", boom)

    import pytest

    body = _admission_review("uid-bug", _hardened_spec())
    with pytest.raises(AttributeError, match="synthetic refactor bug"):
        _handle_admission(body, cfg)


def test_handle_admission_value_error_falls_open(monkeypatch):
    """Data-shape errors (ValueError from a malformed PodSpec field)
    are a KNOWN failure mode the fail-open policy is designed to
    handle. Operator's policy choice applies."""
    cfg = AdmissionConfig(max_severity="critical", fail_open_on_error=True)

    def boom(*_a, **_kw):
        raise ValueError("malformed input")

    monkeypatch.setattr("cepheus.server.admission.analyze", boom)

    body = _admission_review("uid-data", _hardened_spec())
    status, resp = _handle_admission(body, cfg)
    assert status == HTTPStatus.OK
    assert resp["response"]["allowed"]
    assert any("fail-open" in w for w in resp["response"]["warnings"])


def test_union_chains_dedups_by_chain_id():
    """Distinct chains with the same top technique id but different
    step sequences MUST both survive dedup. The previous (top_id,
    rounded_score, severity) key would have silently merged them."""
    from cepheus.models.chain import ChainStep, EscapeChain
    from cepheus.models.technique import (
        EscapeTechnique,
        Severity,
        TechniqueCategory,
    )
    from cepheus.server.admission import _union_chains

    # Two chains start with the same top technique but diverge afterwards.
    top = EscapeTechnique(
        id="cap_sys_admin",
        name="CAP_SYS_ADMIN",
        category=TechniqueCategory.CAPABILITY,
        severity=Severity.CRITICAL,
        description="x",
    )
    second_a = EscapeTechnique(
        id="mount_proc",
        name="proc",
        category=TechniqueCategory.MOUNT,
        severity=Severity.HIGH,
        description="x",
    )
    second_b = EscapeTechnique(
        id="mount_sys",
        name="sys",
        category=TechniqueCategory.MOUNT,
        severity=Severity.HIGH,
        description="x",
    )
    chain_a = EscapeChain(
        id="chain-a",
        steps=[ChainStep(technique=top), ChainStep(technique=second_a)],
        composite_score=0.75,
        severity=Severity.CRITICAL,
    )
    chain_b = EscapeChain(
        id="chain-b",
        steps=[ChainStep(technique=top), ChainStep(technique=second_b)],
        composite_score=0.75,  # identical rounded score — would collide on old key
        severity=Severity.CRITICAL,
    )
    chain_a_dup = EscapeChain(
        id="chain-a",  # genuine duplicate — same id
        steps=[ChainStep(technique=top), ChainStep(technique=second_a)],
        composite_score=0.75,
        severity=Severity.CRITICAL,
    )

    result = _union_chains([[chain_a, chain_b], [chain_a_dup]])
    ids = sorted(c.id for c in result)
    assert ids == ["chain-a", "chain-b"], (
        "distinct chains with identical (top_id, score, severity) must both survive; "
        "true duplicate by chain.id must be deduped"
    )


def test_readyz_returns_503_when_cache_unhealthy():
    """When the operator opted into kernel-CVE gating + node-kernel-
    lookup AND the cache has never successfully fetched, /readyz must
    fail so failurePolicy: Fail propagates the broken state to the
    apiserver instead of admitting pods with the gate silently
    dropped."""
    from cepheus.server.admission import _cache_unhealthy_reason
    from cepheus.server.k8s_client import CacheSnapshot

    class _NeverFetched:
        refresh_interval_sec = 60.0

        def snapshot(self):
            return CacheSnapshot(
                kernel_versions=frozenset(),
                last_refresh_at=0.0,
                last_error="apiserver returned HTTP 403: Forbidden",
            )

    cfg = AdmissionConfig(
        max_severity="critical",
        include_kernel_cves=True,
        node_kernel_cache=_NeverFetched(),  # type: ignore[arg-type]
    )
    reason = _cache_unhealthy_reason(cfg)
    assert reason is not None
    assert "403" in reason


def test_readyz_healthy_when_kernel_cves_disabled():
    """If the operator didn't opt into kernel-CVE gating, cache state
    is irrelevant to /readyz — the gate is using PodSpec data only,
    which the cache doesn't affect."""
    from cepheus.server.admission import _cache_unhealthy_reason
    from cepheus.server.k8s_client import CacheSnapshot

    class _BrokenCache:
        refresh_interval_sec = 60.0

        def snapshot(self):
            return CacheSnapshot(
                kernel_versions=frozenset(),
                last_refresh_at=0.0,
                last_error="cache totally broken",
            )

    cfg = AdmissionConfig(
        max_severity="critical",
        include_kernel_cves=False,  # not opted in — cache state doesn't matter
        node_kernel_cache=_BrokenCache(),  # type: ignore[arg-type]
    )
    assert _cache_unhealthy_reason(cfg) is None


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
