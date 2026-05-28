"""Tests for cepheus.fleet.diff — posture delta between two scans."""

from __future__ import annotations

from cepheus.fleet.diff import diff_reports


def _pod(
    ns: str,
    name: str,
    *,
    chain_ids: list[str] | None = None,
    score: float = 0.0,
    critical: int = 0,
) -> dict:
    return {
        "namespace": ns,
        "name": name,
        "node": "n1",
        "labels": {},
        "chain_ids": chain_ids or [],
        "severity_counts": {"critical": critical, "high": 0, "medium": 0, "low": 0},
        "top_chain_score": score,
        "techniques_matched": len(chain_ids or []),
        "total_techniques_checked": 65,
        "error": None,
    }


def _report(pods: list[dict]) -> dict:
    return {
        "schema_version": 1,
        "cluster_context": "test",
        "pod_count": len(pods),
        "error_count": 0,
        "pods": pods,
    }


def test_no_changes_yields_no_regressions():
    before = _report([_pod("default", "a", chain_ids=["c1"], score=0.5)])
    after = _report([_pod("default", "a", chain_ids=["c1"], score=0.5)])
    diff = diff_reports(before, after)
    assert diff.pods_added == 0
    assert diff.pods_removed == 0
    assert diff.pods_regressed == 0
    assert diff.pods_improved == 0
    assert diff.has_regressions is False


def test_new_pod_counted_as_addition():
    before = _report([])
    after = _report([_pod("ns", "newpod", chain_ids=["c1", "c2"], score=0.8, critical=2)])
    diff = diff_reports(before, after)
    assert diff.pods_added == 1
    assert diff.has_regressions is True
    delta = next(d for d in diff.deltas if d.name == "newpod")
    assert delta.state == "added"
    assert delta.chains_added == ["c1", "c2"]
    assert delta.critical_after == 2


def test_new_clean_pod_is_not_a_regression():
    """A brand-new pod that introduces zero escape chains is an addition
    for visibility but must NOT trip --fail-on-regression — otherwise
    every clean workload rollout fails CI."""
    before = _report([])
    after = _report([_pod("ns", "fresh-hardened", chain_ids=[], score=0.0)])
    diff = diff_reports(before, after)
    assert diff.pods_added == 1
    assert diff.pods_added_with_chains == 0
    assert diff.has_regressions is False


def test_duplicate_pod_keys_do_not_silently_drop(caplog):
    """Two analyzer-error pods can share an empty ('','') key. The diff
    must warn rather than silently shadow one, so error pods aren't
    under-reported."""
    import logging

    before = _report([])
    after = _report(
        [
            {**_pod("", ""), "error": "spec is not a JSON object"},
            {**_pod("", ""), "error": "missing spec"},
        ]
    )
    with caplog.at_level(logging.WARNING, logger="cepheus.fleet"):
        diff_reports(before, after)
    assert any("duplicate pod key" in rec.message for rec in caplog.records)


def test_removed_pod_does_not_count_as_regression():
    before = _report([_pod("ns", "gone", chain_ids=["c1"], score=0.5)])
    after = _report([])
    diff = diff_reports(before, after)
    assert diff.pods_removed == 1
    # A pod going away is not a regression — it's the desired outcome
    # when ops drains a risky pod.
    assert diff.has_regressions is False


def test_added_chain_to_existing_pod_is_regression():
    before = _report([_pod("ns", "p", chain_ids=["c1"], score=0.4)])
    after = _report([_pod("ns", "p", chain_ids=["c1", "c2"], score=0.6)])
    diff = diff_reports(before, after)
    assert diff.pods_regressed == 1
    delta = next(d for d in diff.deltas if d.name == "p")
    assert delta.state == "regressed"
    assert delta.chains_added == ["c2"]
    assert delta.chains_removed == []


def test_removed_chain_is_improvement():
    before = _report([_pod("ns", "p", chain_ids=["c1", "c2"], score=0.7)])
    after = _report([_pod("ns", "p", chain_ids=["c1"], score=0.4)])
    diff = diff_reports(before, after)
    assert diff.pods_improved == 1
    delta = next(d for d in diff.deltas if d.name == "p")
    assert delta.state == "improved"


def test_score_drift_below_noise_floor_is_unchanged():
    before = _report([_pod("ns", "p", chain_ids=["c1"], score=0.50)])
    after = _report([_pod("ns", "p", chain_ids=["c1"], score=0.52)])
    diff = diff_reports(before, after)
    # delta = 0.02, below the 0.05 floor.
    assert diff.pods_regressed == 0
    assert diff.pods_improved == 0


def test_score_jump_above_noise_floor_is_regression():
    before = _report([_pod("ns", "p", chain_ids=["c1"], score=0.50)])
    after = _report([_pod("ns", "p", chain_ids=["c1"], score=0.70)])
    diff = diff_reports(before, after)
    assert diff.pods_regressed == 1


def test_swap_chains_is_regression():
    # A pod that loses one chain and gains a different one is treated
    # as a regression — we can't know the new one is "less bad".
    before = _report([_pod("ns", "p", chain_ids=["c1"], score=0.5)])
    after = _report([_pod("ns", "p", chain_ids=["c2"], score=0.5)])
    diff = diff_reports(before, after)
    assert diff.pods_regressed == 1


def test_emitted_deltas_omit_unchanged():
    """to_dict() should hide unchanged rows so the diff stays readable
    on a big cluster — the totals still account for them."""
    before = _report(
        [
            _pod("ns", "stable", chain_ids=["c1"], score=0.5),
            _pod("ns", "regressing", chain_ids=["c1"], score=0.5),
        ]
    )
    after = _report(
        [
            _pod("ns", "stable", chain_ids=["c1"], score=0.5),
            _pod("ns", "regressing", chain_ids=["c1", "c2"], score=0.7),
        ]
    )
    diff = diff_reports(before, after)
    emitted = diff.to_dict()["deltas"]
    assert len(emitted) == 1
    assert emitted[0]["name"] == "regressing"
