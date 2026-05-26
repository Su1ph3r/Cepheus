"""Tests for the baseline-diff engine used by `cepheus ci --baseline`."""

from __future__ import annotations

import json

import pytest

from cepheus.engine.baseline import (
    ChainIdentity,
    diff,
    load_baseline,
)
from cepheus.models.chain import ChainStep, EscapeChain
from cepheus.models.technique import EscapeTechnique, Severity, TechniqueCategory


# --- helpers ---------------------------------------------------------


def _tech(tid: str) -> EscapeTechnique:
    return EscapeTechnique(
        id=tid,
        name=tid.replace("_", " ").title(),
        category=TechniqueCategory.CAPABILITY,
        severity=Severity.HIGH,
        description=f"test technique {tid}",
        prerequisites=[],
        mitre_attack=[],
    )


def _chain(chain_id: str, technique_ids: list[str], severity: Severity = Severity.HIGH) -> EscapeChain:
    return EscapeChain(
        id=chain_id,
        steps=[
            ChainStep(technique=_tech(tid), poc_command=f"# {tid}", prerequisite_confidence=1.0)
            for tid in technique_ids
        ],
        composite_score=0.8,
        reliability_score=0.9,
        stealth_score=0.5,
        confidence_score=1.0,
        severity=severity,
        description="test",
    )


# --- ChainIdentity.matches -------------------------------------------


def test_identity_matches_by_chain_id():
    a = ChainIdentity(chain_id="abc123", technique_ids=("cap_sys_admin",))
    b = ChainIdentity(chain_id="abc123", technique_ids=("different",))
    assert a.matches(b)


def test_identity_matches_by_technique_tuple():
    a = ChainIdentity(chain_id="abc123", technique_ids=("cap_sys_admin", "procfs_sysrq"))
    b = ChainIdentity(chain_id="xyz789", technique_ids=("cap_sys_admin", "procfs_sysrq"))
    assert a.matches(b)


def test_identity_does_not_match_when_both_differ():
    a = ChainIdentity(chain_id="abc", technique_ids=("x",))
    b = ChainIdentity(chain_id="def", technique_ids=("y",))
    assert not a.matches(b)


def test_two_empty_identities_do_not_match():
    """Regression guard for SF11: pre-0.3.5 `matches` returned True for
    two identities with empty chain_id AND empty technique_ids because
    () == () is True. A corrupted baseline entry would then silently
    match every degenerate chain and mask real regressions."""
    a = ChainIdentity(chain_id="", technique_ids=())
    b = ChainIdentity(chain_id="", technique_ids=())
    assert not a.matches(b)


def test_empty_chain_id_does_not_match_empty_chain_id():
    """Even when only one side has data, empty-string chain_ids must
    never match each other — they're not real identities."""
    a = ChainIdentity(chain_id="", technique_ids=("t1",))
    b = ChainIdentity(chain_id="", technique_ids=("t2",))
    assert not a.matches(b)


# --- diff() ----------------------------------------------------------


def test_diff_empty_baseline_marks_all_new():
    current = [_chain("c1", ["t1"]), _chain("c2", ["t2"])]
    result = diff(current, baseline=set())
    assert len(result.new) == 2
    assert len(result.preserved) == 0
    assert len(result.removed) == 0
    assert result.has_regressions


def test_diff_identical_baseline_marks_all_preserved():
    current = [_chain("c1", ["t1"]), _chain("c2", ["t2"])]
    baseline = {
        ChainIdentity(chain_id="c1", technique_ids=("t1",)),
        ChainIdentity(chain_id="c2", technique_ids=("t2",)),
    }
    result = diff(current, baseline)
    assert len(result.new) == 0
    assert len(result.preserved) == 2
    assert len(result.removed) == 0
    assert not result.has_regressions


def test_diff_partial_overlap_classifies_correctly():
    current = [_chain("c1", ["t1"]), _chain("c2", ["t2"])]
    baseline = {
        ChainIdentity(chain_id="c1", technique_ids=("t1",)),
        ChainIdentity(chain_id="c3-gone", technique_ids=("t3",)),
    }
    result = diff(current, baseline)
    new_ids = [c.id for c in result.new]
    preserved_ids = [c.id for c in result.preserved]
    removed_techs = [i.technique_ids for i in result.removed]
    assert new_ids == ["c2"]
    assert preserved_ids == ["c1"]
    assert removed_techs == [("t3",)]


def test_diff_matches_by_technique_tuple_when_chain_id_drifts():
    """If the chain builder re-hashes (e.g. new step order), the identity
    should still match via the technique tuple — same primitive."""
    current = [_chain("new-hash", ["t1", "t2"])]
    baseline = {ChainIdentity(chain_id="old-hash", technique_ids=("t1", "t2"))}
    result = diff(current, baseline)
    assert len(result.preserved) == 1
    assert len(result.new) == 0


# --- load_baseline ---------------------------------------------------


def test_load_baseline_missing_file(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        load_baseline(tmp_path / "missing.json")


def test_load_baseline_invalid_json(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("not json")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_baseline(f)


def test_load_baseline_unrecognised_structure(tmp_path):
    f = tmp_path / "weird.json"
    f.write_text(json.dumps({"some": "object"}))
    with pytest.raises(ValueError, match="not recognised"):
        load_baseline(f)


def test_load_baseline_json_report(tmp_path, sample_analysis_result):
    """A cepheus JSON report should load and produce one identity per chain."""
    from cepheus.output.json_report import write_report

    f = tmp_path / "report.json"
    write_report(sample_analysis_result, f)
    identities = load_baseline(f)
    assert len(identities) == len(sample_analysis_result.chains)


def test_load_baseline_sarif_report(tmp_path, sample_analysis_result):
    """A SARIF report should load via partialFingerprints + properties.techniques."""
    from cepheus.output.sarif import write_sarif

    f = tmp_path / "report.sarif"
    write_sarif(sample_analysis_result, f)
    identities = load_baseline(f)
    assert len(identities) == len(sample_analysis_result.chains)


def test_round_trip_via_sarif_preserves_identity(sample_analysis_result, tmp_path):
    """Writing a SARIF and reloading it as a baseline should preserve the
    chain identities — so a CI run with the same posture has zero new
    chains against its own previous output."""
    from cepheus.output.sarif import write_sarif

    f = tmp_path / "report.sarif"
    write_sarif(sample_analysis_result, f)
    baseline = load_baseline(f)

    result = diff(sample_analysis_result.chains, baseline)
    assert len(result.new) == 0
    assert len(result.preserved) == len(sample_analysis_result.chains)
    assert not result.has_regressions


def test_load_baseline_directory_path_yields_valueerror(tmp_path):
    """Regression guard for SF12: path-points-to-directory previously
    leaked IsADirectoryError as a raw Python traceback through to the
    user. Should be wrapped as ValueError so the CLI's existing handler
    produces a polished error message."""
    with pytest.raises(ValueError):
        load_baseline(tmp_path)  # tmp_path is a directory


def test_diff_removed_ordering_is_deterministic():
    """Regression guard for Q-I4: `result.removed` must be sorted by
    (chain_id, technique_ids) so repeated runs against the same inputs
    produce identical output. Pre-fix, ordering came from `set`
    iteration which is hash-randomized per process."""
    baseline = {
        ChainIdentity(chain_id="zzz", technique_ids=("z",)),
        ChainIdentity(chain_id="aaa", technique_ids=("a",)),
        ChainIdentity(chain_id="mmm", technique_ids=("m",)),
    }
    result = diff(current_chains=[], baseline=baseline)
    removed_ids = [b.chain_id for b in result.removed]
    assert removed_ids == sorted(removed_ids)
    # And running twice gives the same answer.
    second = diff(current_chains=[], baseline=baseline)
    assert [b.chain_id for b in second.removed] == removed_ids


def test_diff_one_baseline_entry_cannot_preserve_two_current_chains():
    """Regression guard for S6: pre-0.3.5 if two current chains both
    matched the same baseline entry (e.g. same technique tuple, different
    chain_ids), both were appended to `preserved` and the second was
    NOT flagged as new — silently masking a regression for --fail-on-new.

    With consume-on-match, the first claims the baseline entry and the
    second falls through to `new`, correctly flagging the regression."""
    current = [_chain("c1", ["t1", "t2"]), _chain("c2", ["t1", "t2"])]
    baseline = {ChainIdentity(chain_id="some-old-hash", technique_ids=("t1", "t2"))}
    result = diff(current, baseline)
    # One preserve, one new. Pre-fix this was two preserves, zero new.
    assert len(result.preserved) == 1
    assert len(result.new) == 1
    assert result.has_regressions  # the second chain IS a regression


def test_load_baseline_json_null_chain_does_not_crash(tmp_path):
    """Regression guard for E3: a baseline JSON with `null` entries in
    the chains array previously raised AttributeError; now silently
    skipped (defensive)."""
    bad = tmp_path / "null-chain.json"
    bad.write_text(json.dumps({"chains": [None, {"id": "c1", "steps": []}]}), encoding="utf-8")
    identities = load_baseline(bad)
    # The valid entry is loaded; the null is dropped without raising.
    assert any(i.chain_id == "c1" for i in identities)


def test_load_baseline_json_non_dict_step_does_not_crash(tmp_path):
    """Regression guard for E3: a step that's `null` or a non-dict
    previously raised AttributeError on `.get(...)`."""
    bad = tmp_path / "bad-steps.json"
    bad.write_text(
        json.dumps({"chains": [{"id": "c1", "steps": [None, "string-step", {"technique": {"id": "t1"}}]}]}),
        encoding="utf-8",
    )
    identities = load_baseline(bad)
    # The valid step contributes; non-dicts are dropped.
    assert any(i.technique_ids == ("t1",) for i in identities)


def test_load_baseline_json_empty_string_technique_id_dropped(tmp_path):
    """Regression guard for L3: pre-0.3.5 a step with `{"technique": {"id": ""}}`
    contributed an empty-string to the techniques tuple, allowing two
    corrupt baselines to silently match via `("",) == ("",)`."""
    bad = tmp_path / "empty-id.json"
    bad.write_text(
        json.dumps({"chains": [{"id": "c1", "steps": [{"technique": {"id": ""}}]}]}),
        encoding="utf-8",
    )
    identities = load_baseline(bad)
    # The empty-id step is dropped; the chain still loads via its id.
    for i in identities:
        assert "" not in i.technique_ids, "empty-string technique ids must not survive into the identity tuple"


def test_load_baseline_sarif_null_run_does_not_crash(tmp_path):
    """Regression guard for E4: SARIF with `null` runs entry — defensive."""
    bad = tmp_path / "null-run.sarif"
    bad.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    None,
                    {"results": [{"partialFingerprints": {"chainFingerprint/v1": "fp1"}}]},
                ],
            }
        ),
        encoding="utf-8",
    )
    identities = load_baseline(bad)
    assert any(i.chain_id == "fp1" for i in identities)


def test_load_baseline_sarif_accepts_schema_without_strict_version(tmp_path):
    """Regression guard for E6: format detection was strict-matching
    `version == "2.1.0"`. SARIF files with a numeric `version: 2.1`
    or with `$schema` and no `version` field at all were rejected
    despite being structurally valid SARIF logs."""
    bad = tmp_path / "schema-only.sarif"
    bad.write_text(
        json.dumps(
            {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [{"results": [{"partialFingerprints": {"chainFingerprint/v1": "fp1"}}]}],
            }
        ),
        encoding="utf-8",
    )
    identities = load_baseline(bad)
    assert any(i.chain_id == "fp1" for i in identities)
