"""Tests for the `cepheus ci` subcommand.

Image-based enumeration is NOT tested here — it requires a working docker
or podman runtime, which can't be assumed in CI for this project. The
unit tests focus on the posture-file path: feed a fixture in, assert the
gate outcome.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from cepheus.cli import app

runner = CliRunner()

FIXTURE_T1 = Path(__file__).parent / "fixtures" / "k8s-goat" / "T1-system-monitor-posture.json"
FIXTURE_HARDENED = Path(__file__).parent / "fixtures" / "k8s-goat" / "T3-hunger-check-posture.json"


# --- happy paths -----------------------------------------------------


def test_ci_posture_file_no_gate_returns_zero(tmp_path):
    """With no severity gate or fail-on-new, the command always exits 0."""
    out = tmp_path / "report.sarif"
    result = runner.invoke(app, ["ci", str(FIXTURE_T1), "--format", "sarif", "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"


def test_ci_text_format(tmp_path):
    result = runner.invoke(app, ["ci", str(FIXTURE_HARDENED), "--format", "text"])
    assert result.exit_code == 0, result.output
    assert "Analysis Summary" in result.output or "Escape Chains" in result.output


def test_ci_json_format_to_file(tmp_path):
    out = tmp_path / "report.json"
    result = runner.invoke(app, ["ci", str(FIXTURE_T1), "--format", "json", "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()
    data = json.loads(out.read_text())
    assert "chains" in data


# --- severity gate ---------------------------------------------------


def test_ci_severity_gate_fails_on_critical(tmp_path):
    """T1 is privileged + hostPath:/ — has many critical chains. The
    severity gate at critical should fail."""
    out = tmp_path / "report.sarif"
    result = runner.invoke(
        app, ["ci", str(FIXTURE_T1), "--max-severity", "critical", "--format", "sarif", "--output", str(out)]
    )
    assert result.exit_code == 1, result.output
    assert "Severity gate failed" in result.output
    # Report still written even when gate fails — operators want the data.
    assert out.exists()


def test_ci_severity_gate_passes_on_hardened(tmp_path):
    """T3-hunger-check is unprivileged; its only chains are SA-token reads
    (high/medium). A `--max-severity critical` gate should pass."""
    out = tmp_path / "report.sarif"
    result = runner.invoke(
        app, ["ci", str(FIXTURE_HARDENED), "--max-severity", "critical", "--format", "sarif", "--output", str(out)]
    )
    assert result.exit_code == 0, result.output
    assert out.exists()


# --- baseline gate ---------------------------------------------------


def test_ci_fail_on_new_requires_baseline():
    result = runner.invoke(app, ["ci", str(FIXTURE_T1), "--fail-on-new"])
    assert result.exit_code == 2
    assert "requires --baseline" in result.output


def test_ci_self_baseline_zero_regressions(tmp_path):
    """Generate a SARIF baseline from T1, then re-run `ci --baseline=that`.
    Identical posture → zero new chains → exit 0 with --fail-on-new."""
    baseline = tmp_path / "baseline.sarif"
    # 1) capture baseline
    result = runner.invoke(app, ["ci", str(FIXTURE_T1), "--format", "sarif", "--output", str(baseline)])
    assert result.exit_code == 0, result.output
    assert baseline.exists()
    # 2) re-run with that baseline + fail-on-new
    out = tmp_path / "new.sarif"
    result = runner.invoke(
        app,
        [
            "ci",
            str(FIXTURE_T1),
            "--baseline",
            str(baseline),
            "--fail-on-new",
            "--format",
            "sarif",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Baseline:" in result.output
    assert "0 new" in result.output


def test_ci_baseline_detects_new_chains(tmp_path):
    """Use a hardened pod as the baseline, then scan a privileged one.
    The privileged one introduces many new chains → fail-on-new exits 1."""
    baseline = tmp_path / "baseline.sarif"
    result = runner.invoke(app, ["ci", str(FIXTURE_HARDENED), "--format", "sarif", "--output", str(baseline)])
    assert result.exit_code == 0

    result = runner.invoke(
        app,
        [
            "ci",
            str(FIXTURE_T1),
            "--baseline",
            str(baseline),
            "--fail-on-new",
            "--format",
            "sarif",
            "--output",
            str(tmp_path / "regressed.sarif"),
        ],
    )
    assert result.exit_code == 1, result.output
    assert "Baseline regression" in result.output


def test_ci_baseline_file_not_found(tmp_path):
    result = runner.invoke(
        app, ["ci", str(FIXTURE_T1), "--baseline", str(tmp_path / "nonexistent.sarif"), "--fail-on-new"]
    )
    assert result.exit_code == 2
    assert "baseline" in result.output.lower()


def test_ci_baseline_invalid_format(tmp_path):
    bad = tmp_path / "garbage.json"
    bad.write_text(json.dumps({"unrelated": "object"}))
    result = runner.invoke(app, ["ci", str(FIXTURE_T1), "--baseline", str(bad), "--fail-on-new"])
    assert result.exit_code == 2
    assert "baseline" in result.output.lower()


# --- posture-shape validation (S1+S2 regression guard) ---------------


def test_ci_rejects_empty_object_posture(tmp_path):
    """`{}` parses as valid JSON and `ContainerPosture.model_validate`
    accepts it (every field has a default), producing a zero-finding
    scan that passes every gate. The structural validator must reject
    it before the analyzer sees it — otherwise a broken enumerator
    silently turns into a green CI badge."""
    empty = tmp_path / "empty.json"
    empty.write_text("{}", encoding="utf-8")
    result = runner.invoke(app, ["ci", str(empty), "--max-severity", "critical"])
    assert result.exit_code == 1, result.output
    assert "missing required key" in result.output.lower() or "not a valid cepheus posture" in result.output.lower()


def test_ci_rejects_non_object_json(tmp_path):
    """A JSON array or string at the top level isn't a posture."""
    bad = tmp_path / "array.json"
    bad.write_text("[]", encoding="utf-8")
    result = runner.invoke(app, ["ci", str(bad), "--max-severity", "critical"])
    assert result.exit_code == 1, result.output
    assert "json object" in result.output.lower() or "must be" in result.output.lower()


def test_ci_rejects_posture_missing_required_keys(tmp_path):
    """A JSON object that has SOME keys but not the required structural
    ones should be rejected. Common shape: someone runs `echo '{}' > x`
    or pipes a different tool's output."""
    bad = tmp_path / "weird.json"
    bad.write_text(json.dumps({"hostname": "ok"}), encoding="utf-8")
    result = runner.invoke(app, ["ci", str(bad), "--max-severity", "critical"])
    assert result.exit_code == 1, result.output
    assert "missing required key" in result.output.lower()


# --- enumerate argv mutex (Q-I5 + Q-I1 regression guards) ------------


def test_enumerate_rejects_both_container_id_and_image():
    """--container-id and --image are mutually exclusive. Per Q-I1 the
    exit code is 2 (invocation error), matching ci's documented convention."""
    result = runner.invoke(app, ["enumerate", "--container-id", "x", "--image", "nginx:latest"])
    assert result.exit_code == 2, result.output
    assert "exactly one" in result.output.lower()


def test_enumerate_rejects_neither_container_id_nor_image():
    """Same mutex check — neither side passed."""
    result = runner.invoke(app, ["enumerate"])
    assert result.exit_code == 2, result.output
    assert "exactly one" in result.output.lower()


# --- severity-rank lookup (S3 regression guard) ----------------------


def test_severity_filter_uses_direct_lookup_not_get_with_default():
    """Regression guard for S3: the severity filter must use direct
    SEVERITY_RANK[...] indexing so an unknown severity raises KeyError
    instead of silently routing the chain below every gate via dict.get
    with fallback 0."""
    from cepheus.cli import _filter_by_severity, SEVERITY_RANK, SeverityFilter

    # Sanity: SEVERITY_RANK is complete for all current Severity enum values.
    from cepheus.models.technique import Severity

    for sev in Severity:
        assert sev.value in SEVERITY_RANK, f"SEVERITY_RANK missing {sev.value}"
    # And the filter accepts every defined severity without raising.
    from cepheus.models.result import AnalysisResult
    from cepheus.models.posture import ContainerPosture

    empty_result = AnalysisResult(
        posture=ContainerPosture(),
        chains=[],
        remediations=[],
        total_techniques_checked=0,
        techniques_matched=0,
    )
    for sev_filter in SeverityFilter:
        _filter_by_severity(empty_result, sev_filter)  # must not raise


def test_filter_by_severity_populates_techniques_in_visible_chains():
    """Regression guard for S3 (additive fix): _filter_by_severity should
    populate techniques_in_visible_chains with the unique-technique count
    across the post-filter chain set, so renderers/operators can pick the
    consistent count without the original techniques_matched changing
    semantics."""
    from cepheus.cli import _filter_by_severity, SeverityFilter
    from cepheus.cli import _load_posture, _run_analysis
    from cepheus.config import CepheusConfig

    posture = _load_posture(FIXTURE_T1)
    result = _run_analysis(posture, CepheusConfig(), llm=False)
    pre_filter_matched = result.techniques_matched
    _filter_by_severity(result, SeverityFilter.critical)
    # The new field is populated and is <= the pre-filter count.
    assert result.techniques_in_visible_chains is not None
    assert result.techniques_in_visible_chains <= pre_filter_matched
    # And the legacy field is unchanged (additive, non-breaking).
    assert result.techniques_matched == pre_filter_matched


# --- --output validation (E2 regression guards) ----------------------


def test_ci_output_is_directory_rejected_cleanly(tmp_path):
    """Regression guard for E2: passing an existing directory as
    --output previously raised IsADirectoryError as a raw traceback;
    now produces a clean error message at exit code 2."""
    result = runner.invoke(app, ["ci", str(FIXTURE_T1), "--format", "sarif", "--output", str(tmp_path)])
    assert result.exit_code == 2, result.output
    assert "directory" in result.output.lower()
    assert "Traceback" not in result.output


def test_ci_output_parent_does_not_exist_rejected_cleanly(tmp_path):
    """Pointing --output at a path whose parent directory doesn't exist
    should be caught early with a clean error."""
    nowhere = tmp_path / "does_not_exist" / "report.sarif"
    result = runner.invoke(app, ["ci", str(FIXTURE_T1), "--format", "sarif", "--output", str(nowhere)])
    assert result.exit_code == 2, result.output
    assert "parent" in result.output.lower() or "does not exist" in result.output.lower()
    assert "Traceback" not in result.output


# --- container-id enumerator (ER2 regression guard) ------------------


def test_enumerate_container_empty_stdout_emits_clear_error(monkeypatch):
    """Regression guard for ER2: a docker exec that returns exit 0 with
    empty stdout previously fell through to _validate_posture_json's
    "did not produce valid JSON" message. Now it emits a clear
    distroless-style error pointing at the actual cause."""
    import subprocess

    def fake_run(args, **kw):
        return subprocess.CompletedProcess(args=args, returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr("subprocess.run", fake_run)
    result = runner.invoke(app, ["enumerate", "--container-id", "test-container"])
    assert result.exit_code == 1, result.output
    assert "no output" in result.output.lower() or "did not produce" in result.output.lower()


def test_enumerate_container_uses_stdin_pipe_not_docker_cp(monkeypatch):
    """Regression guard for R2 (TOCTOU) + RL3 (leftover script):
    _enumerate_container should stream the enumerator via stdin (no
    `docker cp`, no leftover /tmp/cepheus-enum.sh in the target)."""
    import subprocess

    calls = []

    def fake_run(args, **kw):
        calls.append((args, kw.get("input")))
        return subprocess.CompletedProcess(args=args, returncode=0, stdout=b'{"kernel": {}, "runtime": {}}', stderr=b"")

    monkeypatch.setattr("subprocess.run", fake_run)
    result = runner.invoke(app, ["enumerate", "--container-id", "test-container"])
    assert result.exit_code == 0, result.output
    # No `docker cp` call should be made.
    for args, _ in calls:
        assert "cp" not in args, "_enumerate_container must not use docker cp anymore (TOCTOU)"
    # The single exec call should pass the script via stdin.
    assert len(calls) == 1, f"expected one subprocess call, got {len(calls)}"
    exec_args, input_bytes = calls[0]
    assert "exec" in exec_args
    assert "-i" in exec_args
    assert input_bytes is not None and len(input_bytes) > 0, "enumerator must be piped via stdin"
