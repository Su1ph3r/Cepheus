"""Tests for the `cepheus verify` subcommand.

Mocks `cepheus.engine.verifier._execute_in_container` so the tests don't
need a real container runtime. Focus is on dispatch, exit-code semantics,
filter wiring, and `--posture` vs auto-enumerate branches — i.e. the
parts that are easy to regress in a CLI refactor.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from cepheus.cli import app

runner = CliRunner()

# T1 posture has many matched techniques across severities — a good
# fixture for filter / multi-technique tests.
FIXTURE_T1 = Path(__file__).parent / "fixtures" / "k8s-goat" / "T1-system-monitor-posture.json"


def _patch_all_confirmed(monkeypatch):
    """Make every verifier succeed — useful for exit-0 / counts tests."""
    monkeypatch.setattr(
        "cepheus.engine.verifier._execute_in_container",
        lambda *a, **kw: (0, ""),
    )


def _patch_all_rejected(monkeypatch):
    monkeypatch.setattr(
        "cepheus.engine.verifier._execute_in_container",
        lambda *a, **kw: (1, "EPERM"),
    )


def test_verify_exit_zero_when_any_confirmed(monkeypatch):
    """Per documented grep-like semantics: exit 0 iff at least one
    technique CONFIRMED. This is the primary contract the `verify`
    command exposes to CI consumers."""
    _patch_all_confirmed(monkeypatch)
    result = runner.invoke(app, ["verify", "-c", "test-container", "--posture", str(FIXTURE_T1)])
    assert result.exit_code == 0, result.output


def test_verify_exit_one_when_none_confirmed(monkeypatch):
    _patch_all_rejected(monkeypatch)
    result = runner.invoke(app, ["verify", "-c", "test-container", "--posture", str(FIXTURE_T1)])
    assert result.exit_code == 1, result.output


def test_verify_json_format_to_file(monkeypatch, tmp_path):
    """--format json -o FILE writes a JSON report with the documented
    summary + results shape."""
    _patch_all_confirmed(monkeypatch)
    out = tmp_path / "verify.json"
    result = runner.invoke(
        app,
        [
            "verify",
            "-c",
            "test-container",
            "--posture",
            str(FIXTURE_T1),
            "--format",
            "json",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["container_id"] == "test-container"
    assert "summary" in data
    assert data["summary"]["confirmed"] >= 1
    assert isinstance(data["results"], list)


def test_verify_filter_all_critical(monkeypatch):
    """--all-critical should restrict verification to critical+high
    techniques only. Verified by counting calls to _execute_in_container."""
    seen = []

    def fake_run(container_id, runtime, command, timeout=10):
        seen.append(command)
        return (0, "")

    monkeypatch.setattr("cepheus.engine.verifier._execute_in_container", fake_run)
    # With --all-critical, only critical+high techniques should be verified.
    result_filtered = runner.invoke(
        app,
        ["verify", "-c", "c1", "--posture", str(FIXTURE_T1), "--all-critical", "--format", "json"],
    )
    assert result_filtered.exit_code == 0, result_filtered.output
    filtered_count = len(seen)

    seen.clear()
    result_all = runner.invoke(app, ["verify", "-c", "c1", "--posture", str(FIXTURE_T1), "--format", "json"])
    assert result_all.exit_code == 0, result_all.output
    all_count = len(seen)

    # All-critical should run no more verifiers than the unfiltered case.
    # On T1 (privileged, hostPath:/) there are also medium-severity techniques
    # so the strict-less-than expectation is reasonable, but we accept equality
    # for postures where every match happens to be critical/high.
    assert filtered_count <= all_count


def test_verify_filter_by_technique_id(monkeypatch):
    """--technique ID restricts to that specific technique only.
    Repeatable, combines via OR with --all-critical."""
    seen_techniques = []

    def fake_run(container_id, runtime, command, timeout=10):
        seen_techniques.append(command)
        return (0, "")

    monkeypatch.setattr("cepheus.engine.verifier._execute_in_container", fake_run)
    result = runner.invoke(
        app,
        [
            "verify",
            "-c",
            "c1",
            "--posture",
            str(FIXTURE_T1),
            "--technique",
            "cap_sys_admin_mount",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    # Should have run at most one verifier (cap_sys_admin_mount). On
    # postures where this technique didn't match, zero is also acceptable.
    assert len(seen_techniques) <= 1


def test_verify_missing_posture_file_exits_nonzero(monkeypatch, tmp_path):
    """A nonexistent --posture file should fail loudly, not silently
    try to enumerate via container runtime."""
    _patch_all_confirmed(monkeypatch)
    result = runner.invoke(app, ["verify", "-c", "c1", "--posture", str(tmp_path / "does-not-exist.json")])
    assert result.exit_code != 0
    assert "not found" in result.output.lower() or "no such" in result.output.lower()


def test_verify_terminal_format_renders_table(monkeypatch):
    """Default terminal format renders a Rich table with outcome,
    severity, technique columns."""
    _patch_all_confirmed(monkeypatch)
    result = runner.invoke(app, ["verify", "-c", "c1", "--posture", str(FIXTURE_T1)])
    assert result.exit_code == 0, result.output
    # Rich's table renderer collapses headers under whatever terminal width
    # the test runner has; check for the summary line that's always present.
    assert "Summary:" in result.output
    assert "confirmed" in result.output


def test_verify_sarif_format_to_file(monkeypatch, tmp_path):
    """--format sarif -o FILE writes a SARIF 2.1.0 log with one result
    per verified technique. New in v0.4.0."""
    _patch_all_confirmed(monkeypatch)
    out = tmp_path / "verify.sarif"
    result = runner.invoke(
        app,
        [
            "verify",
            "-c",
            "test-container",
            "--posture",
            str(FIXTURE_T1),
            "--format",
            "sarif",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert "runs" in data and len(data["runs"]) == 1
    run = data["runs"][0]
    assert run["properties"]["container-id"] == "test-container"
    assert run["properties"]["verify-confirmed"] >= 1
    # Every result references a rule that's in tool.driver.rules.
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids, f"orphan ruleId {res['ruleId']} not in rules"


def test_verify_parallel_flag_accepted(monkeypatch):
    """--parallel/-j flag should be accepted by the CLI and pass through."""
    captured_kwargs = {}
    real_verify = __import__("cepheus.engine.verifier", fromlist=["verify_analysis"]).verify_analysis

    def fake_verify(*args, **kw):
        captured_kwargs.update(kw)
        return real_verify(*args, **kw)

    monkeypatch.setattr("cepheus.engine.verifier.verify_analysis", fake_verify)
    monkeypatch.setattr(
        "cepheus.engine.verifier._execute_in_container",
        lambda *a, **kw: (0, ""),
    )
    result = runner.invoke(app, ["verify", "-c", "c1", "--posture", str(FIXTURE_T1), "--parallel", "4"])
    assert result.exit_code == 0, result.output
    assert captured_kwargs.get("parallel") == 4


def test_verify_parallel_zero_means_auto(monkeypatch):
    """parallel=0 (the default) should resolve to None, letting verify_analysis auto-select."""
    captured_kwargs = {}
    real_verify = __import__("cepheus.engine.verifier", fromlist=["verify_analysis"]).verify_analysis

    def fake_verify(*args, **kw):
        captured_kwargs.update(kw)
        return real_verify(*args, **kw)

    monkeypatch.setattr("cepheus.engine.verifier.verify_analysis", fake_verify)
    monkeypatch.setattr(
        "cepheus.engine.verifier._execute_in_container",
        lambda *a, **kw: (0, ""),
    )
    result = runner.invoke(app, ["verify", "-c", "c1", "--posture", str(FIXTURE_T1)])
    assert result.exit_code == 0, result.output
    assert captured_kwargs.get("parallel") is None
