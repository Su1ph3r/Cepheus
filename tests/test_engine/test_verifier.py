"""Tests for the live-verification engine — `cepheus.engine.verifier`.

The subprocess boundary is monkey-patched out; tests focus on dispatch /
classification logic and filter semantics, which is where bugs live.
"""

from __future__ import annotations

from cepheus.engine.verifier import (
    TechniqueVerification,
    VerificationReport,
    VerifyOutcome,
    verify_analysis,
)
from cepheus.models.chain import ChainStep, EscapeChain
from cepheus.models.posture import ContainerPosture
from cepheus.models.result import AnalysisResult
from cepheus.models.technique import EscapeTechnique, Severity, TechniqueCategory


def _tech(tid: str, sev: Severity = Severity.HIGH, verify_command: str | None = "exit 0") -> EscapeTechnique:
    return EscapeTechnique(
        id=tid,
        name=tid.replace("_", " ").title(),
        category=TechniqueCategory.CAPABILITY,
        severity=sev,
        description=f"test {tid}",
        verify_command=verify_command,
    )


def _result(techniques: list[EscapeTechnique]) -> AnalysisResult:
    chains = [
        EscapeChain(
            id=f"chain-{t.id}",
            steps=[ChainStep(technique=t, poc_command="", prerequisite_confidence=1.0)],
            composite_score=0.8,
            reliability_score=0.9,
            stealth_score=0.5,
            confidence_score=1.0,
            severity=t.severity,
            description="",
        )
        for t in techniques
    ]
    return AnalysisResult(
        posture=ContainerPosture(),
        chains=chains,
        total_techniques_checked=len(techniques),
        techniques_matched=len(techniques),
    )


def test_confirmed_when_exit_zero(monkeypatch):
    monkeypatch.setattr(
        "cepheus.engine.verifier._execute_in_container",
        lambda *a, **kw: (0, ""),
    )
    result = _result([_tech("t1")])
    report = verify_analysis(result, container_id="c", runtime="docker")
    assert report.confirmed_count == 1
    assert report.not_confirmed_count == 0
    assert report.results[0].outcome == VerifyOutcome.CONFIRMED


def test_not_confirmed_when_exit_nonzero(monkeypatch):
    monkeypatch.setattr(
        "cepheus.engine.verifier._execute_in_container",
        lambda *a, **kw: (1, "EPERM"),
    )
    result = _result([_tech("t1")])
    report = verify_analysis(result, container_id="c", runtime="docker")
    assert report.not_confirmed_count == 1
    assert report.results[0].outcome == VerifyOutcome.NOT_CONFIRMED
    assert report.results[0].stderr == "EPERM"


def test_error_when_timeout_sentinel(monkeypatch):
    """exit_code=-1 (_RC_TIMEOUT) is the timeout sentinel — classified ERROR
    so operators distinguish "verifier infrastructure broken" from
    "kernel rejected the probe.\""""
    from cepheus.engine.verifier import _RC_TIMEOUT

    assert _RC_TIMEOUT == -1
    monkeypatch.setattr(
        "cepheus.engine.verifier._execute_in_container",
        lambda *a, **kw: (_RC_TIMEOUT, "verify timed out after 10s"),
    )
    result = _result([_tech("t1")])
    report = verify_analysis(result, container_id="c", runtime="docker")
    assert report.error_count == 1
    assert report.results[0].outcome == VerifyOutcome.ERROR


def test_error_when_no_runtime_sentinel(monkeypatch):
    """exit_code=-2 (_RC_NO_RUNTIME) is the missing-runtime sentinel —
    distinct from timeout so the operator can tell whether to bump
    --timeout or install docker/podman."""
    from cepheus.engine.verifier import _RC_NO_RUNTIME

    assert _RC_NO_RUNTIME == -2
    monkeypatch.setattr(
        "cepheus.engine.verifier._execute_in_container",
        lambda *a, **kw: (_RC_NO_RUNTIME, "runtime 'docker' not found in PATH"),
    )
    result = _result([_tech("t1")])
    report = verify_analysis(result, container_id="c", runtime="docker")
    assert report.error_count == 1
    assert report.results[0].outcome == VerifyOutcome.ERROR
    assert "not found" in (report.results[0].stderr or "")


def test_error_when_infra_sentinel(monkeypatch):
    """exit_code=-3 (_RC_INFRA) catches the long tail of OS-side errors
    (PermissionError, OSError, UnicodeDecodeError) so a single bad
    verifier doesn't crash the entire verify_analysis walk."""
    from cepheus.engine.verifier import _RC_INFRA

    assert _RC_INFRA == -3
    monkeypatch.setattr(
        "cepheus.engine.verifier._execute_in_container",
        lambda *a, **kw: (_RC_INFRA, "PermissionError: docker not executable"),
    )
    result = _result([_tech("t1")])
    report = verify_analysis(result, container_id="c", runtime="docker")
    assert report.error_count == 1
    assert report.results[0].outcome == VerifyOutcome.ERROR


def test_one_failing_verifier_does_not_block_other_techniques(monkeypatch):
    """Regression guard for ER3: pre-0.3.5 a single PermissionError in
    one verifier crashed the entire walk, losing results for every
    other technique. With _RC_INFRA each failure becomes a per-technique
    ERROR row and the walk continues."""
    import subprocess

    call_count = {"n": 0}

    def fake_run(*args, **kw):
        call_count["n"] += 1
        # Second call raises a real OSError; first and third succeed.
        if call_count["n"] == 2:
            raise PermissionError("EACCES: docker socket")
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)

    result = _result([_tech("t1"), _tech("t2"), _tech("t3")])
    report = verify_analysis(result, container_id="c", runtime="docker")
    # All three techniques produced a result row — none was lost to a crash.
    assert len(report.results) == 3
    # The middle one is ERROR (infra-side failure), the others are CONFIRMED.
    outcomes = [r.outcome for r in report.results]
    assert outcomes.count(VerifyOutcome.CONFIRMED) == 2
    assert outcomes.count(VerifyOutcome.ERROR) == 1


def test_in_container_timeout_wraps_probe(monkeypatch):
    """Regression guard for RL1: the verifier should wrap probes with
    in-container `timeout(1)` so the wall-clock kill fires inside the
    container — `docker exec`'s host SIGKILL doesn't propagate to the
    in-container shell."""
    import subprocess

    seen_args: list[list[str]] = []

    def fake_run(args, **kw):
        seen_args.append(args)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    from cepheus.engine.verifier import _execute_in_container

    _execute_in_container("c1", "docker", "true", timeout=10)
    # The argv passed to `docker exec` should include `timeout` somewhere
    # in the wrapped sh -c body (last positional arg).
    assert seen_args, "subprocess.run was not invoked"
    last_arg = seen_args[0][-1]
    assert "timeout" in last_arg
    assert "true" in last_arg


def test_timeout_exit_124_classified_as_timeout(monkeypatch):
    """When the in-container `timeout` binary fires, the wrapped shell
    exits 124 — that should map to _RC_TIMEOUT, not a non-zero
    NOT_CONFIRMED."""
    import subprocess

    def fake_run(args, **kw):
        return subprocess.CompletedProcess(args=args, returncode=124, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    from cepheus.engine.verifier import _execute_in_container, _RC_TIMEOUT

    rc, _stderr = _execute_in_container("c1", "docker", "sleep 100", timeout=5)
    assert rc == _RC_TIMEOUT


def test_cap_sys_ptrace_has_no_verifier():
    """cap_sys_ptrace had a broken verifier (`ps -p 1 -o stat=`) that
    reported CONFIRMED 100% of the time because every container's /proc/1
    is readable regardless of CAP_SYS_PTRACE. Per Q2 it was set to None
    until a real ptrace probe is written — verify the regression guard."""
    from cepheus.engine.technique_db import get_technique_by_id

    tech = get_technique_by_id("cap_sys_ptrace")
    assert tech is not None
    assert tech.verify_command is None, (
        "cap_sys_ptrace must NOT have a verify_command — the previous probe "
        "didn't actually test ptrace. NO_VERIFIER is honest; "
        "always-CONFIRMED is a silent lie."
    )


def test_no_verifier_when_verify_command_is_none():
    result = _result([_tech("t_no_check", verify_command=None)])
    report = verify_analysis(result, container_id="c", runtime="docker")
    assert report.no_verifier_count == 1
    assert report.results[0].outcome == VerifyOutcome.NO_VERIFIER


def test_same_technique_in_multiple_chains_runs_once(monkeypatch):
    """A technique that appears in N chains should be verified once, not N times."""
    call_count = {"n": 0}

    def fake_run(*a, **kw):
        call_count["n"] += 1
        return (0, "")

    monkeypatch.setattr("cepheus.engine.verifier._execute_in_container", fake_run)

    t = _tech("shared")
    chains = [
        EscapeChain(
            id=f"c{i}",
            steps=[ChainStep(technique=t, poc_command="", prerequisite_confidence=1.0)],
            composite_score=0.5,
            reliability_score=0.5,
            stealth_score=0.5,
            confidence_score=0.5,
            severity=Severity.HIGH,
            description="",
        )
        for i in range(3)
    ]
    result = AnalysisResult(
        posture=ContainerPosture(),
        chains=chains,
        total_techniques_checked=1,
        techniques_matched=1,
    )
    report = verify_analysis(result, container_id="c", runtime="docker")
    assert call_count["n"] == 1
    assert len(report.results) == 1


def test_filter_by_severity(monkeypatch):
    monkeypatch.setattr(
        "cepheus.engine.verifier._execute_in_container",
        lambda *a, **kw: (0, ""),
    )
    result = _result(
        [
            _tech("low_t", Severity.LOW),
            _tech("med_t", Severity.MEDIUM),
            _tech("high_t", Severity.HIGH),
            _tech("crit_t", Severity.CRITICAL),
        ]
    )
    report = verify_analysis(result, container_id="c", runtime="docker", only_severities={"critical", "high"})
    assert len(report.results) == 2
    assert {r.technique_id for r in report.results} == {"high_t", "crit_t"}


def test_filter_by_technique_ids(monkeypatch):
    monkeypatch.setattr(
        "cepheus.engine.verifier._execute_in_container",
        lambda *a, **kw: (0, ""),
    )
    result = _result([_tech("t1"), _tech("t2"), _tech("t3")])
    report = verify_analysis(result, container_id="c", runtime="docker", only_technique_ids={"t1", "t3"})
    assert {r.technique_id for r in report.results} == {"t1", "t3"}


def test_report_summary_counts():
    rep = VerificationReport(
        results=[
            TechniqueVerification("a", "A", "high", VerifyOutcome.CONFIRMED, exit_code=0),
            TechniqueVerification("b", "B", "low", VerifyOutcome.NOT_CONFIRMED, exit_code=1),
            TechniqueVerification("c", "C", "medium", VerifyOutcome.NOT_CONFIRMED, exit_code=2),
            TechniqueVerification("d", "D", "critical", VerifyOutcome.NO_VERIFIER),
            TechniqueVerification("e", "E", "critical", VerifyOutcome.ERROR, exit_code=-1),
        ]
    )
    assert rep.confirmed_count == 1
    assert rep.not_confirmed_count == 2
    assert rep.no_verifier_count == 1
    assert rep.error_count == 1


def test_cli_flag_field_populated_on_capability_techniques():
    """cli_flag migration should have populated at least the capability-drop family."""
    from cepheus.engine.technique_db import get_all_techniques

    by_id = {t.id: t for t in get_all_techniques()}
    must_have_flag = {
        "cap_sys_admin_mount",
        "cap_sys_ptrace",
        "cap_dac_read_search",
        "cap_dac_override",
        "cap_net_admin",
        "cap_sys_rawio",
        "cap_net_raw_metadata",
        "devfs_access",
        "writable_proc_privileged",
        "tmpfs_shm_cross_container",
        "lsm_apparmor_unconfined",
        "lsm_selinux_unconfined",
        "cap_sys_admin_apparmor_unconfined",
        "cap_sys_admin_no_seccomp",
    }
    for tid in must_have_flag:
        assert by_id[tid].cli_flag, f"{tid} should have cli_flag populated after migration"
        assert by_id[tid].cli_flag.startswith(("--", "-")), f"{tid} cli_flag should look like a CLI flag"


def test_verify_command_field_populated_on_safe_subset():
    """verify_command migration should have populated at least cap + procfs + sa families."""
    from cepheus.engine.technique_db import get_all_techniques

    by_id = {t.id: t for t in get_all_techniques()}
    must_have_verifier = {
        "cap_sys_admin_mount",
        "cap_dac_read_search",
        "cap_dac_override",
        "procfs_sysrq",
        "procfs_core_pattern",
        "k8s_service_account",
        "k8s_configmap_secrets",
        "cloud_metadata_ssrf",
    }
    for tid in must_have_verifier:
        assert by_id[tid].verify_command, f"{tid} should have verify_command populated"


def test_verifier_coverage_meets_minimum():
    """Regression guard against verifier-coverage backsliding. v0.4.0 ships
    47/65 techniques with verify_command (72% coverage). This test fails if
    the coverage drops below the v0.4.0 floor — preventing accidental
    deletion of probes during refactoring."""
    from cepheus.engine.technique_db import get_all_techniques

    techs = get_all_techniques()
    with_v = [t for t in techs if t.verify_command]
    # Floor: 40 techniques (v0.4.0 ships 47; allow small downward drift for
    # legitimate removals — anything above 40 keeps the differentiator intact).
    assert len(with_v) >= 40, (
        f"Verifier coverage dropped below 40/65 floor — currently {len(with_v)}/65. "
        f"Adding new techniques without verify_command is fine; REMOVING existing "
        f"verify_commands erodes Cepheus's primary moat."
    )


def test_verifier_coverage_complete_for_critical_categories():
    """Mount, combinatorial, and info_disclosure categories should be 100%
    verified — they're the categories where non-destructive probes are
    most natural and most diagnostic. Capability should be at least 8/9
    (cap_sys_ptrace is intentionally NO_VERIFIER per Q2 fix)."""
    from cepheus.engine.technique_db import get_all_techniques
    from collections import defaultdict

    by_cat: dict[str, list] = defaultdict(list)
    for t in get_all_techniques():
        by_cat[t.category.value].append(t)

    def coverage(cat: str) -> tuple[int, int]:
        verified = sum(1 for t in by_cat[cat] if t.verify_command)
        return verified, len(by_cat[cat])

    mount_v, mount_t = coverage("mount")
    assert mount_v == mount_t, f"mount category should be 100% verified, got {mount_v}/{mount_t}"

    combo_v, combo_t = coverage("combinatorial")
    assert combo_v == combo_t, f"combinatorial category should be 100% verified, got {combo_v}/{combo_t}"

    info_v, info_t = coverage("info_disclosure")
    assert info_v == info_t, f"info_disclosure category should be 100% verified, got {info_v}/{info_t}"

    cap_v, cap_t = coverage("capability")
    assert cap_v >= cap_t - 1, (
        f"capability category should be all-but-one verified (cap_sys_ptrace is "
        f"the legitimate None), got {cap_v}/{cap_t}"
    )


def test_verify_analysis_parallel_execution(monkeypatch):
    """Regression guard for the parallel verify path. With multiple
    matched techniques and parallel>1, the probes should run concurrently
    (not sequentially) and produce the same results as serial mode."""
    import threading
    import time

    concurrent_high_water = [0]
    in_flight = [0]
    lock = threading.Lock()

    def fake_run(*a, **kw):
        with lock:
            in_flight[0] += 1
            if in_flight[0] > concurrent_high_water[0]:
                concurrent_high_water[0] = in_flight[0]
        # Hold for 50ms so concurrent probes overlap observably.
        time.sleep(0.05)
        with lock:
            in_flight[0] -= 1
        return (0, "")

    monkeypatch.setattr("cepheus.engine.verifier._execute_in_container", fake_run)

    techs = [_tech(f"t{i}") for i in range(8)]
    result = _result(techs)
    report = verify_analysis(result, container_id="c", runtime="docker", parallel=4)
    # All 8 verified; some ran concurrently (high water > 1).
    assert len(report.results) == 8
    assert concurrent_high_water[0] > 1, (
        f"Expected concurrent verifier execution; max concurrent was {concurrent_high_water[0]}"
    )


def test_verify_analysis_parallel_results_deterministically_ordered(monkeypatch):
    """Parallel execution must still produce stable, deterministic result
    ordering across runs — otherwise SARIF / JSON diff-ability is lost."""
    monkeypatch.setattr(
        "cepheus.engine.verifier._execute_in_container",
        lambda *a, **kw: (0, ""),
    )
    techs = [
        _tech("low_t", Severity.LOW),
        _tech("crit_a", Severity.CRITICAL),
        _tech("med_t", Severity.MEDIUM),
        _tech("crit_b", Severity.CRITICAL),
        _tech("high_t", Severity.HIGH),
    ]
    result = _result(techs)
    r1 = verify_analysis(result, container_id="c", runtime="docker", parallel=4)
    r2 = verify_analysis(result, container_id="c", runtime="docker", parallel=4)
    assert [t.technique_id for t in r1.results] == [t.technique_id for t in r2.results]
    # Severity-desc ordering: critical first (alpha-sorted within), then high, then medium, then low.
    assert [t.technique_id for t in r1.results] == ["crit_a", "crit_b", "high_t", "med_t", "low_t"]


def test_verify_analysis_parallel_one_equals_serial(monkeypatch):
    """parallel=1 should skip the thread pool entirely (debuggability)
    and produce the same results as the default."""
    monkeypatch.setattr(
        "cepheus.engine.verifier._execute_in_container",
        lambda *a, **kw: (0, ""),
    )
    result = _result([_tech(f"t{i}") for i in range(3)])
    r_serial = verify_analysis(result, container_id="c", runtime="docker", parallel=1)
    r_auto = verify_analysis(result, container_id="c", runtime="docker", parallel=None)
    assert [t.technique_id for t in r_serial.results] == [t.technique_id for t in r_auto.results]
    assert r_serial.confirmed_count == r_auto.confirmed_count
