"""Live verification engine — `cepheus verify`.

Given a target container and an AnalysisResult, attempts each chain's
top-step technique's ``verify_command`` inside the container and reports
whether the kernel/runtime actually permits the primitive. This catches
the case where a static-posture match is theoretically exploitable
(prereqs met) but the live container rejects the operation (e.g. EROFS,
EPERM, or some seccomp filter the enumerator didn't see).

Four outcomes per technique:
  CONFIRMED     — verifier exited 0; the primitive works in this container.
  NOT_CONFIRMED — verifier exited non-zero; static match is a false positive.
  NO_VERIFIER   — technique has no ``verify_command`` defined (e.g. kernel
                  CVEs where the only confirmation is real exploitation).
  ERROR         — verifier infrastructure failed (timeout, runtime binary
                  missing). Distinct from NOT_CONFIRMED — the container's
                  posture was never actually evaluated. Inspect ``exit_code``
                  (one of the ``_RC_*`` sentinels) for the specific cause.

Verify commands are best-effort non-destructive. Most probes are pure
file/readlink/test checks or open-then-close idioms that trigger the
kernel's permission check without ever issuing a write. Two members of
the verifier family (``cap_sys_admin_mount``, ``cap_net_admin``) perform
transient state changes that self-clean on the same shell line. The
verifier never exploits — it only asks "would the operation be
permitted?".
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from enum import Enum

from cepheus.models.result import AnalysisResult


class VerifyOutcome(str, Enum):
    CONFIRMED = "CONFIRMED"
    NOT_CONFIRMED = "NOT_CONFIRMED"
    NO_VERIFIER = "NO_VERIFIER"
    ERROR = "ERROR"


@dataclass
class TechniqueVerification:
    technique_id: str
    technique_name: str
    severity: str
    outcome: VerifyOutcome
    exit_code: int | None = None
    stderr: str | None = None


@dataclass
class VerificationReport:
    results: list[TechniqueVerification]

    @property
    def confirmed_count(self) -> int:
        return sum(1 for r in self.results if r.outcome == VerifyOutcome.CONFIRMED)

    @property
    def not_confirmed_count(self) -> int:
        return sum(1 for r in self.results if r.outcome == VerifyOutcome.NOT_CONFIRMED)

    @property
    def no_verifier_count(self) -> int:
        return sum(1 for r in self.results if r.outcome == VerifyOutcome.NO_VERIFIER)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if r.outcome == VerifyOutcome.ERROR)


_RC_TIMEOUT = -1
_RC_NO_RUNTIME = -2
_RC_INFRA = -3


def _execute_in_container(
    container_id: str,
    runtime: str,
    command: str,
    timeout: int = 10,
) -> tuple[int, str]:
    """Run `command` inside the container via `<runtime> exec`. Returns
    (exit_code, stderr_text). Caller decides what exit_code means.

    Negative codes are infrastructure-side sentinels distinct from any
    shell exit code (POSIX exit codes are 0..255):
      ``_RC_TIMEOUT`` (-1) — verifier wall-clock cap exceeded.
      ``_RC_NO_RUNTIME`` (-2) — runtime binary missing from PATH.
      ``_RC_INFRA`` (-3) — other OS-side subprocess failure (EACCES on
        runtime binary, ENOMEM/EMFILE fork failure, invalid-utf8 in
        stderr, etc.). Catches the long tail so a single bad verifier
        doesn't crash the entire ``verify_analysis`` walk.

    Operators need to distinguish these: a timeout means "bump the
    --timeout flag or fix the probe"; a missing runtime means "install
    docker/podman"; an infra failure means "fix the runner environment".
    Conflating them (the pre-0.3.5 behaviour) made the report ambiguous.
    """
    # Wrap the probe with in-container `timeout(1)` so the wall-clock kill
    # fires INSIDE the container — `docker exec`'s host-side SIGKILL does
    # NOT propagate through the daemon to the in-container process, so
    # using `subprocess.run(timeout=...)` alone leaves an orphan shell
    # running inside the target. The in-container budget is one second
    # shorter than the outer cap so the in-container kill fires first;
    # the outer cap is a safety net for the case where `timeout(1)` is
    # itself missing (busybox `timeout` is standard but absent on some
    # truly-minimal images). `timeout` exits 124 on timeout — translated
    # to the _RC_TIMEOUT sentinel here so callers see ERROR, not a
    # generic non-zero NOT_CONFIRMED.
    inner_budget = max(1, timeout - 1)
    wrapped = f"timeout -k 1 {inner_budget} sh -c {shlex.quote(command)}"
    try:
        proc = subprocess.run(
            [runtime, "exec", "--", container_id, "sh", "-c", wrapped],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        # `timeout` exits 124 on TERM-then-time, 137 on KILL — both
        # mean "we killed the inner probe". Map both to the ERROR sentinel
        # so operators see "verifier timed out" not "primitive rejected".
        if proc.returncode in (124, 137):
            return _RC_TIMEOUT, f"verify timed out after {inner_budget}s (in-container)"
        return proc.returncode, proc.stderr.strip()
    except subprocess.TimeoutExpired:
        # In-container `timeout(1)` didn't fire (likely missing from
        # PATH); outer cap caught the runaway. Probe shell may still be
        # running inside the container — flagged in stderr text.
        return _RC_TIMEOUT, (
            f"verify timed out after {timeout}s (outer); in-container "
            f"`timeout` binary may be missing — probe process may be orphaned"
        )
    except FileNotFoundError:
        return _RC_NO_RUNTIME, f"runtime '{runtime}' not found in PATH"
    except (PermissionError, OSError, UnicodeDecodeError) as exc:
        # Without this catch, ANY of these turns one bad verifier into a
        # crash that wipes the entire VerificationReport for the user.
        # ERROR-classify per-technique so the rest of the walk continues.
        return _RC_INFRA, f"{type(exc).__name__}: {exc}"


def verify_analysis(
    result: AnalysisResult,
    container_id: str,
    *,
    runtime: str = "docker",
    timeout: int = 10,
    only_severities: set[str] | None = None,
    only_technique_ids: set[str] | None = None,
) -> VerificationReport:
    """Walk an AnalysisResult and attempt live verification of each
    matched technique inside the target container.

    Args:
        result: From `cepheus.engine.analyzer.analyze()`.
        container_id: Running container ID/name (passed to `runtime exec`).
        runtime: 'docker' or 'podman'.
        timeout: Per-verifier wall-clock cap.
        only_severities: When set, skip techniques whose severity isn't
            in this set. Useful for `--all-critical` style invocation.
        only_technique_ids: When set, only verify techniques whose id is
            in this set. Mutually-OR'd with only_severities.

    Returns a VerificationReport with one entry per *unique* matched
    technique (deduplicated by technique.id across chains).
    """
    seen_ids: set[str] = set()
    results: list[TechniqueVerification] = []

    for chain in result.chains:
        for step in chain.steps:
            tech = step.technique
            if tech is None or tech.id in seen_ids:
                continue
            seen_ids.add(tech.id)

            if only_severities is not None and tech.severity.value not in only_severities:
                continue
            if only_technique_ids is not None and tech.id not in only_technique_ids:
                continue

            if not tech.verify_command:
                results.append(
                    TechniqueVerification(
                        technique_id=tech.id,
                        technique_name=tech.name,
                        severity=tech.severity.value,
                        outcome=VerifyOutcome.NO_VERIFIER,
                    )
                )
                continue

            rc, stderr = _execute_in_container(container_id, runtime, tech.verify_command, timeout)
            if rc == 0:
                outcome = VerifyOutcome.CONFIRMED
            elif rc in (_RC_TIMEOUT, _RC_NO_RUNTIME, _RC_INFRA):
                outcome = VerifyOutcome.ERROR
            else:
                outcome = VerifyOutcome.NOT_CONFIRMED

            results.append(
                TechniqueVerification(
                    technique_id=tech.id,
                    technique_name=tech.name,
                    severity=tech.severity.value,
                    outcome=outcome,
                    exit_code=rc,
                    stderr=stderr or None,
                )
            )

    return VerificationReport(results=results)
