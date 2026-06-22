"""Tests for the confirmation layer — promoting static matches to confirmed
findings via live verification, and the precondition-only downgrade that stops
the verifier from over-confirming version-gated CVEs.

This is the precision backbone of the "confirmed-only by default" behaviour:
the engagement failure mode was static matches presented as findings. These
tests pin that a chain is CONFIRMED only when a live verifier actually proves
the primitive — never from a passing precondition probe alone.
"""

from __future__ import annotations

from cepheus.engine.confirmation import (
    apply_confirmation,
    mark_unconfirmed,
)
from cepheus.models.chain import ChainStep, EscapeChain
from cepheus.models.posture import ContainerPosture, KernelInfo, RuntimeInfo
from cepheus.models.result import AnalysisResult
from cepheus.models.technique import (
    ConfirmationStatus,
    EscapeTechnique,
    Severity,
    TechniqueCategory,
)
from cepheus.engine.verifier import (
    TechniqueVerification,
    VerificationReport,
    VerifyOutcome,
)


def _tech(tid: str, *, verify: str | None = "true", primitive: bool = True) -> EscapeTechnique:
    return EscapeTechnique(
        id=tid,
        name=tid,
        category=TechniqueCategory.RUNTIME,
        severity=Severity.CRITICAL,
        description="x",
        verify_command=verify,
        verify_confirms_primitive=primitive,
    )


def _result(*techs: EscapeTechnique) -> AnalysisResult:
    posture = ContainerPosture(kernel=KernelInfo(version="5.15.0"), runtime=RuntimeInfo(runtime="docker"))
    chain = EscapeChain(
        id="c1",
        steps=[ChainStep(technique=t) for t in techs],
        severity=Severity.CRITICAL,
        description="chain",
    )
    return AnalysisResult(posture=posture, chains=[chain])


def _report(*pairs: tuple[str, VerifyOutcome]) -> VerificationReport:
    return VerificationReport(
        results=[
            TechniqueVerification(technique_id=tid, technique_name=tid, severity="critical", outcome=o)
            for tid, o in pairs
        ]
    )


def test_confirmed_primitive_marks_chain_confirmed():
    result = _result(_tech("misconfig", primitive=True))
    apply_confirmation(result, _report(("misconfig", VerifyOutcome.CONFIRMED)))
    assert result.chains[0].confirmation == ConfirmationStatus.CONFIRMED


def test_refuted_step_refutes_chain():
    result = _result(_tech("misconfig"))
    apply_confirmation(result, _report(("misconfig", VerifyOutcome.NOT_CONFIRMED)))
    assert result.chains[0].confirmation == ConfirmationStatus.REFUTED


def test_precondition_only_pass_is_potential_not_confirmed():
    """The crux fix: a passing PRECONDITION-only verifier (e.g. NVIDIA device
    present, but toolkit version unproven) must NOT be reported as a confirmed
    escape — otherwise a patched host lights up CRITICAL."""
    result = _result(_tech("cve_precond", primitive=False))
    apply_confirmation(result, _report(("cve_precond", VerifyOutcome.CONFIRMED)))
    assert result.chains[0].confirmation == ConfirmationStatus.POTENTIAL


def test_precondition_only_fail_still_refutes():
    """An absent precondition genuinely means the CVE can't be exploited here,
    so a FAIL refutes even for precondition-only verifiers — that's real recall
    for the false-positive-suppression story."""
    result = _result(_tech("cve_precond", primitive=False))
    apply_confirmation(result, _report(("cve_precond", VerifyOutcome.NOT_CONFIRMED)))
    assert result.chains[0].confirmation == ConfirmationStatus.REFUTED


def test_no_verifier_is_unverifiable():
    result = _result(_tech("kernelcve", verify=None))
    apply_confirmation(result, _report(("kernelcve", VerifyOutcome.NO_VERIFIER)))
    assert result.chains[0].confirmation == ConfirmationStatus.UNVERIFIABLE


def test_multistep_unconfirmed_step_blocks_chain_confirmation():
    """A chain is only as exploitable as its weakest step: one confirmed step
    plus one merely-potential step is POTENTIAL, not CONFIRMED."""
    result = _result(_tech("a"), _tech("b"))
    apply_confirmation(result, _report(("a", VerifyOutcome.CONFIRMED)))  # b not in report
    assert result.chains[0].confirmation == ConfirmationStatus.POTENTIAL


def test_error_outcome_propagates():
    result = _result(_tech("x"))
    apply_confirmation(result, _report(("x", VerifyOutcome.ERROR)))
    assert result.chains[0].confirmation == ConfirmationStatus.ERROR


def test_mark_unconfirmed_offline_potential_when_all_verifiable():
    result = _result(_tech("a"), _tech("b"))
    mark_unconfirmed(result)
    assert result.chains[0].confirmation == ConfirmationStatus.POTENTIAL


def test_mark_unconfirmed_offline_unverifiable_when_any_lacks_verifier():
    result = _result(_tech("a"), _tech("kernelcve", verify=None))
    mark_unconfirmed(result)
    assert result.chains[0].confirmation == ConfirmationStatus.UNVERIFIABLE


def test_gate_confirmed_only_default_keeps_only_confirmed():
    """The headline behaviour: after a live run, the default report shows ONLY
    confirmed escapes. Refuted matches (the engagement's false positives) are
    always dropped; unproven matches are hidden."""
    from cepheus.cli import _gate_by_confirmation

    result = _result(_tech("a"))
    result.chains = [
        _named_chain("a", ConfirmationStatus.CONFIRMED),
        _named_chain("b", ConfirmationStatus.REFUTED),
        _named_chain("c", ConfirmationStatus.POTENTIAL),
        _named_chain("d", ConfirmationStatus.UNVERIFIABLE),
    ]
    _gate_by_confirmation(result, show_potential=False)
    assert [c.id for c in result.chains] == ["a"]


def test_gate_show_potential_keeps_unproven_but_never_refuted():
    from cepheus.cli import _gate_by_confirmation

    result = _result(_tech("a"))
    result.chains = [
        _named_chain("a", ConfirmationStatus.CONFIRMED),
        _named_chain("b", ConfirmationStatus.REFUTED),
        _named_chain("c", ConfirmationStatus.POTENTIAL),
        _named_chain("d", ConfirmationStatus.UNVERIFIABLE),
    ]
    _gate_by_confirmation(result, show_potential=True)
    assert [c.id for c in result.chains] == ["a", "c", "d"]


def _named_chain(cid: str, status: ConfirmationStatus) -> EscapeChain:
    chain = EscapeChain(
        id=cid,
        steps=[ChainStep(technique=_tech(cid))],
        severity=Severity.CRITICAL,
        description=cid,
    )
    chain.confirmation = status
    return chain


def test_precondition_sidecar_covers_real_cves():
    """Guard: the curated precondition-only set must stay applied to the real
    technique DB so a passing GPU/ingress/unshare probe never confirms."""
    from cepheus.engine.technique_db import get_technique_by_id

    for tid in ("cve_2025_23266", "cve_2024_0132", "cve_2025_1974", "cve_2022_0185"):
        t = get_technique_by_id(tid)
        assert t is not None and t.verify_command
        assert t.verify_confirms_primitive is False, tid
    # The leaked-fd runc CVE genuinely proves the primitive — must stay True.
    assert get_technique_by_id("cve_2024_21626").verify_confirms_primitive is True
