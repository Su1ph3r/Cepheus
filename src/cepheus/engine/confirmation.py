"""Confirmation layer — promote static matches to confirmed findings.

A matched chain is a *hypothesis*: its prerequisites matched the captured
posture. Whether the kernel/runtime actually permits the primitive in the
concrete container is a separate question answered by the live verifier
(``cepheus.engine.verifier``). This module joins the two: it stamps each
chain in an ``AnalysisResult`` with a :class:`ConfirmationStatus` so the
CLI can default to surfacing only *confirmed* escapes — the fix for the
"every finding was a false positive" failure mode where static matches were
presented with the same authority as demonstrated ones.

Two entry points:

* :func:`apply_confirmation` — given a :class:`VerificationReport` from a
  live run, fold per-technique outcomes into per-chain statuses.
* :func:`mark_unconfirmed` — when no live verification was possible (offline
  posture file, no container), label every chain POTENTIAL or UNVERIFIABLE
  so the renderer never implies a match was confirmed.

Chain-level aggregation rule (a chain succeeds only if every step does):

* any step REFUTED            -> chain REFUTED   (a required step is rejected)
* else any step ERROR         -> chain ERROR     (a step was never tested)
* else any step UNVERIFIABLE
       and none CONFIRMED      -> chain UNVERIFIABLE
* else any step POTENTIAL      -> chain POTENTIAL (something still unproven)
* else (all CONFIRMED)         -> chain CONFIRMED
"""

from __future__ import annotations

from cepheus.models.result import AnalysisResult
from cepheus.models.technique import ConfirmationStatus
from cepheus.engine.verifier import VerificationReport, VerifyOutcome

# Map a per-technique verifier outcome to a per-step confirmation status.
_OUTCOME_TO_STATUS = {
    VerifyOutcome.CONFIRMED: ConfirmationStatus.CONFIRMED,
    VerifyOutcome.NOT_CONFIRMED: ConfirmationStatus.REFUTED,
    VerifyOutcome.NO_VERIFIER: ConfirmationStatus.UNVERIFIABLE,
    VerifyOutcome.ERROR: ConfirmationStatus.ERROR,
}


def _aggregate(step_statuses: list[ConfirmationStatus]) -> ConfirmationStatus:
    """Collapse the per-step statuses of one chain into a single verdict.

    Encodes "a chain is only as exploitable as its weakest step": a single
    refuted/erroring/unproven step prevents the chain from being CONFIRMED.
    """
    if not step_statuses:
        return ConfirmationStatus.UNVERIFIABLE
    s = set(step_statuses)
    if ConfirmationStatus.REFUTED in s:
        return ConfirmationStatus.REFUTED
    if ConfirmationStatus.ERROR in s:
        return ConfirmationStatus.ERROR
    if ConfirmationStatus.CONFIRMED not in s and ConfirmationStatus.UNVERIFIABLE in s:
        # Nothing confirmed and at least one step can't be verified at all.
        return ConfirmationStatus.UNVERIFIABLE
    if ConfirmationStatus.POTENTIAL in s or ConfirmationStatus.UNVERIFIABLE in s:
        # Some steps confirmed, but others remain unproven — not a full chain.
        return ConfirmationStatus.POTENTIAL
    return ConfirmationStatus.CONFIRMED


def apply_confirmation(result: AnalysisResult, report: VerificationReport) -> None:
    """Stamp each chain in ``result`` with a confirmation status derived from a
    live :class:`VerificationReport`. Mutates ``result.chains`` in place.

    A technique that appears in a chain but not in the report (e.g. it was
    filtered out of the verify run by ``--only-severity``) is treated as
    POTENTIAL — it has not been confirmed nor refuted.
    """
    outcome_by_id = {r.technique_id: r.outcome for r in report.results}
    for chain in result.chains:
        step_statuses: list[ConfirmationStatus] = []
        for step in chain.steps:
            tech = step.technique
            if tech is None:
                continue
            outcome = outcome_by_id.get(tech.id)
            if outcome is None:
                step_statuses.append(ConfirmationStatus.POTENTIAL)
                continue
            status = _OUTCOME_TO_STATUS[outcome]
            # A passing PRECONDITION-only verifier proves a necessary condition,
            # not the version-specific bug — downgrade CONFIRMED to POTENTIAL so
            # a patched-but-precondition-present host is never reported as a
            # confirmed escape. A failing one still REFUTES (precondition absent
            # => not exploitable here), so only the CONFIRMED case is touched.
            if status == ConfirmationStatus.CONFIRMED and not getattr(tech, "verify_confirms_primitive", True):
                status = ConfirmationStatus.POTENTIAL
            step_statuses.append(status)
        chain.confirmation = _aggregate(step_statuses)


def mark_unconfirmed(result: AnalysisResult) -> None:
    """Label every chain for the *offline* case — no live verification ran.

    A chain is POTENTIAL when every step has an automated verifier (it could
    be confirmed by running ``cepheus scan -c`` against a live container) and
    UNVERIFIABLE when any step has no verifier at all (e.g. a kernel CVE that
    can only be confirmed by exploitation). This keeps the renderer honest:
    nothing is ever shown as CONFIRMED without a live probe behind it.
    """
    for chain in result.chains:
        verifiable = [step.technique for step in chain.steps if step.technique is not None]
        if verifiable and all(t.verify_command for t in verifiable):
            chain.confirmation = ConfirmationStatus.POTENTIAL
        else:
            chain.confirmation = ConfirmationStatus.UNVERIFIABLE
