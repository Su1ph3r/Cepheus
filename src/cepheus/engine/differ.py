"""Posture diff engine — compare two postures and identify security changes."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from cepheus.config import CepheusConfig
from cepheus.models.posture import ContainerPosture
from cepheus.models.technique import Severity, SEVERITY_ORDER


class TechniqueDelta(BaseModel):
    technique_id: str
    name: str
    severity: Severity
    status: str  # "remediated" or "new"


class ChainDelta(BaseModel):
    chain_id: str
    description: str
    severity: Severity
    status: str  # "remediated", "new", or "changed"
    score_before: float | None = None
    score_after: float | None = None


class PostureDelta(BaseModel):
    field_name: str
    before_value: Any = None
    after_value: Any = None


class ScoreSummary(BaseModel):
    total_chains: int = 0
    critical_chains: int = 0
    high_chains: int = 0
    max_score: float = 0.0
    avg_score: float = 0.0


class DiffResult(BaseModel):
    posture_deltas: list[PostureDelta] = Field(default_factory=list)
    technique_deltas: list[TechniqueDelta] = Field(default_factory=list)
    chain_deltas: list[ChainDelta] = Field(default_factory=list)
    before_summary: ScoreSummary = Field(default_factory=ScoreSummary)
    after_summary: ScoreSummary = Field(default_factory=ScoreSummary)
    improved: bool = True


def _build_summary(result) -> ScoreSummary:
    """Build a ScoreSummary from an AnalysisResult."""
    total_chains = len(result.chains)
    critical_chains = sum(1 for c in result.chains if c.severity == Severity.CRITICAL)
    high_chains = sum(1 for c in result.chains if c.severity == Severity.HIGH)
    max_score = max((c.composite_score for c in result.chains), default=0.0)
    avg_score = (
        sum(c.composite_score for c in result.chains) / total_chains
        if total_chains > 0
        else 0.0
    )
    return ScoreSummary(
        total_chains=total_chains,
        critical_chains=critical_chains,
        high_chains=high_chains,
        max_score=max_score,
        avg_score=avg_score,
    )


def _compare_posture_fields(
    before: ContainerPosture, after: ContainerPosture
) -> list[PostureDelta]:
    """Compare key posture fields and return deltas for fields that changed."""
    deltas: list[PostureDelta] = []

    field_accessors: list[tuple[str, Any, Any]] = [
        (
            "capabilities.effective",
            sorted(before.capabilities.effective),
            sorted(after.capabilities.effective),
        ),
        ("security.seccomp", before.security.seccomp, after.security.seccomp),
        ("security.apparmor", before.security.apparmor, after.security.apparmor),
        ("security.selinux", before.security.selinux, after.security.selinux),
        ("runtime.privileged", before.runtime.privileged, after.runtime.privileged),
        (
            "network.can_reach_docker_sock",
            before.network.can_reach_docker_sock,
            after.network.can_reach_docker_sock,
        ),
        (
            "network.can_reach_metadata",
            before.network.can_reach_metadata,
            after.network.can_reach_metadata,
        ),
        (
            "network.can_reach_containerd_sock",
            before.network.can_reach_containerd_sock,
            after.network.can_reach_containerd_sock,
        ),
        (
            "network.can_reach_crio_sock",
            before.network.can_reach_crio_sock,
            after.network.can_reach_crio_sock,
        ),
        ("cgroup_version", before.cgroup_version, after.cgroup_version),
        (
            "writable_paths",
            sorted(before.writable_paths),
            sorted(after.writable_paths),
        ),
        (
            "runtime.runc_version",
            before.runtime.runc_version,
            after.runtime.runc_version,
        ),
        (
            "credentials.service_account_token",
            before.credentials.service_account_token,
            after.credentials.service_account_token,
        ),
    ]

    for field_name, before_val, after_val in field_accessors:
        if before_val != after_val:
            deltas.append(
                PostureDelta(
                    field_name=field_name,
                    before_value=str(before_val),
                    after_value=str(after_val),
                )
            )

    return deltas


def diff_postures(
    before: ContainerPosture,
    after: ContainerPosture,
    config: CepheusConfig | None = None,
) -> DiffResult:
    """Compare two container postures and produce a detailed diff.

    Runs the full analysis pipeline on both postures, then compares
    posture fields, techniques, and escape chains to identify what
    changed between the two configurations.
    """
    from cepheus.engine.analyzer import analyze

    if config is None:
        config = CepheusConfig()

    # Run analysis on both postures
    before_result = analyze(before, config)
    after_result = analyze(after, config)

    # Posture field deltas
    posture_deltas = _compare_posture_fields(before, after)

    # Technique deltas — collect all technique IDs from chain steps
    before_technique_ids: dict[str, tuple[str, Severity]] = {}
    for chain in before_result.chains:
        for step in chain.steps:
            tid = step.technique.id
            if tid not in before_technique_ids:
                before_technique_ids[tid] = (step.technique.name, step.technique.severity)

    after_technique_ids: dict[str, tuple[str, Severity]] = {}
    for chain in after_result.chains:
        for step in chain.steps:
            tid = step.technique.id
            if tid not in after_technique_ids:
                after_technique_ids[tid] = (step.technique.name, step.technique.severity)

    before_only = set(before_technique_ids.keys()) - set(after_technique_ids.keys())
    after_only = set(after_technique_ids.keys()) - set(before_technique_ids.keys())

    technique_deltas: list[TechniqueDelta] = []
    for tid in sorted(before_only):
        name, severity = before_technique_ids[tid]
        technique_deltas.append(
            TechniqueDelta(
                technique_id=tid,
                name=name,
                severity=severity,
                status="remediated",
            )
        )
    for tid in sorted(after_only):
        name, severity = after_technique_ids[tid]
        technique_deltas.append(
            TechniqueDelta(
                technique_id=tid,
                name=name,
                severity=severity,
                status="new",
            )
        )

    # Chain deltas
    before_chains = {c.id: c for c in before_result.chains}
    after_chains = {c.id: c for c in after_result.chains}

    chain_deltas: list[ChainDelta] = []

    # Remediated chains (in before but not after)
    for cid in sorted(set(before_chains.keys()) - set(after_chains.keys())):
        chain = before_chains[cid]
        chain_deltas.append(
            ChainDelta(
                chain_id=cid,
                description=chain.description,
                severity=chain.severity,
                status="remediated",
                score_before=chain.composite_score,
                score_after=None,
            )
        )

    # New chains (in after but not before)
    for cid in sorted(set(after_chains.keys()) - set(before_chains.keys())):
        chain = after_chains[cid]
        chain_deltas.append(
            ChainDelta(
                chain_id=cid,
                description=chain.description,
                severity=chain.severity,
                status="new",
                score_before=None,
                score_after=chain.composite_score,
            )
        )

    # Changed chains (in both but different composite score)
    for cid in sorted(set(before_chains.keys()) & set(after_chains.keys())):
        bc = before_chains[cid]
        ac = after_chains[cid]
        if bc.composite_score != ac.composite_score:
            chain_deltas.append(
                ChainDelta(
                    chain_id=cid,
                    description=ac.description,
                    severity=ac.severity,
                    status="changed",
                    score_before=bc.composite_score,
                    score_after=ac.composite_score,
                )
            )

    # Build summaries
    before_summary = _build_summary(before_result)
    after_summary = _build_summary(after_result)

    # Determine if security posture improved
    # Requires at least one metric to strictly improve, with no metric regressing
    if before_summary.total_chains == 0 and after_summary.total_chains == 0:
        improved = True
    else:
        no_regression = (
            after_summary.max_score <= before_summary.max_score
            and after_summary.total_chains <= before_summary.total_chains
        )
        has_actual_change = (
            after_summary.max_score < before_summary.max_score
            or after_summary.total_chains < before_summary.total_chains
        )
        improved = no_regression and has_actual_change

    return DiffResult(
        posture_deltas=posture_deltas,
        technique_deltas=technique_deltas,
        chain_deltas=chain_deltas,
        before_summary=before_summary,
        after_summary=after_summary,
        improved=improved,
    )
