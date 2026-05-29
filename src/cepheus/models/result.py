"""Analysis result model — final output of the engine."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cepheus.models.chain import EscapeChain
from cepheus.models.posture import ContainerPosture
from cepheus.models.technique import Severity


class RemediationItem(BaseModel):
    # Frozen: a remediation item is built once and never mutated.
    # Immutability is part of the 1.0 API contract (see docs/API.md).
    # AnalysisResult itself stays mutable (the CLI enriches it with LLM
    # analysis / executive summary and applies severity filtering).
    model_config = ConfigDict(frozen=True)

    technique_id: str
    severity: Severity
    current_state: str
    recommended_fix: str
    runtime_flag: str | None = None


class AnalysisResult(BaseModel):
    posture: ContainerPosture
    chains: list[EscapeChain] = Field(default_factory=list)
    total_techniques_checked: int = 0
    techniques_matched: int = Field(
        default=0,
        description=(
            "Number of techniques that matched the posture BEFORE any "
            "severity filter was applied. Stable across `--min-severity` "
            "choices — useful for trend dashboards. For the count that "
            "corresponds to the chains the user will actually see in the "
            "rendered report, use `techniques_in_visible_chains`."
        ),
    )
    techniques_in_visible_chains: int | None = Field(
        default=None,
        description=(
            "Number of unique techniques contributing to the post-filter "
            "`chains` list. None when no severity filter was applied. "
            "Renderers prefer this when present so the summary count "
            "matches the visible chain count (added in v0.3.5)."
        ),
    )
    remediations: list[RemediationItem] = Field(default_factory=list)
    llm_analysis: str | None = None
    executive_summary: str | None = None
    analysis_timestamp: str = ""
