"""Analysis result model — final output of the engine."""

from __future__ import annotations

from pydantic import BaseModel, Field

from cepheus.models.chain import EscapeChain
from cepheus.models.posture import ContainerPosture
from cepheus.models.technique import Severity


class RemediationItem(BaseModel):
    technique_id: str
    severity: Severity
    current_state: str
    recommended_fix: str
    runtime_flag: str | None = None


class AnalysisResult(BaseModel):
    posture: ContainerPosture
    chains: list[EscapeChain] = Field(default_factory=list)
    total_techniques_checked: int = 0
    techniques_matched: int = 0
    remediations: list[RemediationItem] = Field(default_factory=list)
    llm_analysis: str | None = None
    analysis_timestamp: str = ""
