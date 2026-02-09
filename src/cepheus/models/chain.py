"""Escape chain model — ordered sequence of technique steps."""

from __future__ import annotations

from pydantic import BaseModel, Field

from cepheus.models.technique import EscapeTechnique, Severity


class ChainStep(BaseModel):
    technique: EscapeTechnique
    poc_command: str = ""
    prerequisite_confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class EscapeChain(BaseModel):
    id: str
    steps: list[ChainStep] = Field(default_factory=list)
    composite_score: float = Field(default=0.0, ge=0.0, le=1.0)
    reliability_score: float = Field(default=0.0, ge=0.0, le=1.0)
    stealth_score: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: Severity = Severity.LOW
    description: str = ""
