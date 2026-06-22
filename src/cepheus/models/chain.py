"""Escape chain model — ordered sequence of technique steps."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cepheus.models.technique import ConfirmationStatus, EscapeTechnique, Severity


class ChainStep(BaseModel):
    # Frozen: a chain step is constructed once by the chainer and never
    # mutated. Immutability is part of the 1.0 API contract (see
    # docs/API.md). EscapeChain itself stays mutable — the scorer sets
    # composite_score on it after construction.
    model_config = ConfigDict(frozen=True)

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
    confirmation: ConfirmationStatus | None = Field(
        default=None,
        description=(
            "Live-verification verdict for this chain. None until "
            "`apply_confirmation` runs (pure static analysis). Once set, "
            "renderers and the confirmed-only default filter key off it. "
            "A chain's status aggregates its steps: any REFUTED step refutes "
            "the chain (a required step doesn't work); otherwise the chain is "
            "CONFIRMED only when every verifiable step confirmed."
        ),
    )
