"""Tests for the escape chain scorer."""

from cepheus.config import CepheusConfig
from cepheus.engine.scorer import rank_chains, score_chain
from cepheus.models.chain import ChainStep, EscapeChain
from cepheus.models.technique import EscapeTechnique, Severity, TechniqueCategory


def _tech(id: str = "t") -> EscapeTechnique:
    return EscapeTechnique(
        id=id, name="Test", category=TechniqueCategory.CAPABILITY,
        severity=Severity.HIGH, description="test",
    )


def _chain(reliability: float = 0.8, stealth: float = 0.5, confidence: float = 1.0, steps: int = 1) -> EscapeChain:
    return EscapeChain(
        id="test",
        steps=[ChainStep(technique=_tech(f"t{i}"), poc_command="cmd") for i in range(steps)],
        reliability_score=reliability,
        stealth_score=stealth,
        confidence_score=confidence,
        severity=Severity.HIGH,
        description="test chain",
    )


def test_score_single_step_chain():
    chain = _chain(reliability=0.9, stealth=0.7, confidence=1.0)
    config = CepheusConfig()
    scored = score_chain(chain, config)
    # composite = (0.9 * 0.4 + 0.7 * 0.25 + 1.0 * 0.35) * 1.0  (length_penalty = 1 for single step)
    # = (0.36 + 0.175 + 0.35) * 1.0 = 0.885
    assert abs(scored.composite_score - 0.885) < 0.001


def test_score_two_step_chain():
    chain = _chain(reliability=0.9, stealth=0.7, confidence=1.0, steps=2)
    config = CepheusConfig()
    scored = score_chain(chain, config)
    # length_penalty = 1.0 / (1.0 + 0.15 * 1) = 1/1.15 ≈ 0.8696
    # composite = 0.885 * 0.8696 ≈ 0.7696
    assert scored.composite_score < 0.885  # Penalized vs single step
    assert abs(scored.composite_score - 0.885 * (1.0 / 1.15)) < 0.001


def test_score_three_step_chain():
    chain = _chain(reliability=0.9, stealth=0.7, confidence=1.0, steps=3)
    config = CepheusConfig()
    scored = score_chain(chain, config)
    # length_penalty = 1.0 / (1.0 + 0.15 * 2) = 1/1.30 ≈ 0.769
    two_step = _chain(reliability=0.9, stealth=0.7, confidence=1.0, steps=2)
    score_chain(two_step, config)
    assert scored.composite_score < two_step.composite_score  # More steps = more penalty


def test_rank_chains():
    c1 = _chain(reliability=0.5, stealth=0.3, confidence=0.5)
    c1.id = "low"
    c2 = _chain(reliability=0.9, stealth=0.8, confidence=1.0)
    c2.id = "high"
    c3 = _chain(reliability=0.7, stealth=0.5, confidence=0.7)
    c3.id = "mid"

    ranked = rank_chains([c1, c2, c3])
    assert ranked[0].id == "high"
    assert ranked[-1].id == "low"


def test_score_with_custom_weights():
    chain = _chain(reliability=1.0, stealth=0.0, confidence=0.0)
    config = CepheusConfig(weight_reliability=1.0, weight_stealth=0.0, weight_confidence=0.0)
    scored = score_chain(chain, config)
    assert scored.composite_score == 1.0


def test_score_zero_scores():
    chain = _chain(reliability=0.0, stealth=0.0, confidence=0.0)
    scored = score_chain(chain)
    assert scored.composite_score == 0.0
