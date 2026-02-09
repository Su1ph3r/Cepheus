"""Tests for EscapeChain and ChainStep."""

from cepheus.models.chain import ChainStep, EscapeChain
from cepheus.models.technique import EscapeTechnique, Severity, TechniqueCategory


def _make_technique(id: str = "test", severity: Severity = Severity.HIGH) -> EscapeTechnique:
    return EscapeTechnique(
        id=id,
        name=f"Test {id}",
        category=TechniqueCategory.CAPABILITY,
        severity=severity,
        description=f"Test technique {id}",
    )


def test_chain_step():
    t = _make_technique()
    step = ChainStep(
        technique=t,
        poc_command="mount -t proc proc /mnt",
        prerequisite_confidence=0.95,
    )
    assert step.technique.id == "test"
    assert step.poc_command == "mount -t proc proc /mnt"
    assert step.prerequisite_confidence == 0.95


def test_escape_chain_single_step():
    t = _make_technique(severity=Severity.CRITICAL)
    chain = EscapeChain(
        id="chain_test",
        steps=[ChainStep(technique=t, poc_command="exploit", prerequisite_confidence=1.0)],
        composite_score=0.85,
        reliability_score=0.9,
        stealth_score=0.7,
        confidence_score=1.0,
        severity=Severity.CRITICAL,
        description="Single-step critical escape",
    )
    assert len(chain.steps) == 1
    assert chain.composite_score == 0.85
    assert chain.severity == Severity.CRITICAL


def test_escape_chain_multi_step():
    t1 = _make_technique("step1", Severity.MEDIUM)
    t2 = _make_technique("step2", Severity.CRITICAL)
    chain = EscapeChain(
        id="multi_chain",
        steps=[
            ChainStep(technique=t1, poc_command="step 1 cmd", prerequisite_confidence=0.9),
            ChainStep(technique=t2, poc_command="step 2 cmd", prerequisite_confidence=0.8),
        ],
        composite_score=0.72,
        severity=Severity.CRITICAL,
        description="Two-step chain",
    )
    assert len(chain.steps) == 2
    assert chain.steps[0].technique.id == "step1"
    assert chain.steps[1].technique.id == "step2"


def test_escape_chain_json_roundtrip():
    t = _make_technique()
    chain = EscapeChain(
        id="roundtrip",
        steps=[ChainStep(technique=t, poc_command="cmd")],
        composite_score=0.5,
        severity=Severity.HIGH,
        description="Roundtrip test",
    )
    json_str = chain.model_dump_json()
    chain2 = EscapeChain.model_validate_json(json_str)
    assert chain2.id == "roundtrip"
    assert chain2.steps[0].technique.id == "test"
