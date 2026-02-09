"""Tests for the chain builder."""

from cepheus.engine.chainer import build_combinatorial_chains, build_single_chains
from cepheus.models.posture import ContainerPosture
from cepheus.models.technique import EscapeTechnique, Severity, TechniqueCategory


def _tech(id: str, category: TechniqueCategory = TechniqueCategory.CAPABILITY, severity: Severity = Severity.HIGH) -> EscapeTechnique:
    return EscapeTechnique(
        id=id,
        name=f"Test {id}",
        category=category,
        severity=severity,
        description=f"Test technique {id}",
        reliability=0.8,
        stealth=0.5,
    )


def test_build_single_chains():
    techs = [
        (_tech("t1"), 0.9, "cmd1"),
        (_tech("t2"), 0.8, "cmd2"),
    ]
    chains = build_single_chains(techs)
    assert len(chains) == 2
    assert chains[0].steps[0].technique.id == "t1"
    assert chains[0].confidence_score == 0.9
    assert chains[1].steps[0].technique.id == "t2"


def test_single_chain_severity():
    techs = [(_tech("crit", severity=Severity.CRITICAL), 1.0, "cmd")]
    chains = build_single_chains(techs)
    assert chains[0].severity == Severity.CRITICAL


def test_build_combinatorial_combo_technique():
    combo = _tech("combo1", TechniqueCategory.COMBINATORIAL, Severity.CRITICAL)
    techs = [(combo, 0.95, "combo_cmd")]
    posture = ContainerPosture()
    chains = build_combinatorial_chains(techs, posture)
    assert len(chains) == 1
    assert chains[0].description.startswith("[Combo]")


def test_build_combinatorial_info_escalation_pair():
    info = _tech("cloud_metadata_creds", TechniqueCategory.INFO_DISCLOSURE, Severity.HIGH)
    esc = _tech("k8s_service_account", TechniqueCategory.RUNTIME, Severity.HIGH)
    techs = [
        (info, 0.9, "info_cmd"),
        (esc, 0.8, "esc_cmd"),
    ]
    posture = ContainerPosture()
    chains = build_combinatorial_chains(techs, posture)
    # Should find at least one chain pairing info → esc
    multi_step = [c for c in chains if len(c.steps) == 2]
    assert len(multi_step) == 1
    assert multi_step[0].steps[0].technique.id == "cloud_metadata_creds"
    assert multi_step[0].steps[1].technique.id == "k8s_service_account"


def test_build_combinatorial_no_useful_pair():
    info = _tech("env_secret_leak", TechniqueCategory.INFO_DISCLOSURE, Severity.MEDIUM)
    esc = _tech("cap_sys_admin_mount", TechniqueCategory.CAPABILITY, Severity.CRITICAL)
    techs = [
        (info, 0.9, "info_cmd"),
        (esc, 0.8, "esc_cmd"),
    ]
    posture = ContainerPosture()
    chains = build_combinatorial_chains(techs, posture)
    # No useful pairing between env_secret_leak and cap_sys_admin_mount
    multi_step = [c for c in chains if len(c.steps) == 2]
    assert len(multi_step) == 0
