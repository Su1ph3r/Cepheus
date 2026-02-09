"""Tests for EscapeTechnique and related models."""

from cepheus.models.technique import (
    SEVERITY_ORDER,
    EscapeTechnique,
    Prerequisite,
    Severity,
    TechniqueCategory,
)


def test_technique_category_values():
    assert TechniqueCategory.CAPABILITY == "capability"
    assert TechniqueCategory.KERNEL == "kernel"
    assert TechniqueCategory.COMBINATORIAL == "combinatorial"


def test_severity_values():
    assert Severity.CRITICAL == "critical"
    assert Severity.LOW == "low"


def test_severity_ordering():
    assert SEVERITY_ORDER[Severity.CRITICAL] > SEVERITY_ORDER[Severity.HIGH]
    assert SEVERITY_ORDER[Severity.HIGH] > SEVERITY_ORDER[Severity.MEDIUM]
    assert SEVERITY_ORDER[Severity.MEDIUM] > SEVERITY_ORDER[Severity.LOW]


def test_prerequisite_defaults():
    p = Prerequisite(
        check_field="capabilities.effective",
        check_type="contains",
        check_value="CAP_SYS_ADMIN",
    )
    assert p.confidence_if_met == 1.0
    assert p.confidence_if_absent == 0.3
    assert p.description == ""


def test_prerequisite_custom_confidence():
    p = Prerequisite(
        check_field="runtime.privileged",
        check_type="equals",
        check_value=True,
        confidence_if_met=0.95,
        confidence_if_absent=0.1,
        description="Container must be privileged",
    )
    assert p.confidence_if_met == 0.95
    assert p.confidence_if_absent == 0.1


def test_escape_technique_minimal():
    t = EscapeTechnique(
        id="test_technique",
        name="Test Technique",
        category=TechniqueCategory.CAPABILITY,
        severity=Severity.HIGH,
        description="A test technique",
    )
    assert t.id == "test_technique"
    assert t.prerequisites == []
    assert t.cve is None
    assert t.reliability == 0.5


def test_escape_technique_full():
    t = EscapeTechnique(
        id="cap_sys_admin_mount",
        name="CAP_SYS_ADMIN Mount Escape",
        category=TechniqueCategory.CAPABILITY,
        severity=Severity.CRITICAL,
        description="Mount host filesystem via CAP_SYS_ADMIN",
        prerequisites=[
            Prerequisite(
                check_field="capabilities.effective",
                check_type="contains",
                check_value="CAP_SYS_ADMIN",
                description="Requires CAP_SYS_ADMIN capability",
            ),
        ],
        mitre_attack=["T1611"],
        references=["https://example.com"],
        reliability=0.9,
        stealth=0.3,
        remediation="Drop CAP_SYS_ADMIN: --cap-drop=ALL",
    )
    assert len(t.prerequisites) == 1
    assert t.prerequisites[0].check_field == "capabilities.effective"
    assert t.mitre_attack == ["T1611"]
    assert t.reliability == 0.9


def test_escape_technique_json_roundtrip():
    t = EscapeTechnique(
        id="roundtrip",
        name="Roundtrip Test",
        category=TechniqueCategory.MOUNT,
        severity=Severity.MEDIUM,
        description="Test roundtrip",
        prerequisites=[
            Prerequisite(
                check_field="mounts",
                check_type="not_empty",
                description="Needs mounts",
            ),
        ],
    )
    json_str = t.model_dump_json()
    t2 = EscapeTechnique.model_validate_json(json_str)
    assert t2.id == "roundtrip"
    assert len(t2.prerequisites) == 1
