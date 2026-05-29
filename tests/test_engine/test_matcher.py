"""Tests for the prerequisite evaluation engine."""

from cepheus.engine.matcher import (
    _MISSING,
    _parse_kernel_version,
    evaluate_prerequisite,
    match_technique,
    resolve_dot_path,
)
from cepheus.models.posture import (
    CapabilityInfo,
    ContainerPosture,
    KernelInfo,
    RuntimeInfo,
    SecurityProfile,
)
from cepheus.models.technique import (
    EscapeTechnique,
    Prerequisite,
    Severity,
    TechniqueCategory,
)


# --- resolve_dot_path tests ---


def test_resolve_simple_field():
    p = ContainerPosture(hostname="test-host")
    assert resolve_dot_path(p, "hostname") == "test-host"


def test_resolve_nested_field():
    p = ContainerPosture(kernel=KernelInfo(version="5.15.0", major=5, minor=15, patch=0))
    assert resolve_dot_path(p, "kernel.version") == "5.15.0"
    assert resolve_dot_path(p, "kernel.major") == 5


def test_resolve_deep_nested():
    p = ContainerPosture(capabilities=CapabilityInfo(effective=["CAP_SYS_ADMIN"]))
    result = resolve_dot_path(p, "capabilities.effective")
    assert "CAP_SYS_ADMIN" in result


def test_resolve_missing_field():
    p = ContainerPosture()
    result = resolve_dot_path(p, "nonexistent.field")
    assert isinstance(result, type(_MISSING))


def test_resolve_dict_path():
    d = {"a": {"b": {"c": 42}}}
    assert resolve_dot_path(d, "a.b.c") == 42


# --- kernel version parsing ---


def test_parse_kernel_version():
    assert _parse_kernel_version("5.15.0-76-generic") == (5, 15, 0)
    assert _parse_kernel_version("6.2.13") == (6, 2, 13)
    assert _parse_kernel_version("invalid") == (0, 0, 0)


def test_parse_kernel_version_two_part():
    """Two-part kernel versions like '6.1' should parse as (6, 1, 0)."""
    assert _parse_kernel_version("6.1") == (6, 1, 0)
    assert _parse_kernel_version("5.15") == (5, 15, 0)
    assert _parse_kernel_version("6.1-rc1") == (6, 1, 0)


# --- evaluate_prerequisite tests ---


def test_contains_list_pass():
    p = ContainerPosture(capabilities=CapabilityInfo(effective=["CAP_SYS_ADMIN", "CAP_NET_RAW"]))
    prereq = Prerequisite(
        check_field="capabilities.effective",
        check_type="contains",
        check_value="CAP_SYS_ADMIN",
    )
    assert evaluate_prerequisite(p, prereq) == 1.0


def test_contains_list_fail():
    p = ContainerPosture(capabilities=CapabilityInfo(effective=["CAP_NET_RAW"]))
    prereq = Prerequisite(
        check_field="capabilities.effective",
        check_type="contains",
        check_value="CAP_SYS_ADMIN",
    )
    assert evaluate_prerequisite(p, prereq) == 0.0


def test_equals_pass():
    p = ContainerPosture(runtime=RuntimeInfo(privileged=True))
    prereq = Prerequisite(
        check_field="runtime.privileged",
        check_type="equals",
        check_value=True,
    )
    assert evaluate_prerequisite(p, prereq) == 1.0


def test_equals_fail():
    p = ContainerPosture(runtime=RuntimeInfo(privileged=False))
    prereq = Prerequisite(
        check_field="runtime.privileged",
        check_type="equals",
        check_value=True,
    )
    assert evaluate_prerequisite(p, prereq) == 0.0


def test_not_equals_pass():
    p = ContainerPosture(security=SecurityProfile(seccomp="disabled"))
    prereq = Prerequisite(
        check_field="security.seccomp",
        check_type="not_equals",
        check_value="strict",
    )
    assert evaluate_prerequisite(p, prereq) == 1.0


def test_not_equals_fail():
    p = ContainerPosture(security=SecurityProfile(seccomp="strict"))
    prereq = Prerequisite(
        check_field="security.seccomp",
        check_type="not_equals",
        check_value="strict",
    )
    assert evaluate_prerequisite(p, prereq) == 0.0


def test_gte_pass():
    p = ContainerPosture(cgroup_version=2)
    prereq = Prerequisite(check_field="cgroup_version", check_type="gte", check_value=2)
    assert evaluate_prerequisite(p, prereq) == 1.0


def test_gte_fail():
    p = ContainerPosture(cgroup_version=1)
    prereq = Prerequisite(check_field="cgroup_version", check_type="gte", check_value=2)
    assert evaluate_prerequisite(p, prereq) == 0.0


def test_lte_pass():
    p = ContainerPosture(cgroup_version=1)
    prereq = Prerequisite(check_field="cgroup_version", check_type="lte", check_value=1)
    assert evaluate_prerequisite(p, prereq) == 1.0


def test_kernel_gte_pass():
    p = ContainerPosture(kernel=KernelInfo(version="5.15.0", major=5, minor=15, patch=0))
    prereq = Prerequisite(check_field="kernel.version", check_type="kernel_gte", check_value="4.18.0")
    assert evaluate_prerequisite(p, prereq) == 1.0


def test_kernel_gte_fail():
    p = ContainerPosture(kernel=KernelInfo(version="4.15.0", major=4, minor=15, patch=0))
    prereq = Prerequisite(check_field="kernel.version", check_type="kernel_gte", check_value="5.0.0")
    assert evaluate_prerequisite(p, prereq) == 0.0


def test_kernel_lte_pass():
    p = ContainerPosture(kernel=KernelInfo(version="5.10.0", major=5, minor=10, patch=0))
    prereq = Prerequisite(check_field="kernel.version", check_type="kernel_lte", check_value="5.16.0")
    assert evaluate_prerequisite(p, prereq) == 1.0


def test_kernel_between_pass():
    p = ContainerPosture(kernel=KernelInfo(version="5.10.0", major=5, minor=10, patch=0))
    prereq = Prerequisite(
        check_field="kernel.version",
        check_type="kernel_between",
        check_value=["5.8.0", "5.16.0"],
    )
    assert evaluate_prerequisite(p, prereq) == 1.0


def test_kernel_between_fail():
    p = ContainerPosture(kernel=KernelInfo(version="6.0.0", major=6, minor=0, patch=0))
    prereq = Prerequisite(
        check_field="kernel.version",
        check_type="kernel_between",
        check_value=["5.8.0", "5.16.0"],
    )
    assert evaluate_prerequisite(p, prereq) == 0.0


def test_exists_pass():
    p = ContainerPosture(runtime=RuntimeInfo(runtime_version="20.10"))
    prereq = Prerequisite(check_field="runtime.runtime_version", check_type="exists")
    assert evaluate_prerequisite(p, prereq) == 1.0


def test_exists_fail():
    p = ContainerPosture(runtime=RuntimeInfo(runtime_version=None))
    prereq = Prerequisite(check_field="runtime.runtime_version", check_type="exists")
    assert evaluate_prerequisite(p, prereq) == 0.0


def test_not_empty_pass():
    p = ContainerPosture(writable_paths=["/proc/sysrq-trigger"])
    prereq = Prerequisite(check_field="writable_paths", check_type="not_empty")
    assert evaluate_prerequisite(p, prereq) == 1.0


def test_not_empty_fail():
    p = ContainerPosture(writable_paths=[])
    prereq = Prerequisite(check_field="writable_paths", check_type="not_empty")
    assert evaluate_prerequisite(p, prereq) == 0.0


def test_regex_pass():
    p = ContainerPosture(runtime=RuntimeInfo(runtime="docker"))
    prereq = Prerequisite(
        check_field="runtime.runtime",
        check_type="regex",
        check_value="^(docker|containerd)$",
    )
    assert evaluate_prerequisite(p, prereq) == 1.0


def test_regex_fail():
    p = ContainerPosture(runtime=RuntimeInfo(runtime="podman"))
    prereq = Prerequisite(
        check_field="runtime.runtime",
        check_type="regex",
        check_value="^(docker|containerd)$",
    )
    assert evaluate_prerequisite(p, prereq) == 0.0


def test_missing_field_returns_confidence_if_absent():
    p = ContainerPosture()
    prereq = Prerequisite(
        check_field="nonexistent.field",
        check_type="contains",
        check_value="something",
        confidence_if_absent=0.4,
    )
    assert evaluate_prerequisite(p, prereq) == 0.4


# --- match_technique tests ---


def test_match_technique_all_pass():
    p = ContainerPosture(
        capabilities=CapabilityInfo(effective=["CAP_SYS_ADMIN"]),
        security=SecurityProfile(seccomp="disabled"),
    )
    t = EscapeTechnique(
        id="test",
        name="Test",
        category=TechniqueCategory.CAPABILITY,
        severity=Severity.CRITICAL,
        description="test",
        prerequisites=[
            Prerequisite(check_field="capabilities.effective", check_type="contains", check_value="CAP_SYS_ADMIN"),
            Prerequisite(check_field="security.seccomp", check_type="not_equals", check_value="strict"),
        ],
    )
    matched, confidence = match_technique(p, t)
    assert matched is True
    assert confidence == 1.0


def test_match_technique_one_fails():
    p = ContainerPosture(
        capabilities=CapabilityInfo(effective=[]),
        security=SecurityProfile(seccomp="disabled"),
    )
    t = EscapeTechnique(
        id="test",
        name="Test",
        category=TechniqueCategory.CAPABILITY,
        severity=Severity.CRITICAL,
        description="test",
        prerequisites=[
            Prerequisite(check_field="capabilities.effective", check_type="contains", check_value="CAP_SYS_ADMIN"),
            Prerequisite(check_field="security.seccomp", check_type="not_equals", check_value="strict"),
        ],
    )
    matched, confidence = match_technique(p, t)
    assert matched is False
    assert confidence == 0.0


def test_version_lte_pass():
    p = ContainerPosture(runtime=RuntimeInfo(runc_version="1.1.10"))
    prereq = Prerequisite(check_field="runtime.runc_version", check_type="version_lte", check_value="1.1.12")
    assert evaluate_prerequisite(p, prereq) == 1.0


def test_version_lte_fail():
    p = ContainerPosture(runtime=RuntimeInfo(runc_version="1.2.0"))
    prereq = Prerequisite(check_field="runtime.runc_version", check_type="version_lte", check_value="1.1.12")
    assert evaluate_prerequisite(p, prereq) == 0.0


def test_version_lte_missing():
    p = ContainerPosture(runtime=RuntimeInfo(runc_version=None))
    prereq = Prerequisite(check_field="runtime.runc_version", check_type="version_lte", check_value="1.1.12")
    assert evaluate_prerequisite(p, prereq) == 0.3


def test_any_of_check_passes():
    """any_of returns confidence_if_met when list contains at least one match."""
    posture = ContainerPosture(capabilities=CapabilityInfo(effective=["CAP_SYS_ADMIN", "CAP_NET_RAW"]))
    prereq = Prerequisite(
        check_field="capabilities.effective",
        check_type="any_of",
        check_value=["CAP_SYS_ADMIN", "CAP_BPF"],
        confidence_if_met=1.0,
        confidence_if_absent=0.0,
    )
    assert evaluate_prerequisite(posture, prereq) == 1.0


def test_any_of_check_fails():
    """any_of returns 0.0 when list contains none of the values."""
    posture = ContainerPosture(capabilities=CapabilityInfo(effective=["CAP_NET_RAW"]))
    prereq = Prerequisite(
        check_field="capabilities.effective",
        check_type="any_of",
        check_value=["CAP_SYS_ADMIN", "CAP_BPF"],
        confidence_if_met=1.0,
        confidence_if_absent=0.0,
    )
    assert evaluate_prerequisite(posture, prereq) == 0.0


def test_any_of_non_list_field():
    """any_of returns 0.0 when field is not a list."""
    posture = ContainerPosture(hostname="test")
    prereq = Prerequisite(
        check_field="hostname",
        check_type="any_of",
        check_value=["test", "other"],
        confidence_if_met=1.0,
        confidence_if_absent=0.0,
    )
    assert evaluate_prerequisite(posture, prereq) == 0.0


def test_any_of_string_check_value():
    """any_of with non-list check_value returns 0.0 instead of iterating characters."""
    posture = ContainerPosture(capabilities=CapabilityInfo(effective=["CAP_SYS_ADMIN"]))
    prereq = Prerequisite(
        check_field="capabilities.effective",
        check_type="any_of",
        check_value="CAP_SYS_ADMIN",  # string, not list — should not iterate chars
        confidence_if_met=1.0,
        confidence_if_absent=0.0,
    )
    assert evaluate_prerequisite(posture, prereq) == 0.0


def test_match_technique_no_prerequisites():
    p = ContainerPosture()
    t = EscapeTechnique(
        id="test",
        name="Test",
        category=TechniqueCategory.INFO_DISCLOSURE,
        severity=Severity.LOW,
        description="test",
        prerequisites=[],
    )
    matched, confidence = match_technique(p, t)
    assert matched is True
    assert confidence == 1.0


# --- regression guards: malformed-input edges (bug-hunt --full) ---


def test_kernel_lte_unknown_kernel_does_not_false_positive():
    """A malformed/unknown kernel parses to (0,0,0); kernel_lte must NOT
    treat that as <= every target (which would false-positive every
    'kernel <= X' CVE gate)."""
    posture = ContainerPosture(kernel=KernelInfo(version="garbage", major=0, minor=0, patch=0))
    prereq = Prerequisite(
        check_field="kernel.version",
        check_type="kernel_lte",
        check_value="5.0.0",
        confidence_if_met=0.9,
        confidence_if_absent=0.2,
    )
    # Unknown kernel → confidence_if_absent, not a spurious confidence_if_met.
    assert evaluate_prerequisite(posture, prereq) == 0.2


def test_gte_rejects_bool_value():
    """float(True) == 1.0 must not silently satisfy a numeric gte gate."""
    posture = ContainerPosture()
    prereq = Prerequisite(
        check_field="runtime.privileged",  # a bool field
        check_type="gte",
        check_value=1,
        confidence_if_met=0.9,
        confidence_if_absent=0.1,
    )
    posture.runtime.privileged = True
    assert evaluate_prerequisite(posture, prereq) == 0.1


def _runc_cve_technique() -> EscapeTechnique:
    """A technique whose SOLE prereq is a version_lte on runc_version —
    the shape of CVE-2025-31133/52565/52881."""
    return EscapeTechnique(
        id="t_runc_cve",
        name="runc version CVE",
        category=TechniqueCategory.KERNEL,
        severity=Severity.HIGH,
        description="runc <= 1.2.7",
        prerequisites=[
            Prerequisite(
                check_field="runtime.runc_version",
                check_type="version_lte",
                check_value="1.2.7",
                confidence_if_absent=0.2,
            )
        ],
    )


def test_version_lte_known_vulnerable_runc_matches_on_distro_kernel():
    """A KNOWN vulnerable runc version must match even on a distro/vendor
    kernel — version_lte is a component-version check, not a kernel-range
    check, so the distro-kernel backport downgrade must NOT suppress it."""
    posture = ContainerPosture(
        kernel=KernelInfo(version="6.6.114.1-microsoft-standard-WSL2", major=6, minor=6, patch=114),
        runtime=RuntimeInfo(runc_version="1.2.7"),
    )
    posture.kernel.is_distro_kernel = True
    matched, conf = match_technique(posture, _runc_cve_technique(), min_confidence=0.3)
    assert matched is True
    assert conf >= 0.3


def test_version_lte_unknown_runc_does_not_false_positive_on_distro_kernel():
    """Unknown runc version on a distro kernel must NOT match — no false
    positive (confidence_if_absent stays below the 0.3 threshold)."""
    posture = ContainerPosture(
        kernel=KernelInfo(version="6.6.114.1-microsoft-standard-WSL2", major=6, minor=6, patch=114),
        runtime=RuntimeInfo(runc_version=None),
    )
    posture.kernel.is_distro_kernel = True
    matched, _ = match_technique(posture, _runc_cve_technique(), min_confidence=0.3)
    assert matched is False
