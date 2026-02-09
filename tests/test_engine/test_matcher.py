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
    NetworkInfo,
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
