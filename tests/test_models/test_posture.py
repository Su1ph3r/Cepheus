"""Tests for ContainerPosture and sub-models."""

from cepheus.models.posture import (
    CapabilityInfo,
    ContainerPosture,
    CredentialInfo,
    KernelInfo,
    MountInfo,
    NamespaceInfo,
    NetworkInfo,
    RuntimeInfo,
    SecurityProfile,
)


def test_kernel_info_defaults():
    k = KernelInfo(version="5.15.0-76-generic")
    assert k.version == "5.15.0-76-generic"
    assert k.major == 0
    assert k.minor == 0
    assert k.patch == 0


def test_kernel_info_parsed():
    k = KernelInfo(version="5.15.0-76-generic", major=5, minor=15, patch=0)
    assert k.major == 5
    assert k.minor == 15


def test_capability_info_defaults():
    c = CapabilityInfo()
    assert c.effective == []
    assert c.bounding == []
    assert c.permitted == []


def test_capability_info_with_caps():
    c = CapabilityInfo(effective=["CAP_SYS_ADMIN", "CAP_NET_RAW"])
    assert "CAP_SYS_ADMIN" in c.effective
    assert len(c.effective) == 2


def test_mount_info():
    m = MountInfo(source="/dev/sda1", destination="/", fstype="ext4", options=["rw", "relatime"])
    assert m.source == "/dev/sda1"
    assert "rw" in m.options


def test_namespace_info_defaults():
    n = NamespaceInfo()
    assert n.pid is True
    assert n.user is True


def test_security_profile_defaults():
    s = SecurityProfile()
    assert s.seccomp == "disabled"
    assert s.apparmor is None
    assert s.selinux is None


def test_network_info():
    n = NetworkInfo(interfaces=["eth0", "lo"], can_reach_metadata=True)
    assert n.can_reach_metadata is True
    assert "eth0" in n.interfaces


def test_credential_info():
    c = CredentialInfo(service_account_token=True, environment_secrets=["AWS_SECRET_KEY"])
    assert c.service_account_token is True
    assert "AWS_SECRET_KEY" in c.environment_secrets


def test_runtime_info_defaults():
    r = RuntimeInfo()
    assert r.runtime == "unknown"
    assert r.privileged is False


def test_runtime_info_privileged():
    r = RuntimeInfo(runtime="docker", privileged=True, pid_one="/sbin/init")
    assert r.privileged is True
    assert r.runtime == "docker"


def test_container_posture_defaults():
    p = ContainerPosture()
    assert p.enumeration_version == "0.1.0"
    assert p.kernel.version == ""  # KernelInfo default
    assert p.capabilities.effective == []
    assert p.mounts == []
    assert p.cgroup_version == 1


def test_container_posture_full():
    p = ContainerPosture(
        hostname="test-container",
        kernel=KernelInfo(version="5.15.0", major=5, minor=15, patch=0),
        capabilities=CapabilityInfo(effective=["CAP_SYS_ADMIN"]),
        runtime=RuntimeInfo(runtime="docker", privileged=True),
        writable_paths=["/proc/sysrq-trigger"],
        available_tools=["curl", "wget"],
    )
    assert p.hostname == "test-container"
    assert "CAP_SYS_ADMIN" in p.capabilities.effective
    assert p.runtime.privileged is True


def test_container_posture_json_roundtrip():
    p = ContainerPosture(
        hostname="roundtrip-test",
        kernel=KernelInfo(version="5.10.0", major=5, minor=10, patch=0),
    )
    json_str = p.model_dump_json()
    p2 = ContainerPosture.model_validate_json(json_str)
    assert p2.hostname == "roundtrip-test"
    assert p2.kernel.major == 5


def test_container_posture_from_dict():
    data = {
        "hostname": "from-dict",
        "kernel": {"version": "5.4.0", "major": 5, "minor": 4, "patch": 0},
        "capabilities": {"effective": ["CAP_NET_RAW"]},
    }
    p = ContainerPosture.model_validate(data)
    assert p.hostname == "from-dict"
    assert "CAP_NET_RAW" in p.capabilities.effective
