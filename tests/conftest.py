"""Shared pytest fixtures for Cepheus tests."""

from __future__ import annotations

import pytest

from cepheus.models.chain import ChainStep, EscapeChain
from cepheus.models.posture import (
    CapabilityInfo,
    ContainerPosture,
    CredentialInfo,
    KernelInfo,
    KubernetesInfo,
    MountInfo,
    NamespaceInfo,
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


@pytest.fixture
def sample_posture() -> ContainerPosture:
    """Realistic container posture with various misconfigurations."""
    return ContainerPosture(
        enumeration_version="0.1.0",
        timestamp="2024-06-15T10:30:00Z",
        hostname="webapp-7f8b9c-pod",
        kernel=KernelInfo(version="5.10.0-23-generic", major=5, minor=10, patch=0),
        capabilities=CapabilityInfo(
            effective=["CAP_SYS_ADMIN", "CAP_NET_RAW", "CAP_NET_BIND_SERVICE"],
            bounding=["CAP_SYS_ADMIN", "CAP_NET_RAW", "CAP_NET_BIND_SERVICE"],
            permitted=["CAP_SYS_ADMIN", "CAP_NET_RAW", "CAP_NET_BIND_SERVICE"],
        ),
        mounts=[
            MountInfo(source="overlay", destination="/", fstype="overlay", options=["rw"]),
            MountInfo(source="proc", destination="/proc", fstype="proc", options=["rw"]),
            MountInfo(source="tmpfs", destination="/dev", fstype="tmpfs", options=["rw"]),
        ],
        namespaces=NamespaceInfo(pid=True, net=True, mnt=True, user=True, uts=True, ipc=True, cgroup=True),
        security=SecurityProfile(seccomp="disabled", apparmor=None, selinux=None),
        network=NetworkInfo(
            interfaces=["eth0", "lo"],
            can_reach_metadata=True,
            can_reach_docker_sock=False,
            listening_ports=[8080],
        ),
        credentials=CredentialInfo(
            service_account_token=False,
            environment_secrets=["DB_PASSWORD"],
            cloud_metadata_available=True,
        ),
        runtime=RuntimeInfo(runtime="docker", privileged=False, pid_one="node"),
        cgroup_version=1,
        writable_paths=["/proc/sys/kernel/core_pattern"],
        available_tools=["curl", "wget", "sh"],
    )


@pytest.fixture
def privileged_posture() -> ContainerPosture:
    """Fully privileged container — maximum attack surface."""
    return ContainerPosture(
        enumeration_version="0.1.0",
        timestamp="2024-06-15T10:30:00Z",
        hostname="debug-pod",
        kernel=KernelInfo(version="5.10.0-generic", major=5, minor=10, patch=0),
        capabilities=CapabilityInfo(
            effective=[
                "CAP_SYS_ADMIN", "CAP_NET_RAW", "CAP_SYS_PTRACE",
                "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_NET_ADMIN",
                "CAP_SYS_RAWIO", "CAP_SYS_MODULE",
            ],
        ),
        mounts=[
            MountInfo(source="overlay", destination="/", fstype="overlay", options=["rw"]),
            MountInfo(source="/dev/sda1", destination="/host", fstype="ext4", options=["rw"]),
        ],
        namespaces=NamespaceInfo(pid=False, net=False, mnt=True, user=True, uts=True, ipc=True, cgroup=True),
        security=SecurityProfile(seccomp="disabled", apparmor=None),
        network=NetworkInfo(
            interfaces=["eth0", "lo"],
            can_reach_metadata=True,
            can_reach_docker_sock=True,
            can_reach_containerd_sock=True,
            can_reach_crio_sock=False,
            listening_ports=[8080, 2375],
        ),
        credentials=CredentialInfo(
            service_account_token=True,
            environment_secrets=["AWS_SECRET_KEY", "DB_PASSWORD", "API_TOKEN"],
            cloud_metadata_available=True,
        ),
        runtime=RuntimeInfo(
            runtime="docker",
            privileged=True,
            pid_one="bash",
            orchestrator="kubernetes",
            runc_version="1.1.10",
        ),
        kubernetes=KubernetesInfo(
            namespace="default",
            pod_name="debug-pod",
            pod_security_standard="privileged",
        ),
        cgroup_version=1,
        writable_paths=[
            "/proc/sysrq-trigger",
            "/proc/sys/kernel/core_pattern",
            "/sys/fs/cgroup",
            "/sys",
            "/dev",
            "/dev/shm",
            "/proc/sys/vm",
        ],
        available_tools=["curl", "wget", "mount", "nsenter", "python3"],
    )


@pytest.fixture
def hardened_posture() -> ContainerPosture:
    """Well-configured container — minimal attack surface."""
    return ContainerPosture(
        enumeration_version="0.1.0",
        timestamp="2024-06-15T10:30:00Z",
        hostname="secure-app",
        kernel=KernelInfo(version="6.8.1-generic", major=6, minor=8, patch=1),
        capabilities=CapabilityInfo(effective=[], bounding=[], permitted=[]),
        mounts=[
            MountInfo(source="overlay", destination="/", fstype="overlay", options=["ro"]),
        ],
        namespaces=NamespaceInfo(pid=True, net=True, mnt=True, user=True, uts=True, ipc=True, cgroup=True),
        security=SecurityProfile(seccomp="filtering", apparmor="docker-default"),
        network=NetworkInfo(
            interfaces=["eth0"],
            can_reach_metadata=False,
            can_reach_docker_sock=False,
        ),
        credentials=CredentialInfo(service_account_token=False),
        runtime=RuntimeInfo(runtime="containerd", privileged=False, pid_one="app"),
        cgroup_version=2,
        writable_paths=[],
        available_tools=["sh"],
    )


@pytest.fixture
def sample_technique() -> EscapeTechnique:
    """A single EscapeTechnique for unit tests."""
    return EscapeTechnique(
        id="test_cap_sys_admin",
        name="Test CAP_SYS_ADMIN Escape",
        category=TechniqueCategory.CAPABILITY,
        severity=Severity.CRITICAL,
        description="Mount host filesystem via CAP_SYS_ADMIN",
        prerequisites=[
            Prerequisite(
                check_field="capabilities.effective",
                check_type="contains",
                check_value="CAP_SYS_ADMIN",
                description="Requires CAP_SYS_ADMIN",
            ),
            Prerequisite(
                check_field="security.seccomp",
                check_type="not_equals",
                check_value="strict",
                description="Seccomp must not be strict",
            ),
        ],
        mitre_attack=["T1611"],
        reliability=0.9,
        stealth=0.3,
        remediation="--cap-drop=ALL",
    )


@pytest.fixture
def sample_chain(sample_technique) -> EscapeChain:
    """A single EscapeChain for unit tests."""
    return EscapeChain(
        id="test_chain_001",
        steps=[
            ChainStep(
                technique=sample_technique,
                poc_command="mkdir /mnt/host && mount /dev/sda1 /mnt/host",
                prerequisite_confidence=1.0,
            ),
        ],
        composite_score=0.85,
        reliability_score=0.9,
        stealth_score=0.3,
        confidence_score=1.0,
        severity=Severity.CRITICAL,
        description="CAP_SYS_ADMIN mount escape",
    )


@pytest.fixture
def sample_analysis_result(sample_posture, sample_chain, sample_technique):
    """A basic AnalysisResult for unit tests."""
    from cepheus.models.result import AnalysisResult, RemediationItem

    return AnalysisResult(
        posture=sample_posture,
        chains=[sample_chain],
        total_techniques_checked=56,
        techniques_matched=1,
        remediations=[
            RemediationItem(
                technique_id=sample_technique.id,
                severity=sample_technique.severity,
                current_state=sample_technique.description,
                recommended_fix=sample_technique.remediation,
                runtime_flag="--cap-drop=ALL",
            ),
        ],
        analysis_timestamp="2024-06-15T10:30:00Z",
    )
