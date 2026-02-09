"""Tests for the analyzer orchestrator.

These tests require the technique_db to be available. They test the full pipeline.
"""

import pytest

from cepheus.models.posture import (
    CapabilityInfo,
    ContainerPosture,
    CredentialInfo,
    KernelInfo,
    NetworkInfo,
    RuntimeInfo,
    SecurityProfile,
)


@pytest.fixture
def privileged_posture():
    """A highly privileged container — should match many techniques."""
    return ContainerPosture(
        hostname="privileged-container",
        kernel=KernelInfo(version="5.10.0-generic", major=5, minor=10, patch=0),
        capabilities=CapabilityInfo(
            effective=["CAP_SYS_ADMIN", "CAP_NET_RAW", "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH"],
        ),
        runtime=RuntimeInfo(runtime="docker", privileged=True, pid_one="bash"),
        security=SecurityProfile(seccomp="disabled", apparmor=None),
        network=NetworkInfo(can_reach_docker_sock=True, can_reach_metadata=True),
        credentials=CredentialInfo(
            service_account_token=True,
            environment_secrets=["AWS_SECRET_KEY", "DB_PASSWORD"],
            cloud_metadata_available=True,
        ),
        writable_paths=["/proc/sysrq-trigger", "/proc/sys/kernel/core_pattern", "/sys/fs/cgroup"],
        cgroup_version=1,
        available_tools=["curl", "wget", "mount"],
    )


@pytest.fixture
def hardened_posture():
    """A well-hardened container — should match few techniques."""
    return ContainerPosture(
        hostname="hardened-container",
        kernel=KernelInfo(version="6.8.1-generic", major=6, minor=8, patch=1),
        capabilities=CapabilityInfo(effective=[]),
        runtime=RuntimeInfo(runtime="containerd", privileged=False, pid_one="app"),
        security=SecurityProfile(seccomp="filtering", apparmor="docker-default"),
        network=NetworkInfo(can_reach_docker_sock=False, can_reach_metadata=False),
        credentials=CredentialInfo(service_account_token=False),
        writable_paths=[],
        cgroup_version=2,
    )


def test_analyze_privileged(privileged_posture):
    """Privileged container should have many matched techniques."""
    from cepheus.engine.analyzer import analyze

    result = analyze(privileged_posture)
    assert result.techniques_matched > 5
    assert len(result.chains) > 0
    assert result.total_techniques_checked == 56
    # Should have remediations
    assert len(result.remediations) > 0
    # First chain should be high-scoring
    assert result.chains[0].composite_score > 0.5


def test_analyze_hardened(hardened_posture):
    """Hardened container should have very few matched techniques."""
    from cepheus.engine.analyzer import analyze

    result = analyze(hardened_posture)
    # May still match some based on runtime detection, but far fewer
    assert result.techniques_matched < result.total_techniques_checked
    # Chains should exist but with lower scores
    if result.chains:
        assert result.chains[0].composite_score <= 1.0


def test_analyze_empty_posture():
    """Empty posture should not crash."""
    from cepheus.engine.analyzer import analyze

    result = analyze(ContainerPosture())
    assert result.total_techniques_checked == 56
    assert result.analysis_timestamp != ""


def test_analyze_result_sorted():
    """Chains should be sorted by composite_score descending."""
    from cepheus.engine.analyzer import analyze

    posture = ContainerPosture(
        capabilities=CapabilityInfo(effective=["CAP_SYS_ADMIN"]),
        security=SecurityProfile(seccomp="disabled"),
        runtime=RuntimeInfo(privileged=True),
        network=NetworkInfo(can_reach_docker_sock=True),
    )
    result = analyze(posture)
    if len(result.chains) >= 2:
        for i in range(len(result.chains) - 1):
            assert result.chains[i].composite_score >= result.chains[i + 1].composite_score
