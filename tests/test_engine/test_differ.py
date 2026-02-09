"""Tests for the posture diff engine."""

import pytest

from cepheus.models.posture import (
    CapabilityInfo,
    ContainerPosture,
    KernelInfo,
    NetworkInfo,
    RuntimeInfo,
    SecurityProfile,
)


def test_diff_identical_postures():
    """Diffing identical postures should show no changes and not claim improvement."""
    from cepheus.engine.differ import diff_postures

    posture = ContainerPosture(hostname="test")
    result = diff_postures(posture, posture)
    assert result.posture_deltas == []
    # Identical postures — no actual improvement occurred
    assert result.improved is (
        result.before_summary.total_chains == 0 and result.after_summary.total_chains == 0
    )


def test_diff_remediated_techniques():
    """Hardening a posture should show remediated techniques."""
    from cepheus.engine.differ import diff_postures

    before = ContainerPosture(
        capabilities=CapabilityInfo(effective=["CAP_SYS_ADMIN"]),
        security=SecurityProfile(seccomp="disabled"),
    )
    after = ContainerPosture(
        capabilities=CapabilityInfo(effective=[]),
        security=SecurityProfile(seccomp="filtering"),
    )
    result = diff_postures(before, after)
    remediated = [td for td in result.technique_deltas if td.status == "remediated"]
    assert len(remediated) > 0


def test_diff_new_techniques():
    """Adding capabilities should show new techniques."""
    from cepheus.engine.differ import diff_postures

    before = ContainerPosture(
        capabilities=CapabilityInfo(effective=[]),
        security=SecurityProfile(seccomp="filtering"),
    )
    after = ContainerPosture(
        capabilities=CapabilityInfo(effective=["CAP_SYS_ADMIN"]),
        security=SecurityProfile(seccomp="disabled"),
    )
    result = diff_postures(before, after)
    new_techs = [td for td in result.technique_deltas if td.status == "new"]
    assert len(new_techs) > 0


def test_diff_posture_field_changes():
    """Posture field changes should be detected."""
    from cepheus.engine.differ import diff_postures

    before = ContainerPosture(
        runtime=RuntimeInfo(privileged=True),
        security=SecurityProfile(seccomp="disabled"),
    )
    after = ContainerPosture(
        runtime=RuntimeInfo(privileged=False),
        security=SecurityProfile(seccomp="filtering"),
    )
    result = diff_postures(before, after)
    changed_fields = [d.field_name for d in result.posture_deltas]
    assert "runtime.privileged" in changed_fields
    assert "security.seccomp" in changed_fields


def test_diff_improvement_flag():
    """Improvement flag should reflect security posture change direction."""
    from cepheus.engine.differ import diff_postures

    privileged = ContainerPosture(
        capabilities=CapabilityInfo(effective=["CAP_SYS_ADMIN"]),
        security=SecurityProfile(seccomp="disabled"),
        runtime=RuntimeInfo(privileged=True),
        network=NetworkInfo(can_reach_docker_sock=True),
    )
    hardened = ContainerPosture(
        capabilities=CapabilityInfo(effective=[]),
        security=SecurityProfile(seccomp="filtering"),
        kernel=KernelInfo(version="6.8.1", major=6, minor=8, patch=1),
    )
    result = diff_postures(privileged, hardened)
    assert result.improved is True


def test_diff_serialization():
    """DiffResult should serialize to dict."""
    from cepheus.engine.differ import diff_postures

    posture = ContainerPosture(hostname="test")
    result = diff_postures(posture, posture)
    data = result.model_dump(mode="json")
    assert "posture_deltas" in data
    assert "technique_deltas" in data
    assert "chain_deltas" in data
    assert "improved" in data
