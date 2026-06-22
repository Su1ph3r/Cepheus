"""Recall tests for the P4 detection expansion.

Three classic, high-value container escapes that the DB was missing:
  - CAP_SYS_MODULE (load a kernel module -> ring-0 on the host)
  - writable /proc/sys/kernel/modprobe (hijack the modprobe helper)
  - writable /sys/kernel/uevent_helper (hijack the uevent helper)

Each test pins both recall (fires on the vulnerable posture) and precision
(stays silent on a hardened one), so the additions can't regress in either
direction. All three have real primitive-proving verifiers, so none should be
classified precondition-only.
"""

from __future__ import annotations

from cepheus.engine.analyzer import analyze
from cepheus.engine.technique_db import get_technique_by_id
from cepheus.models.posture import (
    CapabilityInfo,
    ContainerPosture,
    KernelInfo,
    RuntimeInfo,
    SecurityProfile,
)


def _ids(posture: ContainerPosture) -> set[str]:
    return {s.technique.id for c in analyze(posture).chains for s in c.steps}


def _base(**kw) -> ContainerPosture:
    base = dict(
        kernel=KernelInfo(version="5.15.0-76-generic", major=5, minor=15, patch=0),
        runtime=RuntimeInfo(runtime="docker"),
        security=SecurityProfile(seccomp="filtering"),
    )
    base.update(kw)
    return ContainerPosture(**base)


# --- CAP_SYS_MODULE ---------------------------------------------------------
def test_cap_sys_module_fires_when_held():
    posture = _base(capabilities=CapabilityInfo(effective=["CAP_SYS_MODULE"]))
    assert "cap_sys_module" in _ids(posture)


def test_cap_sys_module_silent_without_cap():
    posture = _base(capabilities=CapabilityInfo(effective=["CAP_NET_BIND_SERVICE"]))
    assert "cap_sys_module" not in _ids(posture)


# --- modprobe_path overwrite (writable + CAP_SYS_ADMIN) ---------------------
def test_modprobe_path_fires_with_writable_and_cap():
    posture = _base(
        writable_paths=["/proc/sys/kernel/modprobe"],
        capabilities=CapabilityInfo(effective=["CAP_SYS_ADMIN"]),
    )
    assert "procfs_modprobe_path" in _ids(posture)


def test_modprobe_path_silent_without_cap_sys_admin():
    """Writable per DAC but no CAP_SYS_ADMIN -> kernel rejects the write, so the
    technique must not fire (the same EROFS reality as core_pattern)."""
    posture = _base(writable_paths=["/proc/sys/kernel/modprobe"])
    assert "procfs_modprobe_path" not in _ids(posture)


# --- uevent_helper overwrite (writable /sys) --------------------------------
def test_uevent_helper_fires_when_writable():
    posture = _base(writable_paths=["/sys/kernel/uevent_helper"])
    assert "sysfs_uevent_helper" in _ids(posture)


def test_uevent_helper_silent_when_not_writable():
    posture = _base(writable_paths=["/some/other/path"])
    assert "sysfs_uevent_helper" not in _ids(posture)


# --- precision wiring -------------------------------------------------------
def test_new_techniques_have_real_primitive_verifiers():
    for tid in ("cap_sys_module", "procfs_modprobe_path", "sysfs_uevent_helper"):
        t = get_technique_by_id(tid)
        assert t is not None, tid
        assert t.verify_command, tid
        # These genuinely prove the primitive, not just a precondition.
        assert t.verify_confirms_primitive is True, tid


def test_hardened_container_still_clean_with_new_techniques():
    """The new detections must not light up a hardened container."""
    assert _ids(_base()) == set()
