"""Regression tests for the 2026-06 calibration pass.

Each test pins a specific false-positive (or false-negative) that the tool
exhibited and was fixed, so the cry-wolf behaviour can't silently return. See
the case-study FIELD-STUDY.md "Cepheus accuracy notes" for the field evidence
behind each.
"""

from __future__ import annotations

from cepheus.engine.analyzer import analyze
from cepheus.engine.matcher import detect_distro_kernel
from cepheus.models.posture import (
    CapabilityInfo,
    ContainerPosture,
    KernelInfo,
    NetworkInfo,
    RuntimeInfo,
    SecurityProfile,
)


def _ids(posture: ContainerPosture) -> set[str]:
    return {s.technique.id for c in analyze(posture).chains for s in c.steps}


def _hardened(**kw) -> ContainerPosture:
    base = dict(
        kernel=KernelInfo(version="5.15.0-76-generic", major=5, minor=15, patch=0),
        runtime=RuntimeInfo(runtime="docker"),
        security=SecurityProfile(seccomp="filtering"),
    )
    base.update(kw)
    return ContainerPosture(**base)


# --- the headline: a hardened container must be clean -----------------------
def test_hardened_container_produces_no_findings():
    """A fully hardened container on a routine (Ubuntu) host must not produce a
    single finding. Pre-fix this returned 12 critical/high false positives."""
    assert analyze(_hardened()).chains == []


def test_privileged_container_still_fires():
    """Calibration must not blunt real findings: a privileged/cap-laden
    container must still produce escape chains."""
    p = _hardened(
        runtime=RuntimeInfo(runtime="docker", privileged=True),
        capabilities=CapabilityInfo(effective=["CAP_SYS_ADMIN", "CAP_DAC_READ_SEARCH"]),
    )
    assert len(analyze(p).chains) > 0


# --- lsm_apparmor_unconfined: unknown != unconfined -------------------------
def test_apparmor_unknown_does_not_fire():
    assert "lsm_apparmor_unconfined" not in _ids(_hardened(security=SecurityProfile(apparmor=None)))


def test_apparmor_known_unconfined_fires():
    assert "lsm_apparmor_unconfined" in _ids(_hardened(security=SecurityProfile(apparmor="unconfined")))


# --- host-version CVEs: no fire without observable version ------------------
def test_cve_2025_9074_silent_without_version():
    assert "cve_2025_9074" not in _ids(_hardened(runtime=RuntimeInfo(runtime="docker")))


def test_cve_2025_9074_fires_with_vulnerable_version():
    p = _hardened(runtime=RuntimeInfo(runtime="docker", runtime_version="4.40.0"))
    assert "cve_2025_9074" in _ids(p)


def test_cve_2024_21626_silent_without_runc_version():
    assert "cve_2024_21626" not in _ids(_hardened(runtime=RuntimeInfo(runtime="docker")))


def test_cve_2024_21626_fires_with_vulnerable_runc():
    p = _hardened(
        kernel=KernelInfo(version="5.15.0", major=5, minor=15, patch=0),  # non-distro
        runtime=RuntimeInfo(runtime="docker", runc_version="1.1.5"),
    )
    assert "cve_2024_21626" in _ids(p)


# --- docker_socket_mount: must fire even without curl -----------------------
def test_docker_socket_mount_fires_without_curl():
    """The reachable+writable socket IS the primitive; it must fire on images
    without curl (alpine/busybox). Pre-fix the curl prerequisite hard-failed."""
    p = _hardened(network=NetworkInfo(can_reach_docker_sock=True), available_tools=["sh"])
    assert "docker_socket_mount" in _ids(p)


# --- distro-kernel awareness: routine hosts don't light up ------------------
def test_distro_kernel_patterns_recognise_common_hosts():
    for v in ("5.15.0-76-generic", "6.1.0-13-cloud-amd64", "5.15.0-pve", "5.15.0-50-lowlatency"):
        assert detect_distro_kernel(v)[0] is True, v


def test_kernel_cve_capped_out_on_distro_kernel():
    # DirtyPipe range includes 5.15, but an Ubuntu -generic kernel is backport-
    # maintained, so the kernel-range match is capped below threshold and drops.
    assert "cve_2022_0847" not in _ids(_hardened())


def test_user_ns_exploit_capped_on_distro_kernel():
    # kernel_lte + the ubiquitous namespaces.user==True must be treated as
    # kernel-only and capped on a distro kernel (pre-fix it escaped the cap).
    assert "user_ns_kernel_exploit" not in _ids(_hardened())


def test_unknown_kernel_does_not_fire_kernel_cves():
    """A PodSpec-derived / synthetic posture has no kernel version. Kernel-range
    CVEs must NOT fire on an unknown kernel (they did, at the bare 0.3 threshold,
    which lit up every admission-webhook PodSpec with criticals)."""
    p = ContainerPosture(runtime=RuntimeInfo(runtime="docker"))  # kernel.version == ""
    fired = _ids(p)
    assert "cve_2022_0847" not in fired
    assert "user_ns_kernel_exploit" not in fired
