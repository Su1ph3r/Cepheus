"""Prerequisite evaluation engine — resolves dot-paths and evaluates DSL checks."""

from __future__ import annotations

import re
from typing import Any

from cepheus.config import CepheusConfig
from cepheus.models.posture import ContainerPosture
from cepheus.models.technique import EscapeTechnique, Prerequisite

# Check types that key off the host KERNEL version alone. When a technique's
# prerequisites are exclusively these, the match is opportunistic: we know the
# host kernel is *in the published vulnerable range*, but we have not verified
# the specific vulnerable component is present/reachable or that the kernel
# binary isn't patched (distro backports). See P2/P3 in cepheus-precision-design.md.
#
# `version_lte` is deliberately NOT here: it checks a *specific component's*
# version (e.g. runtime.runc_version, gpu.nvidia_toolkit_version), so a match
# means the vulnerable component version was directly observed — a high-
# confidence finding, not an opportunistic kernel-range guess. It must not be
# subject to the distro-kernel backport downgrade (kernel backports don't patch
# the runc/toolkit binary). The unknown-version case is handled by each
# prerequisite's own confidence_if_absent instead.
_KERNEL_ONLY_CHECK_TYPES = {"kernel_gte", "kernel_lte", "kernel_between"}


def _is_ubiquitous_default_prereq(p: Prerequisite) -> bool:
    """A prerequisite that is true on essentially every container and therefore
    does NOT confirm a specific vulnerable component — e.g. "user namespaces are
    enabled". Such a prereq must not exempt an otherwise kernel-version-only
    technique from the kernel-range confidence cap. Without this,
    `user_ns_kernel_exploit` (kernel_lte + namespaces.user==True) escaped the cap
    and fired HIGH on routine hosts in the vulnerable kernel range."""
    return p.check_field.startswith("namespaces.") and p.check_type == "equals" and p.check_value is True


# Substrings/regexes that identify a distro/vendor kernel that actively backports
# upstream security patches. When detected, kernel-range-only CVE matches are
# downgraded further (config.distro_kernel_max_confidence). The match list
# below is conservative — false negatives (treating a backported kernel as
# generic) keep the old behaviour; false positives (treating a non-backported
# kernel as backported) reduce CVE recall, which is a worse failure mode.
_DISTRO_KERNEL_PATTERNS: list[tuple[str, str]] = [
    # (pattern, tag) — pattern is matched case-insensitively against kernel.version
    ("microsoft-standard-WSL2", "wsl2"),
    ("microsoft-standard", "wsl"),
    ("-aws", "aws"),
    ("-azure", "azure"),
    ("-gke", "gke"),
    ("-gcp", "gcp"),
    ("-oracle", "oracle"),
    ("-ibm", "ibm"),
    (".amzn1.", "amazon-linux-1"),
    (".amzn2.", "amazon-linux-2"),
    (".amzn2023.", "amazon-linux-2023"),
    (".el7", "rhel7"),
    (".el8", "rhel8"),
    (".el9", "rhel9"),
    (".centos.", "centos"),
    ("linuxkit", "docker-desktop"),
    ("orbstack", "orbstack"),
    ("-bottlerocket", "bottlerocket"),
    ("-flatcar", "flatcar"),
    # Ubuntu/Debian/Proxmox stock kernels are backport-maintained: the distro
    # patches CVEs in place without bumping the upstream version number, so a
    # "kernel <= X" range match on these is a weak signal. Recognising them caps
    # kernel-range-only CVE matches (DirtyPipe et al.) so a routine Ubuntu host
    # doesn't light up with criticals it's already patched against.
    ("-generic", "ubuntu-generic"),
    ("-lowlatency", "ubuntu-lowlatency"),
    ("-cloud-amd64", "debian-cloud"),
    ("-cloud-arm64", "debian-cloud"),
    ("-pve", "proxmox"),
]


def detect_distro_kernel(version: str) -> tuple[bool, str | None]:
    """Return (is_distro, tag) for a kernel version string.

    Patterns are matched case-insensitively. First match wins.
    """
    if not version:
        return False, None
    lower = version.lower()
    for pattern, tag in _DISTRO_KERNEL_PATTERNS:
        if pattern.lower() in lower:
            return True, tag
    return False, None


class _MissingSentinel:
    """Sentinel for missing fields — distinct from None."""

    def __repr__(self) -> str:
        return "<MISSING>"

    def __bool__(self) -> bool:
        return False


_MISSING = _MissingSentinel()


def resolve_dot_path(obj: Any, path: str) -> Any:
    """Walk a dot-path like 'capabilities.effective' into a Pydantic model or dict.

    Returns the resolved value, or _MISSING sentinel if the path doesn't exist.
    """
    parts = path.split(".")
    current = obj
    for part in parts:
        if current is None:
            return _MISSING
        if isinstance(current, dict):
            if part not in current:
                return _MISSING
            current = current[part]
        elif hasattr(current, part):
            current = getattr(current, part)
        else:
            return _MISSING
    return current


def _parse_kernel_version(version_str: str) -> tuple[int, int, int]:
    """Parse a kernel version string into (major, minor, patch)."""
    match = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", version_str)
    if not match:
        return (0, 0, 0)
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))


def _kernel_tuple(posture: ContainerPosture) -> tuple[int, int, int]:
    """Get kernel version tuple from posture, preferring parsed fields."""
    k = posture.kernel
    if k.major > 0 or k.minor > 0 or k.patch > 0:
        return (k.major, k.minor, k.patch)
    return _parse_kernel_version(k.version)


def evaluate_prerequisite(posture: ContainerPosture, prereq: Prerequisite) -> float:
    """Evaluate a single prerequisite against posture data.

    Returns the confidence value (confidence_if_met or confidence_if_absent).
    Returns 0.0 if the check definitively fails.
    """
    value = resolve_dot_path(posture, prereq.check_field)

    # Handle missing data — use confidence_if_absent
    if isinstance(value, _MissingSentinel):
        return prereq.confidence_if_absent

    check = prereq.check_type

    if check == "contains":
        if isinstance(value, list):
            return prereq.confidence_if_met if prereq.check_value in value else 0.0
        if isinstance(value, str):
            return prereq.confidence_if_met if prereq.check_value in value else 0.0
        return 0.0

    if check == "any_of":
        if isinstance(value, list) and isinstance(prereq.check_value, list):
            return prereq.confidence_if_met if any(v in value for v in prereq.check_value) else 0.0
        return 0.0

    if check == "equals":
        return prereq.confidence_if_met if value == prereq.check_value else 0.0

    if check == "not_equals":
        return prereq.confidence_if_met if value != prereq.check_value else 0.0

    if check in ("gte", "lte"):
        # Reject bool explicitly (float(True) == 1.0 would silently
        # satisfy a numeric threshold) and any non-numeric type, treating
        # them as "unknown" rather than a spurious match/miss.
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            return prereq.confidence_if_absent
        try:
            v, target = float(value), float(prereq.check_value)
        except (TypeError, ValueError):
            return prereq.confidence_if_absent
        ok = v >= target if check == "gte" else v <= target
        return prereq.confidence_if_met if ok else 0.0

    if check == "kernel_gte":
        kt = _kernel_tuple(posture)
        # An unparseable/unknown kernel parses to (0,0,0); treat as
        # "kernel unknown" (confidence_if_absent) rather than letting the
        # comparison produce a spurious definitive result. Mirrors the
        # version_lte guard below.
        if kt == (0, 0, 0):
            return prereq.confidence_if_absent
        target = _parse_kernel_version(str(prereq.check_value))
        return prereq.confidence_if_met if kt >= target else 0.0

    if check == "kernel_lte":
        kt = _kernel_tuple(posture)
        if kt == (0, 0, 0):
            # Without this guard, (0,0,0) <= any target is always True —
            # a malformed kernel version would FALSE-POSITIVE every
            # "kernel <= X" CVE gate.
            return prereq.confidence_if_absent
        target = _parse_kernel_version(str(prereq.check_value))
        return prereq.confidence_if_met if kt <= target else 0.0

    if check == "kernel_between":
        kt = _kernel_tuple(posture)
        if kt == (0, 0, 0):
            return prereq.confidence_if_absent
        if not isinstance(prereq.check_value, list) or len(prereq.check_value) != 2:
            return prereq.confidence_if_absent
        low = _parse_kernel_version(str(prereq.check_value[0]))
        high = _parse_kernel_version(str(prereq.check_value[1]))
        return prereq.confidence_if_met if low <= kt <= high else 0.0

    if check == "exists":
        return prereq.confidence_if_met if value is not None else 0.0

    if check == "not_empty":
        if isinstance(value, (list, str, dict)):
            return prereq.confidence_if_met if len(value) > 0 else 0.0
        return prereq.confidence_if_met if value else 0.0

    if check == "regex":
        try:
            pattern = str(prereq.check_value)
            value_str = str(value)[:1024]
            return prereq.confidence_if_met if re.search(pattern, value_str) else 0.0
        except re.error:
            return prereq.confidence_if_absent

    if check == "version_lte":
        if value is None or value == "":
            return prereq.confidence_if_absent
        try:
            val_tuple = _parse_kernel_version(str(value))
            target_tuple = _parse_kernel_version(str(prereq.check_value))
            if val_tuple == (0, 0, 0):
                return prereq.confidence_if_absent
            return prereq.confidence_if_met if val_tuple <= target_tuple else 0.0
        except (TypeError, ValueError):
            return prereq.confidence_if_absent

    # Unknown check type — treat as absent
    return prereq.confidence_if_absent


def match_technique(
    posture: ContainerPosture,
    technique: EscapeTechnique,
    min_confidence: float = 0.3,
    config: CepheusConfig | None = None,
) -> tuple[bool, float]:
    """Evaluate all prerequisites of a technique against a posture.

    Returns (matched, confidence) where:
    - matched: True if average confidence >= min_confidence AND no prerequisite returned 0.0
    - confidence: Average confidence across all prerequisites

    Precision controls (config-driven, applied AFTER averaging):
    - If all prerequisites are kernel-version checks (kernel_gte / kernel_lte /
      kernel_between) — i.e. the match is "kernel is in vulnerable
      range" with no other gating — cap the resulting confidence at
      `config.kernel_only_max_confidence` (default 0.5). This keeps the
      technique visible but ranked below techniques that confirm a specific
      vulnerable component is present.
    - If additionally `posture.kernel.is_distro_kernel` is True (the enumerator
      recognised a backport-maintained distro/vendor kernel — WSL2, EKS, AKS,
      GKE, RHEL, etc.) cap even further at `config.distro_kernel_max_confidence`
      (default 0.2 — below the default min_confidence, so the technique drops
      out of the report entirely).
    """
    if not technique.prerequisites:
        # No prerequisites means always applicable (info-only technique)
        return True, 1.0

    confidences = []
    for prereq in technique.prerequisites:
        conf = evaluate_prerequisite(posture, prereq)
        if conf == 0.0:
            return False, 0.0
        confidences.append(conf)

    avg_confidence = sum(confidences) / len(confidences)

    # Kernel-only confidence cap. A technique is "kernel-only" if every
    # prerequisite is either a kernel-version check or a ubiquitous default
    # (e.g. namespaces.user==True) that doesn't confirm a specific vulnerable
    # component — and at least one is an actual kernel-version check.
    only_kernel_prereqs = any(p.check_type in _KERNEL_ONLY_CHECK_TYPES for p in technique.prerequisites) and all(
        p.check_type in _KERNEL_ONLY_CHECK_TYPES or _is_ubiquitous_default_prereq(p) for p in technique.prerequisites
    )
    if only_kernel_prereqs:
        if config is None:
            config = CepheusConfig()
        cap = config.kernel_only_max_confidence
        # A distro/backport kernel OR an UNKNOWN kernel (version not captured —
        # e.g. a PodSpec-derived posture from the admission webhook, where the
        # kernel is unknowable) both make a kernel-range match unverifiable.
        # Cap to distro_kernel_max_confidence (default 0.2, below min) so the
        # technique drops instead of firing CRITICAL at the bare threshold.
        kernel_unknown = _kernel_tuple(posture) == (0, 0, 0)
        if getattr(posture.kernel, "is_distro_kernel", False) or kernel_unknown:
            cap = min(cap, config.distro_kernel_max_confidence)
        avg_confidence = min(avg_confidence, cap)

    return avg_confidence >= min_confidence, avg_confidence
