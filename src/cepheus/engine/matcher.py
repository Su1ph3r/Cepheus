"""Prerequisite evaluation engine — resolves dot-paths and evaluates DSL checks."""

from __future__ import annotations

import re
from typing import Any

from cepheus.models.posture import ContainerPosture
from cepheus.models.technique import EscapeTechnique, Prerequisite


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
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version_str)
    if not match:
        return (0, 0, 0)
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


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

    if check == "equals":
        return prereq.confidence_if_met if value == prereq.check_value else 0.0

    if check == "not_equals":
        return prereq.confidence_if_met if value != prereq.check_value else 0.0

    if check == "gte":
        try:
            return prereq.confidence_if_met if float(value) >= float(prereq.check_value) else 0.0
        except (TypeError, ValueError):
            return prereq.confidence_if_absent

    if check == "lte":
        try:
            return prereq.confidence_if_met if float(value) <= float(prereq.check_value) else 0.0
        except (TypeError, ValueError):
            return prereq.confidence_if_absent

    if check == "kernel_gte":
        kt = _kernel_tuple(posture)
        target = _parse_kernel_version(str(prereq.check_value))
        return prereq.confidence_if_met if kt >= target else 0.0

    if check == "kernel_lte":
        kt = _kernel_tuple(posture)
        target = _parse_kernel_version(str(prereq.check_value))
        return prereq.confidence_if_met if kt <= target else 0.0

    if check == "kernel_between":
        kt = _kernel_tuple(posture)
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
) -> tuple[bool, float]:
    """Evaluate all prerequisites of a technique against a posture.

    Returns (matched, confidence) where:
    - matched: True if average confidence >= min_confidence AND no prerequisite returned 0.0
    - confidence: Average confidence across all prerequisites
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
    return avg_confidence >= min_confidence, avg_confidence
