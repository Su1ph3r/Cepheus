"""Nubicustos container export importer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_nubicustos_containers(path: Path) -> list[dict[str, Any]]:
    """Parse Nubicustos container export and return cloud container metadata.

    Args:
        path: Path to Nubicustos container export JSON file.

    Returns:
        List of container metadata dicts with cloud context.

    Raises:
        ValueError: If the file is not a valid Nubicustos export.
    """
    data = json.loads(path.read_text())

    if data.get("export_source") != "nubicustos":
        raise ValueError(
            f"Expected export_source 'nubicustos', got '{data.get('export_source')}'"
        )

    containers = data.get("containers", [])
    return containers


def build_cloud_context(containers: list[dict[str, Any]]) -> dict[str, Any]:
    """Build cloud context dict from Nubicustos container metadata.

    This context is injected into the posture analysis to enable
    cloud-specific technique matching (e.g., ECS/EKS escape techniques).

    Args:
        containers: List of container metadata from Nubicustos.

    Returns:
        Cloud context dict with provider, region, containers, and flags.
    """
    if not containers:
        return {}

    providers = set()
    regions = set()
    has_privileged = False
    container_images = []

    for c in containers:
        if c.get("cloud_provider"):
            providers.add(c["cloud_provider"])
        if c.get("region"):
            regions.add(c["region"])
        if c.get("privileged"):
            has_privileged = True
        if c.get("container_image"):
            container_images.append(c["container_image"])

    return {
        "source": "nubicustos",
        "cloud_providers": sorted(providers),
        "regions": sorted(regions),
        "total_containers": len(containers),
        "has_privileged": has_privileged,
        "container_images": container_images,
        "containers": containers,
    }
