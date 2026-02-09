"""MITRE ATT&CK Navigator layer export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cepheus.models.result import AnalysisResult
from cepheus.models.technique import SEVERITY_ORDER, Severity

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "#ff0000",
    Severity.HIGH: "#ff8c00",
    Severity.MEDIUM: "#ffd700",
    Severity.LOW: "#00cd00",
}

SEVERITY_SCORES: dict[Severity, int] = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 75,
    Severity.MEDIUM: 50,
    Severity.LOW: 25,
}


def generate_layer(
    result: AnalysisResult,
    layer_name: str = "Cepheus Analysis",
) -> dict[str, Any]:
    """Build a MITRE ATT&CK Navigator v4.5 layer dict from an analysis result."""

    # Collect per-MITRE-ID: highest severity and all technique names that matched.
    mitre_map: dict[str, dict[str, Any]] = {}

    for chain in result.chains:
        for step in chain.steps:
            technique = step.technique
            if not technique.mitre_attack:
                continue
            for mitre_id in technique.mitre_attack:
                existing = mitre_map.get(mitre_id)
                if existing is None:
                    mitre_map[mitre_id] = {
                        "severity": technique.severity,
                        "names": [technique.name],
                    }
                else:
                    # Keep the highest severity (higher SEVERITY_ORDER value wins).
                    if SEVERITY_ORDER[technique.severity] > SEVERITY_ORDER[existing["severity"]]:
                        existing["severity"] = technique.severity
                    if technique.name not in existing["names"]:
                        existing["names"].append(technique.name)

    techniques: list[dict[str, Any]] = []
    for mitre_id, info in mitre_map.items():
        severity: Severity = info["severity"]
        techniques.append(
            {
                "techniqueID": mitre_id,
                "color": SEVERITY_COLORS[severity],
                "score": SEVERITY_SCORES[severity],
                "comment": f"Matched via: {', '.join(info['names'])}",
                "enabled": True,
                "metadata": [],
            }
        )

    return {
        "name": layer_name,
        "versions": {"attack": "16", "navigator": "4.5", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Cepheus analysis — {len(result.chains)} escape chains identified",
        "filters": {"platforms": ["Linux", "Containers"]},
        "sorting": 3,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#00cd00", "#ffd700", "#ff8c00", "#ff0000"],
            "minValue": 0,
            "maxValue": 100,
        },
        "metadata": [
            {"name": "generated_by", "value": "Cepheus Container Escape Modeler"},
            {"name": "timestamp", "value": result.analysis_timestamp},
        ],
    }


def write_layer(
    result: AnalysisResult,
    path: str | Path,
    layer_name: str = "Cepheus Analysis",
) -> None:
    """Write a MITRE ATT&CK Navigator layer to a JSON file."""

    layer = generate_layer(result, layer_name)
    Path(path).write_text(json.dumps(layer, indent=2) + "\n")
