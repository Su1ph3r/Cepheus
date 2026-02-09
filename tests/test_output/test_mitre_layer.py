"""Tests for the MITRE ATT&CK Navigator layer export."""

import json
from pathlib import Path

from cepheus.output.mitre_layer import SEVERITY_COLORS, SEVERITY_SCORES, generate_layer, write_layer


def test_layer_structure(sample_analysis_result):
    """Layer should have required Navigator fields."""
    layer = generate_layer(sample_analysis_result)
    assert layer["name"] == "Cepheus Analysis"
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["attack"] == "16"
    assert layer["versions"]["navigator"] == "4.5"
    assert "techniques" in layer
    assert "gradient" in layer


def test_layer_technique_ids(sample_analysis_result):
    """Layer techniques should contain MITRE IDs from chains."""
    layer = generate_layer(sample_analysis_result)
    technique_ids = [t["techniqueID"] for t in layer["techniques"]]
    # T1611 is used by the sample technique
    assert "T1611" in technique_ids


def test_layer_colors(sample_analysis_result):
    """Layer techniques should have correct severity colors."""
    layer = generate_layer(sample_analysis_result)
    for tech in layer["techniques"]:
        assert tech["color"] in SEVERITY_COLORS.values()
        assert tech["score"] in SEVERITY_SCORES.values()


def test_layer_deduplication(sample_analysis_result):
    """Layer should deduplicate MITRE IDs."""
    layer = generate_layer(sample_analysis_result)
    technique_ids = [t["techniqueID"] for t in layer["techniques"]]
    assert len(technique_ids) == len(set(technique_ids))


def test_layer_custom_name(sample_analysis_result):
    """Layer should use custom name when provided."""
    layer = generate_layer(sample_analysis_result, layer_name="Custom Layer")
    assert layer["name"] == "Custom Layer"


def test_write_layer_file(sample_analysis_result, tmp_path):
    """write_layer should create a valid JSON file."""
    output_path = tmp_path / "layer.json"
    write_layer(sample_analysis_result, output_path)
    assert output_path.exists()
    data = json.loads(output_path.read_text())
    assert data["domain"] == "enterprise-attack"
