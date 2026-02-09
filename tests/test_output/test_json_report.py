"""Tests for the JSON report output."""

import json
from pathlib import Path

from cepheus.output.json_report import generate_report, write_report


def test_generate_report_roundtrip(sample_analysis_result):
    """Report should serialize and be valid JSON."""
    report = generate_report(sample_analysis_result)
    assert isinstance(report, dict)
    json_str = json.dumps(report)
    roundtrip = json.loads(json_str)
    assert roundtrip["total_techniques_checked"] == 56
    assert "chains" in roundtrip
    assert "remediations" in roundtrip


def test_write_report_creates_file(sample_analysis_result, tmp_path):
    """write_report should create a valid JSON file."""
    output_path = tmp_path / "report.json"
    write_report(sample_analysis_result, output_path)
    assert output_path.exists()
    data = json.loads(output_path.read_text())
    assert data["total_techniques_checked"] == 56
