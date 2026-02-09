"""Tests for the HTML report output."""

import pytest

from cepheus.output.html_report import generate_html, write_html


def test_html_structure(sample_analysis_result):
    """HTML report should contain basic structure."""
    html = generate_html(sample_analysis_result)
    assert "<!DOCTYPE html>" in html
    assert "<html" in html
    assert "</html>" in html
    assert "Cepheus Analysis Report" in html


def test_html_contains_sections(sample_analysis_result):
    """HTML report should contain expected sections."""
    html = generate_html(sample_analysis_result)
    assert "Executive Summary" in html
    assert "Escape Chains" in html or "No escape chains" in html
    assert "Remediations" in html


def test_html_severity_colors(sample_analysis_result):
    """HTML report should use severity color badges."""
    html = generate_html(sample_analysis_result)
    assert "badge-critical" in html or "badge-high" in html or "badge-medium" in html


def test_html_self_contained(sample_analysis_result):
    """HTML report should be self-contained with no external links."""
    html = generate_html(sample_analysis_result)
    # Should not reference external CSS/JS
    assert "https://" not in html or "https://kubernetes" in html  # Allow ref URLs in content
    assert "<link rel=\"stylesheet\"" not in html
    assert "<script src=" not in html


def test_html_write_file(sample_analysis_result, tmp_path):
    """write_html should create a valid HTML file."""
    output_path = tmp_path / "report.html"
    write_html(sample_analysis_result, output_path)
    assert output_path.exists()
    content = output_path.read_text()
    assert "<!DOCTYPE html>" in content
