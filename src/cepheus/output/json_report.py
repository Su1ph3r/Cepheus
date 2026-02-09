"""JSON report output for Cepheus analysis results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cepheus.models.result import AnalysisResult


def generate_report(result: AnalysisResult) -> dict[str, Any]:
    """Serialize an AnalysisResult to a JSON-compatible dict."""
    return result.model_dump(mode="json")


def write_report(result: AnalysisResult, path: str | Path) -> Path:
    """Write analysis result as JSON to a file."""
    path = Path(path)
    data = generate_report(result)
    path.write_text(json.dumps(data, indent=2))
    return path
