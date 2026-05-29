"""Cepheus analysis engine.

Public API — stable under semantic versioning for the 1.x series. See
``docs/API.md`` for the contract and the list of intentionally-mutable
models. Anything not re-exported here is an internal implementation
detail and may change in a minor release.
"""

from cepheus.engine.analyzer import analyze
from cepheus.engine.baseline import diff as baseline_diff
from cepheus.engine.baseline import load_baseline
from cepheus.engine.differ import diff_postures
from cepheus.engine.technique_db import (
    get_all_techniques,
    get_technique_by_id,
    get_techniques_by_category,
)
from cepheus.engine.verifier import verify_analysis

__all__ = [
    "analyze",
    "verify_analysis",
    "load_baseline",
    "baseline_diff",
    "diff_postures",
    "get_all_techniques",
    "get_technique_by_id",
    "get_techniques_by_category",
]
