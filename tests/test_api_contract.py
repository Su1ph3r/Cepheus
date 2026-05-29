"""1.0 public-API stability contract.

Guards the documented surface in docs/API.md: every name in the engine
and models ``__all__`` must import, and the frozen output models must
reject mutation. A failure here means a public-API regression that would
break semver for the 1.x series.
"""

from __future__ import annotations

import importlib

import pytest
from pydantic import ValidationError


def test_engine_all_names_importable():
    engine = importlib.import_module("cepheus.engine")
    assert engine.__all__, "cepheus.engine must declare a public __all__"
    for name in engine.__all__:
        assert hasattr(engine, name), f"cepheus.engine.__all__ lists {name!r} but it isn't importable"


def test_models_all_names_importable():
    models = importlib.import_module("cepheus.models")
    assert models.__all__, "cepheus.models must declare a public __all__"
    for name in models.__all__:
        assert hasattr(models, name), f"cepheus.models.__all__ lists {name!r} but it isn't importable"


def test_chainstep_is_frozen():
    from cepheus.models import ChainStep
    from cepheus.models.technique import EscapeTechnique, Severity, TechniqueCategory

    step = ChainStep(
        technique=EscapeTechnique(
            id="t",
            name="t",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.LOW,
            description="d",
        ),
        poc_command="echo hi",
    )
    with pytest.raises(ValidationError):
        step.poc_command = "mutated"


def test_remediation_item_is_frozen():
    from cepheus.models import RemediationItem, Severity

    item = RemediationItem(
        technique_id="t",
        severity=Severity.LOW,
        current_state="bad",
        recommended_fix="fix it",
    )
    with pytest.raises(ValidationError):
        item.recommended_fix = "mutated"


def test_mutable_models_stay_mutable():
    """EscapeChain / AnalysisResult are intentionally mutable — the
    scorer and CLI enrich them in place. Guard against an accidental
    freeze that would break those hot paths."""
    from cepheus.models import EscapeChain

    chain = EscapeChain(id="c1")
    chain.composite_score = 0.5  # must NOT raise
    assert chain.composite_score == 0.5
