"""Tests for the Impact / Affected-Component(s) / Recommendation finding
fields surfaced via SARIF (and rendered by the web viewer)."""

from __future__ import annotations

from cepheus.engine.technique_db import get_all_techniques
from cepheus.models.chain import ChainStep, EscapeChain
from cepheus.models.technique import EscapeTechnique, Severity, TechniqueCategory
from cepheus.output.sarif import (
    _affected_components,
    _remediation_text,
    _resolve_impact,
    generate_sarif,
)


def _tech(cat: TechniqueCategory, *, sev: Severity = Severity.HIGH, impact: str = "", **kw) -> EscapeTechnique:
    return EscapeTechnique(id="x", name="x", category=cat, severity=sev, description="d", impact=impact, **kw)


def test_every_shipped_technique_has_curated_impact():
    """All shipped techniques carry a curated one-line impact (the _IMPACT
    side-car). Uncurated techniques would still get a derived fallback, but
    the shipped set should be fully curated."""
    missing = [t.id for t in get_all_techniques() if not t.impact.strip()]
    assert not missing, f"techniques missing curated impact: {missing}"


def test_results_carry_impact_and_affected_components(sample_analysis_result):
    run = generate_sarif(sample_analysis_result)["runs"][0]
    assert run["results"], "fixture should produce at least one result"
    for r in run["results"]:
        props = r["properties"]
        assert isinstance(props["impact"], str) and props["impact"]
        comps = props["affected-components"]
        assert isinstance(comps, list) and comps
        assert comps[0].startswith("Container")


def test_rules_carry_remediation(sample_analysis_result):
    run = generate_sarif(sample_analysis_result)["runs"][0]
    for rule in run["tool"]["driver"]["rules"]:
        assert rule["properties"]["remediation"]


def test_resolve_impact_prefers_curated_else_derives():
    curated = _tech(TechniqueCategory.CAPABILITY, impact="Curated consequence.")
    chain = EscapeChain(id="c", steps=[ChainStep(technique=curated)], severity=Severity.CRITICAL)
    assert _resolve_impact(chain) == "Curated consequence."

    bare = _tech(TechniqueCategory.KERNEL, sev=Severity.HIGH, impact="")
    chain2 = EscapeChain(id="c2", steps=[ChainStep(technique=bare)], severity=Severity.HIGH)
    derived = _resolve_impact(chain2)
    assert derived and derived != "Curated consequence."


def test_affected_components_container_first_and_deduped():
    cap = _tech(TechniqueCategory.CAPABILITY)
    cap2 = _tech(TechniqueCategory.CAPABILITY)
    mnt = _tech(TechniqueCategory.MOUNT)
    chain = EscapeChain(
        id="ch",
        steps=[ChainStep(technique=cap), ChainStep(technique=cap2), ChainStep(technique=mnt)],
    )
    comps = _affected_components(chain, "web-7f9")
    assert comps[0] == "Container: web-7f9"
    assert comps.count("Linux capabilities") == 1  # deduped across two capability steps
    assert "Host mounts / filesystem" in comps
    # No hostname → generic container label, never blank.
    assert _affected_components(chain, None)[0] == "Container"


def test_remediation_text_combines_flag_and_is_never_blank():
    t1 = _tech(TechniqueCategory.CAPABILITY, remediation="Drop the cap", cli_flag="--cap-drop=SYS_ADMIN")
    assert _remediation_text(t1) == "Drop the cap (runtime flag: --cap-drop=SYS_ADMIN)"
    # No remediation, no flag → still non-empty guidance.
    assert _remediation_text(_tech(TechniqueCategory.KERNEL))
