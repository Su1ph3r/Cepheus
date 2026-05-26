"""Tests for the SARIF 2.1.0 output writer."""

from __future__ import annotations

import json

from cepheus.output.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    SEVERITY_TO_LEVEL,
    SEVERITY_TO_SECURITY_SEVERITY,
    _sarif_safe_name,
    generate_sarif,
    write_sarif,
)
from cepheus.models.technique import Severity


def test_generate_sarif_top_level_shape(sample_analysis_result):
    sarif = generate_sarif(sample_analysis_result)
    assert sarif["version"] == SARIF_VERSION
    assert sarif["$schema"] == SARIF_SCHEMA
    assert isinstance(sarif["runs"], list) and len(sarif["runs"]) == 1


def test_generate_sarif_tool_driver(sample_analysis_result):
    run = generate_sarif(sample_analysis_result)["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "Cepheus"
    assert driver["organization"] == "Su1ph3r"
    # The driver version should be the installed package's __version__,
    # which we don't pin here — just confirm it's a non-empty string that
    # looks semver-ish.
    assert driver["version"]
    assert "." in driver["version"]


def test_results_have_required_sarif_fields(sample_analysis_result):
    run = generate_sarif(sample_analysis_result)["runs"][0]
    for result in run["results"]:
        # SARIF 2.1.0 requires `ruleId`, `level`, `message`, `locations`
        # for each result.
        assert "ruleId" in result
        assert result["level"] in {"error", "warning", "note", "none"}
        assert "text" in result["message"]
        assert result["locations"], "each result must have at least one location"
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_rules_deduplicated_by_technique_id(sample_analysis_result):
    """Each technique should appear at most once in tool.driver.rules even
    if multiple chains reference it."""
    run = generate_sarif(sample_analysis_result)["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids)), f"Duplicate rule IDs: {rule_ids}"


def test_severity_mapping_collapses_critical_to_error():
    # Critical and high both → error (SARIF only has error/warning/note)
    assert SEVERITY_TO_LEVEL[Severity.CRITICAL] == "error"
    assert SEVERITY_TO_LEVEL[Severity.HIGH] == "error"
    assert SEVERITY_TO_LEVEL[Severity.MEDIUM] == "warning"
    assert SEVERITY_TO_LEVEL[Severity.LOW] == "note"


def test_security_severity_property_is_string():
    """GitHub Code Scanning expects security-severity as a STRING (not float)."""
    for sev in Severity:
        v = SEVERITY_TO_SECURITY_SEVERITY[sev]
        assert isinstance(v, str)
        # Should be parseable as float in the 0-10 range
        f = float(v)
        assert 0.0 <= f <= 10.0


def test_sarif_safe_name_strips_whitespace():
    # SARIF strict mode disallows whitespace in `name`
    assert _sarif_safe_name("Mount host filesystem via CAP_SYS_ADMIN") == "MountHostFilesystemViaCAP_SYS_ADMIN"
    assert _sarif_safe_name("simple") == "Simple"
    assert _sarif_safe_name("") == ""


def test_write_sarif_produces_parseable_json(sample_analysis_result, tmp_path):
    out = tmp_path / "report.sarif"
    path = write_sarif(sample_analysis_result, out)
    assert path == out
    assert path.exists()
    # Round-trip parse
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["version"] == SARIF_VERSION


def test_partial_fingerprint_present_for_each_result(sample_analysis_result):
    """Stable fingerprints prevent GitHub Code Scanning from opening
    a new issue on every re-scan of the same posture."""
    run = generate_sarif(sample_analysis_result)["runs"][0]
    for result in run["results"]:
        fp = result.get("partialFingerprints", {})
        assert "chainFingerprint/v1" in fp
        assert isinstance(fp["chainFingerprint/v1"], str) and fp["chainFingerprint/v1"]


def test_invocation_carries_timestamp(sample_analysis_result):
    run = generate_sarif(sample_analysis_result)["runs"][0]
    invocations = run["invocations"]
    assert len(invocations) == 1
    assert invocations[0]["executionSuccessful"] is True
    assert invocations[0]["endTimeUtc"]  # non-empty


def test_hostname_is_url_encoded_in_posture_uri(sample_analysis_result):
    """Regression guard for I6: a malicious posture with a hostname
    containing newlines / slashes / control chars must be URL-encoded
    into the artifactLocation URI so it can't produce a malformed SARIF
    or inject content into Code Scanning's location renderer."""
    sample_analysis_result.posture.hostname = "evil\nhost/with spaces"
    sarif = generate_sarif(sample_analysis_result)
    for result in sarif["runs"][0]["results"]:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        # No raw newline or slash in the URI fragment past the scheme.
        assert "\n" not in uri
        # Slashes in the input should be percent-encoded.
        assert "/with spaces" not in uri
        assert uri.startswith("container://")


def test_poc_with_backtick_fence_does_not_break_markdown(sample_analysis_result):
    """Regression guard for the SARIF code-fence-injection defense:
    PoC strings containing triple-backtick sequences must be sanitized
    so they can't escape the embedding ```sh fence and inject
    arbitrary markdown into the Code Scanning UI."""
    # Mutate the sample chain's poc to include a fence-break attempt.
    sample_analysis_result.chains[0].steps[0].poc_command = "echo safe\n```\n# injected"
    sarif = generate_sarif(sample_analysis_result)
    md = sarif["runs"][0]["results"][0]["message"]["markdown"]
    # The PoC fence opens with ```sh and closes with ```. Our sanitizer
    # rewrites any embedded ``` (at line starts) to ~~~ so the outer
    # fence cannot be prematurely closed. Count fence-start sequences:
    # the only ones should be the opener.
    assert md.count("```sh") == 1
    # And the injected line marker survives but stays inside the fence.
    assert "# injected" in md or "injected" in md


def test_chains_without_steps_are_skipped_not_crashing(sample_analysis_result):
    """Regression guard: a degenerate empty-steps chain in the result set
    must not crash the SARIF writer with IndexError mid-write. The writer
    drops such chains defensively so the rest of the report still lands.
    """
    from cepheus.models.chain import EscapeChain
    from cepheus.models.technique import Severity

    degenerate = EscapeChain(
        id="empty-chain",
        steps=[],
        composite_score=0.0,
        reliability_score=0.0,
        stealth_score=0.0,
        confidence_score=0.0,
        severity=Severity.LOW,
        description="degenerate",
    )
    original_chains = list(sample_analysis_result.chains)
    sample_analysis_result.chains = [*original_chains, degenerate]
    sarif = generate_sarif(sample_analysis_result)
    # The degenerate chain is dropped; the original chains still produce
    # results.
    assert len(sarif["runs"][0]["results"]) == len(original_chains)


def test_long_backtick_run_does_not_escape_code_fence(sample_analysis_result):
    """Regression guard for L2: pre-0.3.5 the fence sanitizer regex was
    `^```` which only replaced the FIRST 3 backticks at line start —
    a posture-derived PoC string starting with 6+ backticks would have
    (N-3) backticks remaining, still sufficient to close the outer fence
    early AND open a new code-injection block. The hardened regex
    `^\\s{0,3}`{3,}` collapses ANY 3+-backtick run so only the
    legitimate ```sh ... ``` pair remains."""
    sample_analysis_result.chains[0].steps[0].poc_command = (
        "echo safe\n" + ("`" * 10) + "\n# injected after fence break"
    )
    sarif = generate_sarif(sample_analysis_result)
    md = sarif["runs"][0]["results"][0]["message"]["markdown"]
    # Exactly two fence runs survive: the opening ```sh and the closing ```.
    # Pre-fix this would have been 3+ (the 7 leftover backticks would
    # match the open-fence pattern), letting the attacker inject markdown.
    import re

    fence_runs = list(re.finditer(r"^\s{0,3}`{3,}", md, re.MULTILINE))
    assert len(fence_runs) == 2, (
        f"Only the opening ```sh and closing ``` fences should remain; "
        f"found {len(fence_runs)}: {[m.group() for m in fence_runs]}"
    )
    # And the injected line never reaches the renderer as live markdown —
    # the backtick run was rewritten to tildes which markdown ignores as a fence-close.
    assert ("`" * 10) not in md


def test_indented_backtick_fence_collapsed(sample_analysis_result):
    """Regression guard for L2: CommonMark allows up to 3 spaces before
    a closing fence. Pre-0.3.5 the regex `^```` rejected `   ```` because
    of the leading spaces."""
    sample_analysis_result.chains[0].steps[0].poc_command = "echo safe\n   ```\n# injected"
    sarif = generate_sarif(sample_analysis_result)
    md = sarif["runs"][0]["results"][0]["message"]["markdown"]
    # The indented backtick run is collapsed to indented tildes.
    assert "   ```\n" not in md
    assert "~~~" in md


def test_rules_and_results_use_same_chain_filter(sample_analysis_result):
    """Regression guard for S7: pre-0.3.5 the rules builder didn't pre-filter
    empty-step chains, while the results builder did. The two collections
    must now use the same filter so rule count and result count stay in sync."""
    from cepheus.models.chain import EscapeChain
    from cepheus.models.technique import Severity

    degenerate = EscapeChain(
        id="empty-chain",
        steps=[],
        composite_score=0.0,
        reliability_score=0.0,
        stealth_score=0.0,
        confidence_score=0.0,
        severity=Severity.LOW,
        description="degenerate",
    )
    sample_analysis_result.chains = [*sample_analysis_result.chains, degenerate]
    sarif = generate_sarif(sample_analysis_result)
    run = sarif["runs"][0]
    # Both filters skip the empty chain — no rules and no results from it.
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    result_rule_ids = [r["ruleId"] for r in run["results"]]
    for rid in result_rule_ids:
        assert rid in rule_ids, f"result references rule {rid} that's not in tool.driver.rules"
