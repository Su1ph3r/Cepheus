"""SARIF 2.1.0 export — for GitHub Code Scanning + generic SAST tooling.

SARIF (Static Analysis Results Interchange Format) is the OASIS standard
for security-tool output. GitHub Code Scanning ingests SARIF directly via
the `github/codeql-action/upload-sarif@v3` action and renders results in
the repository's Security tab.

Schema reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
GitHub's accepted-subset spec: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

from cepheus import __version__
from cepheus.models.result import AnalysisResult
from cepheus.models.technique import Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

# Map Cepheus severity → SARIF level. SARIF has only three levels (error,
# warning, note) so critical and high collapse to error.
SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

# Also surface severity via `properties.security-severity` (GitHub uses
# this 0-10 score for filtering in Code Scanning). Numbers chosen to
# match CVSS-like buckets so existing dashboards group these naturally.
SEVERITY_TO_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.5",
}


def _technique_to_rule(technique: Any) -> dict[str, Any]:
    """Build a SARIF `reportingDescriptor` (a rule definition) from a Cepheus
    EscapeTechnique. One per unique technique; deduplicated by caller."""
    rule: dict[str, Any] = {
        "id": technique.id,
        "name": _sarif_safe_name(technique.name),
        "shortDescription": {"text": technique.name},
        "fullDescription": {"text": technique.description},
        "helpUri": technique.references[0] if technique.references else "https://github.com/Su1ph3r/Cepheus",
        "help": {
            "text": technique.remediation or "See description.",
            "markdown": _rule_markdown(technique),
        },
        "defaultConfiguration": {"level": SEVERITY_TO_LEVEL[technique.severity]},
        "properties": {
            "tags": ["security", "container-escape", technique.category.value] + (["cve"] if technique.cve else []),
            "security-severity": SEVERITY_TO_SECURITY_SEVERITY[technique.severity],
            "precision": "high",
        },
    }
    if technique.cve:
        rule["properties"]["cve"] = technique.cve
    if technique.mitre_attack:
        rule["properties"]["mitre-attack"] = technique.mitre_attack
    return rule


def _sarif_safe_name(name: str) -> str:
    """SARIF `name` field disallows whitespace per the strict-mode spec. Convert
    to PascalCase-ish so GitHub's Code Scanning UI still renders cleanly."""
    return "".join(part[:1].upper() + part[1:] for part in name.split() if part)


def _rule_markdown(technique: Any) -> str:
    parts: list[str] = [f"**{technique.name}** ({technique.severity.value})", ""]
    parts.append(technique.description)
    if technique.cve:
        parts.append("")
        parts.append(f"**CVE:** {technique.cve}")
    if technique.mitre_attack:
        parts.append(f"**MITRE ATT&CK:** {', '.join(technique.mitre_attack)}")
    if technique.remediation:
        parts.append("")
        parts.append(f"**Remediation:** {technique.remediation}")
    if technique.references:
        parts.append("")
        parts.append("**References:**")
        for ref in technique.references:
            parts.append(f"- {ref}")
    return "\n".join(parts)


def _chain_to_result(chain: Any, posture_uri: str) -> dict[str, Any]:
    """Build a SARIF `result` (a finding) from an EscapeChain. Uses the
    top-of-chain technique's rule id; the chain narrative is in the
    message text.

    Raises ValueError on a chain with no steps — that's a chainer-side
    bug and should surface loudly here rather than being silently
    swallowed (which would leak through to the SARIF writer as an
    IndexError mid-write and trash the whole report).
    """
    if not chain.steps:
        raise ValueError(f"SARIF result requested for empty chain (id={chain.id!r})")

    top_step = chain.steps[0]
    technique = top_step.technique

    chain_summary = " → ".join(step.technique.name for step in chain.steps)

    message_text = (
        f"Container escape chain detected (severity={chain.severity.value}, "
        f"score={chain.composite_score:.2f}).\n\n"
        f"Chain: {chain_summary}\n\n"
        f"{technique.description}"
    )

    return {
        "ruleId": technique.id,
        "level": SEVERITY_TO_LEVEL[chain.severity],
        "message": {
            "text": message_text,
            "markdown": _result_markdown(chain),
        },
        # Cepheus analyses are container-posture, not source files. SARIF
        # still requires a `locations` entry; we synthesise a logical
        # location pointing at the container.
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": posture_uri, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [
                    {
                        "name": technique.id,
                        "kind": "type",
                        "fullyQualifiedName": f"cepheus.technique.{technique.id}",
                    }
                ],
            }
        ],
        "properties": {
            "composite-score": chain.composite_score,
            "reliability-score": chain.reliability_score,
            "stealth-score": chain.stealth_score,
            "confidence-score": chain.confidence_score,
            "chain-length": len(chain.steps),
            "chain-id": chain.id,
            "techniques": [step.technique.id for step in chain.steps],
        },
        "partialFingerprints": {
            # Stable fingerprint so re-runs against the same posture
            # dedupe in GitHub Code Scanning instead of opening new
            # findings on every push.
            "chainFingerprint/v1": chain.id,
        },
    }


# Match: up to 3 leading spaces (CommonMark indented-fence allowance),
# then 3-or-more backticks, OR a stray carriage return anywhere.
# Replaces the entire backtick run regardless of length so a posture
# with `\\u0060\\u0060\\u0060\\u0060\\u0060\\u0060\\u0060\\u0060\\u0060`
# (9 backticks) can't strip just the first 3 and still close the outer
# fence with the remaining 6.
_MARKDOWN_FENCE_RE = re.compile(r"^\s{0,3}`{3,}|\r")


def _sanitize_for_code_fence(text: str) -> str:
    """Strip markdown-fence-breaking characters from poc-command text
    before embedding inside a triple-backtick block. PoC commands are
    rendered with posture-derived data (hostname, kernel_version,
    runtime); a malicious posture could otherwise include `\\n``` ` to
    break out of the code fence and inject arbitrary markdown into the
    GitHub Code Scanning UI.

    Replaces 3+-backtick sequences at the start of an optionally
    space-indented line (CommonMark fence-close shape) with a tilde
    sequence (visually similar but never parsed as a backtick-fence
    close) and strips embedded carriage returns.
    """
    if not text:
        return ""
    return "\n".join(_MARKDOWN_FENCE_RE.sub("~~~", line) for line in text.splitlines())


def _result_markdown(chain: Any) -> str:
    parts: list[str] = [
        f"### {chain.steps[0].technique.name}",
        "",
        f"**Severity:** {chain.severity.value} · **Composite score:** {chain.composite_score:.2f}",
        "",
    ]
    if len(chain.steps) > 1:
        parts.append("**Chain steps:**")
        for i, step in enumerate(chain.steps, 1):
            parts.append(f"{i}. `{step.technique.id}` — {step.technique.name}")
        parts.append("")
    parts.append("**PoC:**")
    parts.append("```sh")
    for step in chain.steps:
        if step.poc_command:
            parts.append(_sanitize_for_code_fence(step.poc_command))
    parts.append("```")
    return "\n".join(parts)


def generate_sarif(result: AnalysisResult) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log dict from an analysis result.

    The output has one `run` with:
      - `tool.driver` describing Cepheus
      - `tool.driver.rules`: one entry per *unique* technique that
        appears in any chain (deduplicated by `technique.id`)
      - `results`: one entry per ranked chain
    """
    # Deduplicate rules by technique id while preserving insertion order.
    # Mirror the same filter the `results` builder uses below so the rules
    # set and results set agree on which chains contribute — pre-0.3.5
    # the two used different filters and could produce a SARIF run with
    # rules referencing chains that were silently dropped from `results`.
    rules_by_id: dict[str, dict[str, Any]] = {}
    for chain in result.chains:
        if not chain.steps:
            continue
        for step in chain.steps:
            tid = step.technique.id
            if tid not in rules_by_id:
                rules_by_id[tid] = _technique_to_rule(step.technique)

    # URL-encode the hostname into the URI so a malicious posture (with
    # `hostname: "evil\nrun-on-host"` or backslash/space/control chars)
    # can't produce a malformed SARIF URI or inject content into the
    # Code Scanning UI's location rendering.
    safe_hostname = quote(result.posture.hostname or "unknown", safe="")
    posture_uri = f"container://{safe_hostname}"

    # Drop degenerate empty-step chains rather than crash the writer.
    results = [_chain_to_result(chain, posture_uri) for chain in result.chains if chain.steps]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Cepheus",
                        "fullName": "Cepheus — Container Escape Scenario Modeler",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/Su1ph3r/Cepheus",
                        "organization": "Su1ph3r",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": result.analysis_timestamp,
                    }
                ],
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": "file:///"},
                },
                "properties": {
                    "posture-hostname": result.posture.hostname,
                    "posture-kernel": result.posture.kernel.version,
                    "techniques-checked": result.total_techniques_checked,
                    "techniques-matched": result.techniques_matched,
                },
            }
        ],
    }


def write_sarif(result: AnalysisResult, path: str | Path) -> Path:
    """Write a SARIF 2.1.0 log to a JSON file."""
    path = Path(path)
    data = generate_sarif(result)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


# Verify-side SARIF: one result per VERIFIED technique (not per chain).
# Used by `cepheus verify --format sarif` so verifier outcomes upload
# to GitHub Code Scanning alongside (or instead of) the static-analysis
# SARIF. The result's ``level`` reflects the verifier outcome:
#   CONFIRMED     → error (the primitive actually works in this container)
#   NOT_CONFIRMED → note  (static match was a false positive — informational)
#   NO_VERIFIER   → warning (operator should manually check)
#   ERROR         → warning (verifier infra failure — needs operator attention)
_VERIFY_OUTCOME_TO_LEVEL: dict[str, str] = {
    "CONFIRMED": "error",
    "NOT_CONFIRMED": "note",
    "NO_VERIFIER": "warning",
    "ERROR": "warning",
}


def _verify_result_to_sarif(tv: Any, posture_uri: str) -> dict[str, Any]:
    """Build a SARIF result entry from a TechniqueVerification."""
    outcome = tv.outcome.value if hasattr(tv.outcome, "value") else str(tv.outcome)
    level = _VERIFY_OUTCOME_TO_LEVEL.get(outcome, "warning")
    message_lines = [
        f"Verifier outcome: **{outcome}** "
        f"(severity={tv.severity}, exit_code={tv.exit_code if tv.exit_code is not None else 'n/a'}).",
    ]
    if tv.stderr:
        message_lines.append("")
        message_lines.append("**stderr:**")
        message_lines.append("```")
        message_lines.append(_sanitize_for_code_fence(tv.stderr))
        message_lines.append("```")
    return {
        "ruleId": tv.technique_id,
        "level": level,
        "message": {
            "text": (
                f"{tv.technique_id} ({tv.technique_name}) — verifier outcome: {outcome}. "
                f"Exit code: {tv.exit_code if tv.exit_code is not None else 'n/a'}."
            ),
            "markdown": "\n".join(message_lines),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": posture_uri, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [
                    {
                        "name": tv.technique_id,
                        "kind": "type",
                        "fullyQualifiedName": f"cepheus.technique.{tv.technique_id}",
                    }
                ],
            }
        ],
        "properties": {
            "verifier-outcome": outcome,
            "verifier-exit-code": tv.exit_code,
            "severity": tv.severity,
        },
        "partialFingerprints": {
            # Fingerprint by technique id + outcome so re-running with a
            # changed outcome (CONFIRMED → NOT_CONFIRMED, e.g. after a
            # cap drop) opens a new finding instead of reusing the old one.
            "verifyFingerprint/v1": f"{tv.technique_id}:{outcome}",
        },
    }


def generate_verify_sarif(report: Any, container_id: str) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log dict from a VerificationReport.

    Unlike ``generate_sarif`` (which emits one result per chain), this
    emits one result per VERIFIED technique. Severity-rank ordering of
    results is preserved from the verifier — operators see CRITICAL
    confirmed primitives at the top of Code Scanning's Security tab.

    The ``rules`` set is derived from the techniques that produced
    results, so the SARIF run is self-contained (no orphan ruleIds).
    """
    rules_by_id: dict[str, dict[str, Any]] = {}
    safe_container = quote(container_id or "unknown", safe="")
    posture_uri = f"container://{safe_container}"

    # Build minimal rule descriptors from the technique db so the SARIF
    # is self-contained and renderable without the static-analysis SARIF.
    from cepheus.engine.technique_db import get_technique_by_id

    results = []
    for tv in report.results:
        if tv.technique_id not in rules_by_id:
            tech = get_technique_by_id(tv.technique_id)
            if tech is not None:
                rules_by_id[tv.technique_id] = _technique_to_rule(tech)
            else:
                # Fallback minimal rule if the technique isn't in the DB
                # (shouldn't happen in practice but keeps the SARIF valid).
                rules_by_id[tv.technique_id] = {
                    "id": tv.technique_id,
                    "name": _sarif_safe_name(tv.technique_name),
                    "shortDescription": {"text": tv.technique_name},
                    "defaultConfiguration": {"level": "warning"},
                }
        results.append(_verify_result_to_sarif(tv, posture_uri))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Cepheus",
                        "fullName": "Cepheus — Container Escape Verifier",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/Su1ph3r/Cepheus",
                        "organization": "Su1ph3r",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                    }
                ],
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": "file:///"},
                },
                "properties": {
                    "container-id": container_id,
                    "verify-confirmed": report.confirmed_count,
                    "verify-not-confirmed": report.not_confirmed_count,
                    "verify-no-verifier": report.no_verifier_count,
                    "verify-error": report.error_count,
                    "verify-total": len(report.results),
                },
            }
        ],
    }


def write_verify_sarif(report: Any, container_id: str, path: str | Path) -> Path:
    """Write a verify-mode SARIF 2.1.0 log to a JSON file."""
    path = Path(path)
    data = generate_verify_sarif(report, container_id)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path
