"""Analyzer orchestrator — full pipeline from posture to ranked escape chains."""

from __future__ import annotations

from datetime import datetime, timezone

from cepheus.config import CepheusConfig
from cepheus.engine.chainer import build_combinatorial_chains, build_single_chains
from cepheus.engine.matcher import match_technique
from cepheus.engine.scorer import rank_chains
from cepheus.models.chain import EscapeChain
from cepheus.models.posture import ContainerPosture
from cepheus.models.result import AnalysisResult, RemediationItem
from cepheus.models.technique import EscapeTechnique, Severity


def _render_poc(technique_id: str, posture: ContainerPosture) -> str:
    """Render a PoC command for a technique, importing poc_templates lazily."""
    try:
        from cepheus.engine.poc_templates import render_poc

        posture_data = {
            "hostname": posture.hostname,
            "kernel_version": posture.kernel.version,
            "runtime": posture.runtime.runtime,
        }
        return render_poc(technique_id, posture_data)
    except (ImportError, KeyError):
        return f"# No PoC template for {technique_id}"


def _generate_remediations(
    matched_techniques: list[tuple[EscapeTechnique, float]],
) -> list[RemediationItem]:
    """Generate remediation items from matched techniques."""
    items = []
    seen_ids = set()
    for technique, confidence in matched_techniques:
        if technique.id in seen_ids:
            continue
        seen_ids.add(technique.id)

        # Extract runtime flag from remediation text if present
        runtime_flag = None
        remediation = technique.remediation
        if "--" in remediation:
            # Try to extract a flag like "--cap-drop=ALL"
            for word in remediation.split():
                if word.startswith("--"):
                    runtime_flag = word.rstrip(",.")
                    break

        items.append(
            RemediationItem(
                technique_id=technique.id,
                severity=technique.severity,
                current_state=technique.description,
                recommended_fix=remediation,
                runtime_flag=runtime_flag,
            )
        )

    # Sort by severity (critical first)
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    items.sort(key=lambda r: severity_order.get(r.severity, 4))
    return items


def analyze(
    posture: ContainerPosture,
    config: CepheusConfig | None = None,
) -> AnalysisResult:
    """Run the full analysis pipeline.

    1. Load technique database
    2. Match techniques against posture
    3. Build single and combinatorial chains
    4. Score and rank chains
    5. Generate remediations
    6. Return AnalysisResult
    """
    if config is None:
        config = CepheusConfig()

    # Load techniques
    from cepheus.engine.technique_db import get_all_techniques

    all_techniques = get_all_techniques()

    # Match
    matched: list[tuple[EscapeTechnique, float, str]] = []
    matched_for_remediation: list[tuple[EscapeTechnique, float]] = []

    for technique in all_techniques:
        is_match, confidence = match_technique(posture, technique, config.min_confidence)
        if is_match:
            poc = _render_poc(technique.id, posture)
            matched.append((technique, confidence, poc))
            matched_for_remediation.append((technique, confidence))

    # Build chains
    single_chains: list[EscapeChain] = build_single_chains(matched)
    combo_chains: list[EscapeChain] = build_combinatorial_chains(matched, posture)

    # Merge and deduplicate by chain ID
    all_chains_map: dict[str, EscapeChain] = {}
    for chain in single_chains + combo_chains:
        if chain.id not in all_chains_map:
            all_chains_map[chain.id] = chain

    all_chains = list(all_chains_map.values())

    # Score and rank
    ranked_chains = rank_chains(all_chains, config)

    # Remediations
    remediations = _generate_remediations(matched_for_remediation)

    return AnalysisResult(
        posture=posture,
        chains=ranked_chains,
        total_techniques_checked=len(all_techniques),
        techniques_matched=len(matched),
        remediations=remediations,
        analysis_timestamp=datetime.now(timezone.utc).isoformat(),
    )
