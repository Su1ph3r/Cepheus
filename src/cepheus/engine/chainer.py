"""Chain builder — constructs single and combinatorial escape chains."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from cepheus.models.chain import ChainStep, EscapeChain
from cepheus.models.technique import SEVERITY_ORDER, Severity, TechniqueCategory

if TYPE_CHECKING:
    from cepheus.models.posture import ContainerPosture
    from cepheus.models.technique import EscapeTechnique


def _chain_id(technique_ids: list[str]) -> str:
    """Deterministic chain ID from sorted technique IDs."""
    key = "|".join(sorted(technique_ids))
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _highest_severity(steps: list[ChainStep]) -> Severity:
    """Return the highest severity across chain steps."""
    if not steps:
        return Severity.LOW
    return max(steps, key=lambda s: SEVERITY_ORDER[s.technique.severity]).technique.severity


def build_single_chains(
    matched_techniques: list[tuple[EscapeTechnique, float, str]],
) -> list[EscapeChain]:
    """Build single-step chains from individually matched techniques.

    Args:
        matched_techniques: List of (technique, confidence, poc_command) tuples.

    Returns:
        List of single-step EscapeChains.
    """
    chains = []
    for technique, confidence, poc in matched_techniques:
        step = ChainStep(
            technique=technique,
            poc_command=poc,
            prerequisite_confidence=confidence,
        )
        chain = EscapeChain(
            id=_chain_id([technique.id]),
            steps=[step],
            reliability_score=technique.reliability,
            stealth_score=technique.stealth,
            confidence_score=confidence,
            severity=technique.severity,
            description=f"{technique.name}: {technique.description}",
        )
        chains.append(chain)
    return chains


def build_combinatorial_chains(
    matched_techniques: list[tuple[EscapeTechnique, float, str]],
    posture: ContainerPosture,
) -> list[EscapeChain]:
    """Build multi-step chains from combinatorial techniques.

    Combinatorial techniques are those in the COMBINATORIAL category — they
    represent known-useful combinations. We also look for natural pairings
    between capability/mount techniques and info-disclosure techniques.
    """
    chains = []

    # Separate techniques by category
    combo_techs = []
    non_combo_techs = []
    info_techs = []

    for tech, conf, poc in matched_techniques:
        if tech.category == TechniqueCategory.COMBINATORIAL:
            combo_techs.append((tech, conf, poc))
        elif tech.category == TechniqueCategory.INFO_DISCLOSURE:
            info_techs.append((tech, conf, poc))
        else:
            non_combo_techs.append((tech, conf, poc))

    # Combinatorial techniques are already multi-prerequisite — create chains from them
    for combo_tech, combo_conf, combo_poc in combo_techs:
        step = ChainStep(
            technique=combo_tech,
            poc_command=combo_poc,
            prerequisite_confidence=combo_conf,
        )
        chain = EscapeChain(
            id=_chain_id([combo_tech.id]),
            steps=[step],
            reliability_score=combo_tech.reliability,
            stealth_score=combo_tech.stealth,
            confidence_score=combo_conf,
            severity=combo_tech.severity,
            description=f"[Combo] {combo_tech.name}: {combo_tech.description}",
        )
        chains.append(chain)

    # Build natural two-step chains: info disclosure → escalation
    # (credentials obtained via info leak → used for escalation)
    for info_tech, info_conf, info_poc in info_techs:
        for esc_tech, esc_conf, esc_poc in non_combo_techs:
            # Only pair if the info technique could enable the escalation
            if not _is_useful_pairing(info_tech, esc_tech):
                continue

            step1 = ChainStep(
                technique=info_tech,
                poc_command=info_poc,
                prerequisite_confidence=info_conf,
            )
            step2 = ChainStep(
                technique=esc_tech,
                poc_command=esc_poc,
                prerequisite_confidence=esc_conf,
            )
            avg_conf = (info_conf + esc_conf) / 2
            avg_reliability = (info_tech.reliability + esc_tech.reliability) / 2
            avg_stealth = (info_tech.stealth + esc_tech.stealth) / 2
            severity = _highest_severity([step1, step2])

            chain = EscapeChain(
                id=_chain_id([info_tech.id, esc_tech.id]),
                steps=[step1, step2],
                reliability_score=avg_reliability,
                stealth_score=avg_stealth,
                confidence_score=avg_conf,
                severity=severity,
                description=f"[Chain] {info_tech.name} → {esc_tech.name}",
            )
            chains.append(chain)

    return chains


def _is_useful_pairing(info_tech: EscapeTechnique, esc_tech: EscapeTechnique) -> bool:
    """Check if an info-disclosure technique naturally enables an escalation technique."""
    useful_pairs = {
        # Cloud creds enable K8s or cloud-based escapes
        ("cloud_metadata_creds", "k8s_service_account"),
        ("cloud_metadata_creds", "k8s_kubelet_api"),
        ("cloud_metadata_creds", "k8s_node_proxy"),
        # K8s configmap secrets enable K8s-based escapes
        ("k8s_configmap_secrets", "k8s_kubelet_api"),
        ("k8s_configmap_secrets", "k8s_etcd_access"),
        # Docker env inspection enables Docker-based escapes
        ("docker_env_inspection", "docker_api_unauth"),
        # Env secrets could help anywhere — pair with SA token escapes
        ("env_secret_leak", "k8s_service_account"),
        # Cloud metadata + cloud SSRF
        ("cloud_metadata_creds", "cloud_metadata_ssrf"),
    }
    return (info_tech.id, esc_tech.id) in useful_pairs
