"""Weighted composite scoring for escape chains."""

from __future__ import annotations

from cepheus.config import CepheusConfig
from cepheus.models.chain import EscapeChain


def score_chain(chain: EscapeChain, config: CepheusConfig | None = None) -> EscapeChain:
    """Compute the weighted composite score for an escape chain.

    Formula:
        composite = (reliability × w_r + stealth × w_s + confidence × w_c) × length_penalty
        length_penalty = 1.0 / (1.0 + penalty_factor × (chain_length - 1))

    Mutates and returns the chain with composite_score set.
    """
    if config is None:
        config = CepheusConfig()

    w_r = config.weight_reliability
    w_s = config.weight_stealth
    w_c = config.weight_confidence

    raw_score = (
        chain.reliability_score * w_r
        + chain.stealth_score * w_s
        + chain.confidence_score * w_c
    )

    chain_length = len(chain.steps)
    length_penalty = 1.0 / (1.0 + config.chain_length_penalty * max(0, chain_length - 1))

    chain.composite_score = round(raw_score * length_penalty, 4)
    return chain


def rank_chains(chains: list[EscapeChain], config: CepheusConfig | None = None) -> list[EscapeChain]:
    """Score and rank chains by composite_score descending."""
    if config is None:
        config = CepheusConfig()

    for chain in chains:
        score_chain(chain, config)

    return sorted(chains, key=lambda c: c.composite_score, reverse=True)
