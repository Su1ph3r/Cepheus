"""Cepheus configuration via environment variables and config files."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class CepheusConfig(BaseSettings):
    model_config = {"env_prefix": "CEPHEUS_"}

    # LLM settings (optional)
    llm_model: str = "anthropic/claude-sonnet-4-20250514"
    llm_api_key: str | None = None
    llm_base_url: str | None = None
    llm_temperature: float = 0.3
    llm_max_tokens: int = 4096

    # Analysis settings
    min_confidence: float = 0.3
    max_chain_length: int = 3

    # Scoring weights
    weight_reliability: float = 0.40
    weight_stealth: float = 0.25
    weight_confidence: float = 0.35
    chain_length_penalty: float = 0.15

    # Output settings
    color: bool = True
    verbose: bool = False
