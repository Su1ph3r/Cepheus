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

    # Precision controls
    # Cap the confidence of techniques whose only prerequisites are kernel-version
    # checks (kernel_gte / kernel_lte / kernel_between). Without verifying the
    # specific vulnerable component is present and reachable, kernel-range-only
    # matches are opportunistic. Default 0.5 keeps them in the report below
    # proven techniques. Set to 0.0 to drop them entirely; raise to 1.0 for the
    # old (over-confident) behaviour.
    kernel_only_max_confidence: float = 0.5
    # When the kernel is identified as a distro/vendor-maintained build that
    # actively backports security patches (WSL2, EKS/AKS/GKE, RHEL, etc.),
    # downgrade kernel-only matches even further (see KernelInfo.is_distro_kernel).
    distro_kernel_max_confidence: float = 0.2

    # Scoring weights
    weight_reliability: float = 0.40
    weight_stealth: float = 0.25
    weight_confidence: float = 0.35
    chain_length_penalty: float = 0.15

    # Output settings
    color: bool = True
    verbose: bool = False
