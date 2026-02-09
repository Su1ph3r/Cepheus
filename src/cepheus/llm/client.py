"""LLM client for AI-assisted container escape analysis."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cepheus.config import CepheusConfig
    from cepheus.models.chain import EscapeChain
    from cepheus.models.posture import ContainerPosture
    from cepheus.models.result import AnalysisResult

logger = logging.getLogger(__name__)


class LLMClient:
    """Wraps litellm to provide LLM-assisted container security analysis."""

    def __init__(self, config: CepheusConfig) -> None:
        self.config = config
        self._check_litellm()

    def _check_litellm(self) -> None:
        try:
            import litellm  # noqa: F401
        except ImportError:
            raise ImportError(
                "LLM features require the 'llm' extra. "
                "Install with: pip install cepheus[llm]"
            )

    async def analyze_posture(
        self,
        posture: ContainerPosture,
        chains: list[EscapeChain],
    ) -> str:
        """Send posture and matched chains to LLM for novel pattern analysis."""
        from cepheus.llm.prompts import SYSTEM_PROMPT, build_analysis_prompt
        import litellm

        user_prompt = build_analysis_prompt(posture, chains)

        try:
            response = await litellm.acompletion(
                model=self.config.llm_model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=self.config.llm_temperature,
                max_tokens=self.config.llm_max_tokens,
                api_key=self.config.llm_api_key,
                base_url=self.config.llm_base_url,
            )
            return response.choices[0].message.content
        except Exception as exc:
            logger.error("LLM analysis failed: %s", type(exc).__name__)
            return "[LLM analysis unavailable]"

    def analyze_posture_sync(
        self,
        posture: ContainerPosture,
        chains: list[EscapeChain],
    ) -> str:
        """Synchronous wrapper for analyze_posture."""
        return asyncio.run(self.analyze_posture(posture, chains))

    async def summarize(self, result: AnalysisResult) -> str:
        """Generate an executive summary of the full analysis result."""
        from cepheus.llm.prompts import SYSTEM_PROMPT, build_summary_prompt
        import litellm

        user_prompt = build_summary_prompt(result)

        try:
            response = await litellm.acompletion(
                model=self.config.llm_model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=self.config.llm_temperature,
                max_tokens=self.config.llm_max_tokens,
                api_key=self.config.llm_api_key,
                base_url=self.config.llm_base_url,
            )
            return response.choices[0].message.content
        except Exception as exc:
            logger.error("LLM summary failed: %s", type(exc).__name__)
            return "[LLM summary unavailable]"

    def summarize_sync(self, result: AnalysisResult) -> str:
        """Synchronous wrapper for summarize."""
        return asyncio.run(self.summarize(result))
