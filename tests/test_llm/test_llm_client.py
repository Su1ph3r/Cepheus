"""Tests for the LLM client."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cepheus.config import CepheusConfig


def test_llm_client_import_error():
    """LLMClient should raise ImportError when litellm is not available."""
    with patch.dict("sys.modules", {"litellm": None}):
        from cepheus.llm.client import LLMClient
        from cepheus.config import CepheusConfig
        with pytest.raises(ImportError):
            LLMClient(CepheusConfig())


def test_llm_client_success(sample_posture, sample_chain):
    """LLMClient should return analysis text on success."""
    mock_litellm = MagicMock()
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "Test analysis output"

    # Create a coroutine that returns the mock response
    async def mock_acompletion(**kwargs):
        return mock_response

    mock_litellm.acompletion = mock_acompletion

    with patch.dict("sys.modules", {"litellm": mock_litellm}):
        from cepheus.llm.client import LLMClient
        config = CepheusConfig()
        client = LLMClient(config)
        result = client.analyze_posture_sync(sample_posture, [sample_chain])
        assert result == "Test analysis output"


def test_llm_client_failure_graceful(sample_posture, sample_chain):
    """LLMClient should handle failures gracefully."""
    mock_litellm = MagicMock()

    async def mock_acompletion(**kwargs):
        raise Exception("API Error")

    mock_litellm.acompletion = mock_acompletion

    with patch.dict("sys.modules", {"litellm": mock_litellm}):
        from cepheus.llm.client import LLMClient
        config = CepheusConfig()
        client = LLMClient(config)
        result = client.analyze_posture_sync(sample_posture, [sample_chain])
        assert isinstance(result, str)
        assert "unavailable" in result.lower()
