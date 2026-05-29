"""Tests for the LLM client."""

from unittest.mock import MagicMock, patch

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


def test_llm_client_empty_content_degrades_to_sentinel(sample_posture, sample_chain):
    """A model response with None content (e.g. truncation/content-filter)
    must degrade to a clear sentinel string, never None."""
    mock_litellm = MagicMock()
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = None

    async def mock_acompletion(**kwargs):
        return mock_response

    mock_litellm.acompletion = mock_acompletion

    with patch.dict("sys.modules", {"litellm": mock_litellm}):
        from cepheus.llm.client import LLMClient

        client = LLMClient(CepheusConfig())
        result = client.analyze_posture_sync(sample_posture, [sample_chain])
        assert isinstance(result, str)
        assert "unavailable" in result.lower()


def test_llm_client_empty_choices_degrades_to_sentinel(sample_posture, sample_chain):
    """An empty choices list must degrade to a sentinel, not IndexError/None."""
    mock_litellm = MagicMock()
    mock_response = MagicMock()
    mock_response.choices = []

    async def mock_acompletion(**kwargs):
        return mock_response

    mock_litellm.acompletion = mock_acompletion

    with patch.dict("sys.modules", {"litellm": mock_litellm}):
        from cepheus.llm.client import LLMClient

        client = LLMClient(CepheusConfig())
        result = client.analyze_posture_sync(sample_posture, [sample_chain])
        assert isinstance(result, str)
        assert "unavailable" in result.lower()


def test_is_unavailable_marker():
    """The CLI uses this to surface LLM failure instead of shipping a
    degraded report silently."""
    from cepheus.llm.client import is_unavailable_marker

    assert is_unavailable_marker("[LLM analysis unavailable: RateLimitError: 429]") is True
    assert is_unavailable_marker("[LLM summary unavailable: model returned an empty response]") is True
    assert is_unavailable_marker("Real analysis output from the model.") is False
    assert is_unavailable_marker(None) is False
    assert is_unavailable_marker("") is False
