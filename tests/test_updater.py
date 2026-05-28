"""Tests for cepheus.updater — GitHub releases check."""

from __future__ import annotations

import json
from io import BytesIO

import pytest

from cepheus.updater import (
    ReleaseInfo,
    UpdateCheckError,
    _parse_version,
    fetch_latest_release,
    is_newer,
)


def test_parse_version_strips_v_prefix():
    assert _parse_version("v1.2.3") == (1, 2, 3)


def test_parse_version_handles_prerelease_suffix():
    assert _parse_version("v1.2.3-rc.1") == (1, 2, 3)


def test_parse_version_rejects_junk():
    assert _parse_version("garbage") is None
    assert _parse_version("1.2") is None


def test_is_newer_true_on_higher_minor():
    assert is_newer("0.6.3", "v0.7.0") is True


def test_is_newer_false_on_same_version():
    assert is_newer("0.6.3", "v0.6.3") is False


def test_is_newer_false_on_older_remote():
    assert is_newer("0.7.0", "v0.6.3") is False


def test_is_newer_false_on_unparseable_input():
    """An unparseable version must NEVER report a spurious upgrade
    available — we'd rather say 'up to date' than send the user
    chasing a phantom new release."""
    assert is_newer("invalid", "v0.6.3") is False
    assert is_newer("0.6.3", "garbage") is False


def _fake_response(payload: dict | str, status: int = 200):
    """Build a minimal context-manager faking urlopen's return value."""
    if isinstance(payload, dict):
        body = json.dumps(payload).encode("utf-8")
    else:
        body = payload.encode("utf-8")

    class _CtxResp:
        def __enter__(self):
            return BytesIO(body)

        def __exit__(self, *a):
            return False

    return _CtxResp()


def test_fetch_latest_release_happy_path(monkeypatch):
    monkeypatch.setattr(
        "cepheus.updater.urllib.request.urlopen",
        lambda *a, **kw: _fake_response(
            {
                "tag_name": "v0.7.0",
                "name": "0.7.0",
                "html_url": "https://example.com/v0.7.0",
                "published_at": "2026-06-01T00:00:00Z",
                "prerelease": False,
            }
        ),
    )
    info = fetch_latest_release()
    assert isinstance(info, ReleaseInfo)
    assert info.tag == "v0.7.0"
    assert info.html_url == "https://example.com/v0.7.0"


def test_fetch_latest_release_rejects_malformed_tag(monkeypatch):
    monkeypatch.setattr(
        "cepheus.updater.urllib.request.urlopen",
        lambda *a, **kw: _fake_response({"tag_name": "not-a-tag"}),
    )
    with pytest.raises(UpdateCheckError, match="unexpected shape"):
        fetch_latest_release()


def test_fetch_latest_release_rejects_non_json(monkeypatch):
    monkeypatch.setattr(
        "cepheus.updater.urllib.request.urlopen",
        lambda *a, **kw: _fake_response("<html>oops</html>"),
    )
    with pytest.raises(UpdateCheckError, match="not valid UTF-8 JSON"):
        fetch_latest_release()
