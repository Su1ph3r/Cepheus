"""Tests for cepheus.updater — GitHub releases check."""

from __future__ import annotations

import json
from io import BytesIO

import pytest

from cepheus.updater import (
    ReleaseInfo,
    UpdateCheckError,
    _parse_version,
    detect_install_method,
    fetch_latest_release,
    is_newer,
    upgrade_command,
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


@pytest.mark.parametrize(
    ("module_path", "expected"),
    [
        ("/usr/lib/python3.13/site-packages/cepheus/updater.py", "pip"),
        ("/usr/lib/python3/dist-packages/cepheus/updater.py", "pip"),
        ("/home/u/.local/pipx/venvs/cepheus-engine/lib/cepheus/updater.py", "pipx"),
        ("/opt/homebrew/Cellar/cepheus/1.0.0/libexec/cepheus/updater.py", "brew"),
        ("C:/Users/u/scoop/apps/cepheus/current/cepheus/updater.py", "scoop"),
        ("/some/random/checkout/src/cepheus/updater.py", "unknown"),
    ],
)
def test_detect_install_method(monkeypatch, module_path, expected):
    monkeypatch.setattr("cepheus.updater.__file__", module_path)
    monkeypatch.setattr("cepheus.updater.sys.executable", "/usr/bin/python3")
    monkeypatch.setattr("cepheus.updater.sys.frozen", False, raising=False)
    monkeypatch.delenv("PIPX_HOME", raising=False)
    assert detect_install_method() == expected


def test_detect_install_method_frozen_binary(monkeypatch):
    monkeypatch.setattr("cepheus.updater.sys.frozen", True, raising=False)
    assert detect_install_method() == "binary"


def test_upgrade_command_per_method():
    assert upgrade_command("pipx") == ["pipx", "upgrade", "cepheus-engine"]
    assert upgrade_command("brew") == ["brew", "upgrade", "su1ph3r/tap/cepheus"]
    assert upgrade_command("scoop") == ["scoop", "update", "cepheus"]
    assert upgrade_command("pip")[:3] == [__import__("sys").executable, "-m", "pip"]
    # No self-upgrade for binary / unknown installs.
    assert upgrade_command("binary") is None
    assert upgrade_command("unknown") is None


def test_update_apply_runs_detected_command(monkeypatch):
    """`cepheus update --apply` should detect the install method and run
    the upgrade command after confirmation."""
    import subprocess as _sp

    from typer.testing import CliRunner

    import cepheus.updater as up
    from cepheus.cli import app

    monkeypatch.setattr(
        up,
        "fetch_latest_release",
        lambda *a, **k: ReleaseInfo(
            tag="v999.0.0", name="999", html_url="https://example.com", published_at="", prerelease=False
        ),
    )
    monkeypatch.setattr(up, "detect_install_method", lambda: "pip")
    monkeypatch.setattr(up, "upgrade_command", lambda m: ["py", "-m", "pip", "install", "--upgrade", "cepheus-engine"])

    captured: dict = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return _sp.CompletedProcess(cmd, 0)

    monkeypatch.setattr("subprocess.run", fake_run)

    result = CliRunner().invoke(app, ["update", "--apply"], input="y\n")
    assert result.exit_code == 0, result.output
    assert captured.get("cmd") == ["py", "-m", "pip", "install", "--upgrade", "cepheus-engine"]


def test_update_apply_declined_does_not_run(monkeypatch):
    """Declining the confirmation must NOT run any command."""
    import subprocess as _sp

    from typer.testing import CliRunner

    import cepheus.updater as up
    from cepheus.cli import app

    monkeypatch.setattr(
        up,
        "fetch_latest_release",
        lambda *a, **k: ReleaseInfo(
            tag="v999.0.0", name="999", html_url="https://example.com", published_at="", prerelease=False
        ),
    )
    monkeypatch.setattr(up, "detect_install_method", lambda: "pip")
    monkeypatch.setattr(up, "upgrade_command", lambda m: ["py", "-m", "pip", "install", "--upgrade", "cepheus-engine"])

    ran = {"called": False}

    def fake_run(cmd, **kw):
        ran["called"] = True
        return _sp.CompletedProcess(cmd, 0)

    monkeypatch.setattr("subprocess.run", fake_run)

    result = CliRunner().invoke(app, ["update", "--apply"], input="n\n")
    assert ran["called"] is False
    assert "cancelled" in result.output.lower()
