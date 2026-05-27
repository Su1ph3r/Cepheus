"""Tests for the Cepheus CLI."""

import json

import pytest
from typer.testing import CliRunner

from cepheus.cli import app

runner = CliRunner()


@pytest.fixture
def sample_posture_file(tmp_path):
    """Create a sample posture JSON file for testing."""
    posture = {
        "enumeration_version": "0.1.0",
        "timestamp": "2024-01-01T00:00:00Z",
        "hostname": "test-container",
        "kernel": {"version": "5.10.0", "major": 5, "minor": 10, "patch": 0},
        "capabilities": {"effective": ["CAP_SYS_ADMIN", "CAP_NET_RAW"], "bounding": [], "permitted": []},
        "mounts": [],
        "namespaces": {"pid": True, "net": True, "mnt": True, "user": True, "uts": True, "ipc": True, "cgroup": True},
        "security": {"seccomp": "disabled", "apparmor": None, "selinux": None},
        "network": {
            "interfaces": ["eth0"],
            "can_reach_metadata": False,
            "can_reach_docker_sock": False,
            "listening_ports": [],
        },
        "credentials": {"service_account_token": False, "environment_secrets": [], "cloud_metadata_available": False},
        "runtime": {
            "runtime": "docker",
            "runtime_version": None,
            "orchestrator": None,
            "privileged": False,
            "pid_one": "bash",
        },
        "cgroup_version": 1,
        "writable_paths": [],
        "available_tools": [],
    }
    path = tmp_path / "posture.json"
    path.write_text(json.dumps(posture))
    return path


def test_analyze_terminal_format(sample_posture_file):
    result = runner.invoke(app, ["analyze", str(sample_posture_file)])
    assert result.exit_code == 0
    assert "Analysis Summary" in result.output or "Escape Chains" in result.output


def test_analyze_json_format(sample_posture_file):
    result = runner.invoke(app, ["analyze", str(sample_posture_file), "--format", "json"])
    assert result.exit_code == 0


def test_analyze_with_output_file(sample_posture_file, tmp_path):
    output_path = tmp_path / "report.json"
    result = runner.invoke(app, ["analyze", str(sample_posture_file), "--output", str(output_path)])
    assert result.exit_code == 0
    assert output_path.exists()
    report = json.loads(output_path.read_text())
    assert "chains" in report
    assert "remediations" in report


def test_analyze_file_not_found():
    result = runner.invoke(app, ["analyze", "/nonexistent/file.json"])
    assert result.exit_code == 1


def test_analyze_invalid_json(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("not json at all")
    result = runner.invoke(app, ["analyze", str(bad_file)])
    assert result.exit_code == 1


def test_analyze_min_severity(sample_posture_file):
    result = runner.invoke(app, ["analyze", str(sample_posture_file), "--min-severity", "critical"])
    assert result.exit_code == 0


def test_techniques_list():
    result = runner.invoke(app, ["techniques"])
    assert result.exit_code == 0
    assert "cap_sys_admin" in result.output.lower() or "Escape Techniques" in result.output


def test_techniques_filter_category():
    result = runner.invoke(app, ["techniques", "--category", "capability"])
    assert result.exit_code == 0


def test_techniques_filter_severity():
    result = runner.invoke(app, ["techniques", "--severity", "critical"])
    assert result.exit_code == 0


def test_techniques_search():
    result = runner.invoke(app, ["techniques", "--search", "docker"])
    assert result.exit_code == 0


def test_techniques_search_no_results():
    result = runner.invoke(app, ["techniques", "--search", "zzz_nonexistent_zzz"])
    assert result.exit_code == 0


def test_analyze_mitre_format(sample_posture_file, tmp_path):
    output_path = tmp_path / "layer.json"
    result = runner.invoke(
        app, ["analyze", str(sample_posture_file), "--format", "mitre", "--output", str(output_path)]
    )
    assert result.exit_code == 0
    assert output_path.exists()
    import json

    data = json.loads(output_path.read_text())
    assert data["domain"] == "enterprise-attack"


def test_analyze_mitre_format_stdout(sample_posture_file):
    result = runner.invoke(app, ["analyze", str(sample_posture_file), "--format", "mitre"])
    assert result.exit_code == 0


def test_analyze_html_format(sample_posture_file, tmp_path):
    output_path = tmp_path / "report.html"
    result = runner.invoke(app, ["analyze", str(sample_posture_file), "--format", "html", "--output", str(output_path)])
    assert result.exit_code == 0
    assert output_path.exists()
    content = output_path.read_text()
    assert "<!DOCTYPE html>" in content


def test_diff_command(tmp_path):
    privileged = {
        "hostname": "before",
        "kernel": {"version": "5.10.0", "major": 5, "minor": 10, "patch": 0},
        "capabilities": {"effective": ["CAP_SYS_ADMIN"], "bounding": [], "permitted": []},
        "security": {"seccomp": "disabled", "apparmor": None, "selinux": None},
        "runtime": {"runtime": "docker", "privileged": True, "pid_one": "bash"},
        "network": {"interfaces": [], "can_reach_metadata": False, "can_reach_docker_sock": False},
        "credentials": {"service_account_token": False},
        "cgroup_version": 1,
        "writable_paths": [],
        "available_tools": [],
    }
    hardened = {
        "hostname": "after",
        "kernel": {"version": "6.8.1", "major": 6, "minor": 8, "patch": 1},
        "capabilities": {"effective": [], "bounding": [], "permitted": []},
        "security": {"seccomp": "filtering", "apparmor": "docker-default", "selinux": None},
        "runtime": {"runtime": "containerd", "privileged": False, "pid_one": "app"},
        "network": {"interfaces": [], "can_reach_metadata": False, "can_reach_docker_sock": False},
        "credentials": {"service_account_token": False},
        "cgroup_version": 2,
        "writable_paths": [],
        "available_tools": [],
    }
    before_file = tmp_path / "before.json"
    after_file = tmp_path / "after.json"
    before_file.write_text(json.dumps(privileged))
    after_file.write_text(json.dumps(hardened))
    result = runner.invoke(app, ["diff", str(before_file), str(after_file)])
    assert result.exit_code == 0


def test_diff_json_format(tmp_path):
    posture = {
        "hostname": "test",
        "kernel": {"version": "5.10.0", "major": 5, "minor": 10, "patch": 0},
        "capabilities": {"effective": [], "bounding": [], "permitted": []},
        "security": {"seccomp": "filtering"},
        "runtime": {"runtime": "docker", "privileged": False, "pid_one": "app"},
        "network": {"interfaces": [], "can_reach_metadata": False, "can_reach_docker_sock": False},
        "credentials": {"service_account_token": False},
        "cgroup_version": 1,
        "writable_paths": [],
        "available_tools": [],
    }
    f = tmp_path / "posture.json"
    f.write_text(json.dumps(posture))
    result = runner.invoke(app, ["diff", str(f), str(f), "--format", "json"])
    assert result.exit_code == 0


def test_no_args_shows_help():
    result = runner.invoke(app, [])
    # Typer no_args_is_help exits with code 0 or 2 depending on version
    assert result.exit_code in (0, 2)
    assert "analyze" in result.output.lower() or "usage" in result.output.lower()


def test_windows_stdout_reconfigured_to_utf8(monkeypatch):
    """Regression guard for v0.4.2 fix: on Windows, importing cepheus.cli
    must reconfigure stdout/stderr to UTF-8 so non-TTY pipes don't crash
    with `OSError [Errno 22]` the moment Rich emits a non-ASCII char.

    Simulates the import path on Windows by faking sys.platform and a
    fresh stream with a tracking reconfigure(). Asserts reconfigure was
    called with utf-8 + errors=replace.
    """
    import importlib
    import io
    import sys

    calls: list[dict] = []

    class FakeStream(io.StringIO):
        def reconfigure(self, **kwargs):
            calls.append(kwargs)

    fake_out = FakeStream()
    fake_err = FakeStream()
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "stdout", fake_out)
    monkeypatch.setattr(sys, "stderr", fake_err)

    # Force a fresh import so the top-level reconfigure block runs again.
    import cepheus.cli

    importlib.reload(cepheus.cli)

    assert len(calls) == 2, f"expected stdout+stderr reconfigure, got {calls}"
    for call in calls:
        assert call["encoding"] == "utf-8"
        assert call["errors"] == "replace"
