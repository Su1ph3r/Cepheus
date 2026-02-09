"""Tests for the POSIX shell enumerator script."""

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).parent.parent / "enumerator" / "cepheus-enum.sh"


# ---------------------------------------------------------------------------
# Static checks (no execution required)
# ---------------------------------------------------------------------------


def test_script_exists():
    """The enumerator script must exist."""
    assert SCRIPT_PATH.exists(), f"Enumerator script not found at {SCRIPT_PATH}"


def test_script_is_executable():
    """The enumerator script must be executable."""
    st = os.stat(SCRIPT_PATH)
    assert st.st_mode & stat.S_IXUSR, "Script is not executable (user)"


def test_script_starts_with_shebang():
    """The enumerator script must start with #!/bin/sh for POSIX compliance."""
    first_line = SCRIPT_PATH.read_text().split("\n")[0]
    assert first_line.strip() == "#!/bin/sh", f"Expected #!/bin/sh, got: {first_line}"


def test_script_no_bashisms():
    """Basic check that the script avoids common bashisms."""
    content = SCRIPT_PATH.read_text()
    bashisms = [
        "[[ ",       # bash-only test
        "declare ",  # bash-only
        "typeset ",  # bash-only
        "let ",      # bash-only
        "<<<",       # here-string
        "function ", # bash-only function declaration
    ]
    for bashism in bashisms:
        assert bashism not in content, f"Found bashism '{bashism}' in enumerator script"


def test_script_outputs_json_keys():
    """The script should construct JSON with the expected top-level keys."""
    content = SCRIPT_PATH.read_text()
    expected_keys = [
        "enumeration_version",
        "timestamp",
        "hostname",
        "kernel",
        "capabilities",
        "mounts",
        "namespaces",
        "security",
        "network",
        "credentials",
        "runtime",
        "cgroup_version",
        "writable_paths",
        "available_tools",
    ]
    for key in expected_keys:
        assert key in content, f"Expected JSON key '{key}' not found in script"


# ---------------------------------------------------------------------------
# Runtime checks — runs the script and validates JSON output
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def enumerator_json():
    """Run the enumerator and parse its stdout as JSON."""
    result = subprocess.run(
        ["sh", str(SCRIPT_PATH)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Script failed (rc={result.returncode}): {result.stderr}"
    data = json.loads(result.stdout)
    return data


def test_valid_json(enumerator_json):
    assert isinstance(enumerator_json, dict)


def test_all_top_level_keys_present(enumerator_json):
    expected = {
        "enumeration_version", "timestamp", "hostname", "kernel",
        "capabilities", "mounts", "namespaces", "security",
        "network", "credentials", "runtime", "cgroup_version",
        "writable_paths", "available_tools",
    }
    assert expected == set(enumerator_json.keys()), (
        f"Missing: {expected - set(enumerator_json.keys())}, "
        f"Extra: {set(enumerator_json.keys()) - expected}"
    )


def test_enumeration_version(enumerator_json):
    assert enumerator_json["enumeration_version"] == "0.1.0"


def test_timestamp_format(enumerator_json):
    ts = enumerator_json["timestamp"]
    assert "T" in ts and ts.endswith("Z"), f"Bad timestamp: {ts}"


def test_hostname_not_empty(enumerator_json):
    assert len(enumerator_json["hostname"]) > 0


def test_kernel_structure(enumerator_json):
    k = enumerator_json["kernel"]
    assert isinstance(k["version"], str) and len(k["version"]) > 0
    for field in ("major", "minor", "patch"):
        assert isinstance(k[field], int), f"kernel.{field} must be int"


def test_capabilities_structure(enumerator_json):
    c = enumerator_json["capabilities"]
    for field in ("effective", "bounding", "permitted"):
        assert isinstance(c[field], list), f"capabilities.{field} must be list"


def test_namespaces_are_booleans(enumerator_json):
    ns = enumerator_json["namespaces"]
    for field in ("pid", "net", "mnt", "user", "uts", "ipc", "cgroup"):
        assert isinstance(ns[field], bool), f"namespaces.{field} must be bool"


def test_security_profile(enumerator_json):
    s = enumerator_json["security"]
    assert s["seccomp"] in ("disabled", "strict", "filtering")
    assert s["apparmor"] is None or isinstance(s["apparmor"], str)
    assert s["selinux"] is None or isinstance(s["selinux"], str)


def test_network_structure(enumerator_json):
    n = enumerator_json["network"]
    assert isinstance(n["interfaces"], list)
    assert isinstance(n["can_reach_metadata"], bool)
    assert isinstance(n["can_reach_docker_sock"], bool)
    assert isinstance(n["listening_ports"], list)


def test_credentials_structure(enumerator_json):
    c = enumerator_json["credentials"]
    assert isinstance(c["service_account_token"], bool)
    assert isinstance(c["environment_secrets"], list)
    assert isinstance(c["cloud_metadata_available"], bool)


def test_no_secret_values_leaked(enumerator_json):
    """Env secrets should list names only, never values."""
    for name in enumerator_json["credentials"]["environment_secrets"]:
        assert isinstance(name, str)
        assert "=" not in name, f"Secret entry should be a name, not key=value: {name}"


def test_runtime_structure(enumerator_json):
    r = enumerator_json["runtime"]
    assert isinstance(r["runtime"], str)
    assert isinstance(r["privileged"], bool)
    assert isinstance(r["pid_one"], str)
    # runtime_version and orchestrator can be null
    assert r["runtime_version"] is None or isinstance(r["runtime_version"], str)
    assert r["orchestrator"] is None or isinstance(r["orchestrator"], str)


def test_cgroup_version(enumerator_json):
    assert enumerator_json["cgroup_version"] in (1, 2)


def test_available_tools_has_sh(enumerator_json):
    assert "sh" in enumerator_json["available_tools"]


def test_writable_paths_is_list(enumerator_json):
    assert isinstance(enumerator_json["writable_paths"], list)
