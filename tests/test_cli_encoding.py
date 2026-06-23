"""Regression guard: the CLI must not crash when stdout is not UTF-8.

Cepheus emits non-ASCII routinely (box-drawing runes, the … truncation marker,
em dashes in technique descriptions and the confirmation banner). The native
Nuitka binaries do not get CPython's C-locale-to-UTF-8 coercion (PEP 538), so
under a `C`/`POSIX` or empty locale stdout is ASCII and the first em dash
crashed the command with UnicodeEncodeError. v1.1.0 shipped that bug in the
Linux/macOS single-binary path.

`cepheus.cli` reconfigures stdout/stderr to UTF-8 (errors="replace") on import,
on every platform, to fix it. This test forces an ASCII io encoding via
PYTHONIOENCODING=ascii (which defeats PEP 538) and asserts a Rich-rendering
command still exits cleanly with no UnicodeEncodeError — reproducing the
original crash without the fix and locking the fix in.
"""

from __future__ import annotations

import os
import subprocess
import sys


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONIOENCODING": "ascii"}
    return subprocess.run(
        [sys.executable, "-m", "cepheus", *cmd],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_techniques_survives_ascii_stdout():
    """`techniques` renders a Rich table full of non-ASCII; it must not crash
    when the io encoding is ASCII."""
    proc = _run(["techniques"])
    assert proc.returncode == 0, f"exit={proc.returncode}\nstderr:\n{proc.stderr}"
    assert "UnicodeEncodeError" not in proc.stderr


def test_analyze_banner_survives_ascii_stdout(tmp_path):
    """The confirmation/UNCONFIRMED banner and chains table contain em dashes;
    analyzing a posture under an ASCII io encoding must not crash."""
    posture = tmp_path / "p.json"
    posture.write_text(
        '{"kernel":{"version":"5.15.0-76-generic","major":5,"minor":15,"patch":0},'
        '"runtime":{"runtime":"docker","privileged":true},'
        '"capabilities":{"effective":["CAP_SYS_ADMIN","CAP_SYS_MODULE"]},'
        '"security":{"seccomp":"unconfined","apparmor":"unconfined"}}',
        encoding="utf-8",
    )
    proc = _run(["analyze", str(posture), "-s", "critical"])
    assert proc.returncode == 0, f"exit={proc.returncode}\nstderr:\n{proc.stderr}"
    assert "UnicodeEncodeError" not in proc.stderr
