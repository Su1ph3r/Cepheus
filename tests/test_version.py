"""Regression guard for the cepheus ``__version__`` resolution.

Earlier releases hardcoded ``__version__`` as a string literal in
``src/cepheus/__init__.py`` and forgot to bump it during version cuts.
That drift shipped wrong values into every SARIF tool-driver block
(``rules[].driver.version`` + ``semanticVersion``) and every
``cepheus --version`` call, making it impossible for an operator to
tell which release they were running. The fix sources the version
from installed-package metadata via ``importlib.metadata``; this test
asserts the resolution actually matches pyproject.toml's declared
version, so any future regression (e.g. someone reverting to a
hardcoded literal) trips here before shipping.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

import cepheus


def _pyproject_version() -> str:
    """Read the declared version out of pyproject.toml at the repo
    root. Tests run from the same checkout as the package source, so
    walking up from this file lands on the right pyproject."""
    root = Path(__file__).resolve().parent.parent
    pyproject_path = root / "pyproject.toml"
    with pyproject_path.open("rb") as fp:
        data = tomllib.load(fp)
    return data["project"]["version"]


def test_version_matches_pyproject() -> None:
    """``cepheus.__version__`` must equal pyproject.toml's declared
    version when the package is installed (editable or otherwise).

    When the package isn't installed (e.g. a source checkout without
    ``pip install -e .``), ``importlib.metadata`` can't find any
    metadata and falls back to the ``0.0.0+unknown`` sentinel. Skip in
    that case rather than fail — there's nothing to compare against,
    and the assertion would only trip on a configuration issue
    orthogonal to the bug this test guards.
    """
    if cepheus.__version__ == "0.0.0+unknown":
        pytest.skip(
            "cepheus distribution not installed; run `pip install -e .` to enable "
            "this regression test. CI installs the package and runs this check."
        )

    declared = _pyproject_version()
    assert cepheus.__version__ == declared, (
        f"cepheus.__version__ ({cepheus.__version__!r}) drift from "
        f"pyproject.toml [project].version ({declared!r}). "
        "The package metadata is the canonical source — restore the "
        "importlib.metadata-based resolution in src/cepheus/__init__.py "
        "if it was reverted to a hardcoded literal."
    )


def test_version_is_non_empty_string() -> None:
    """Defence in depth — even in the unknown-fallback path, the value
    must be a non-empty string so SARIF tool-driver blocks remain
    well-formed and ``cepheus --version`` doesn't print blanks."""
    assert isinstance(cepheus.__version__, str)
    assert cepheus.__version__, "cepheus.__version__ must be a non-empty string"
