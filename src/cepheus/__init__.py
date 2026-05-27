"""Cepheus — Container Escape Scenario Modeler."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

# Source the version from installed-package metadata rather than a
# hardcoded literal, so the value cannot drift from pyproject.toml.
# Earlier releases pinned ``__version__`` as a string and forgot to
# bump it during version cuts — that bug shipped wrong values into
# every SARIF tool-driver block and every ``cepheus --version`` call,
# making it impossible for an operator to tell which release they were
# running. The PyPI distribution is named ``cepheus-engine`` (the bare
# ``cepheus`` name was already taken on PyPI by an unrelated 2018
# package); the Python module name remains ``cepheus``.
try:
    __version__ = _pkg_version("cepheus-engine")
except PackageNotFoundError:
    # Source checkout without an installed distribution — e.g. someone
    # cloned the repo and is running tests via ``python -m pytest``
    # without ``pip install -e .``. There is no metadata to read.
    # Surface a sentinel that is loudly different from any real version
    # rather than guessing — guessing reintroduces the exact drift bug
    # this resolution is meant to eliminate.
    __version__ = "0.0.0+unknown"
