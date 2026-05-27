"""Module entry point — supports `python -m cepheus ...` and serves as
the concrete compilation target for Nuitka single-binary builds.

`python -m cepheus` is useful for users who can't (or don't want to)
modify PATH; Nuitka needs a real .py file to start from, and the
`[project.scripts]` entry point in pyproject.toml doesn't qualify.
"""

from __future__ import annotations

from cepheus.cli import app


def main() -> None:
    """Synchronous entry point — calls the Typer app."""
    app()


if __name__ == "__main__":
    main()
