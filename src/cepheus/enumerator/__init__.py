"""Bundled POSIX-shell enumerator script.

This sub-package exists so the enumerator shell script
(``cepheus-enum.sh``) is bundled inside the wheel. Earlier releases
shipped the script at the repo root under ``enumerator/`` — outside
``src/cepheus/`` — and hatchling's wheel build only included
``src/cepheus/``, so every PyPI install was missing the script and
``cepheus ci`` failed with "Cannot find cepheus-enum.sh".

The script is loaded at runtime by ``cepheus.cli._find_enumerator_script``
via ``importlib.resources`` / ``Path(__file__).parent`` semantics so
it works for any install layout (editable, wheel-installed,
PyInstaller-frozen).
"""
