"""``cepheus update`` — check for a newer published release.

Reads the latest non-prerelease tag from the GitHub Releases API and
compares it to the locally-installed version. Pure check + advise —
the actual upgrade is delegated to whatever installer the operator
used (pipx, brew, scoop, manual), because Cepheus can't safely
self-replace a running binary across every install path.

The signed-OCI-artifact technique-DB pattern is a deferred follow-up:
the DB currently ships inside the wheel, so updating Cepheus updates
the DB. This module exists to surface the "I have an old version"
signal at the CLI level rather than expecting operators to track
releases out of band.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass

logger = logging.getLogger("cepheus.updater")

_RELEASES_URL = "https://api.github.com/repos/Su1ph3r/Cepheus/releases/latest"
_TIMEOUT_SEC = 8.0
# Tag shape: "v1.2.3" or "v1.2.3-rc.1". Strict so a malformed upstream
# response can't trick the comparison into thinking the user is out of
# date when they aren't.
_TAG_RE = re.compile(r"^v(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?:[-+].*)?$")


@dataclass
class ReleaseInfo:
    tag: str
    name: str
    html_url: str
    published_at: str
    prerelease: bool


class UpdateCheckError(RuntimeError):
    """Raised when we couldn't reach GitHub or the response shape was
    not what we expected. Caller decides whether to surface this or
    silently skip the check (e.g. air-gapped operator)."""


def _parse_version(s: str) -> tuple[int, int, int] | None:
    m = _TAG_RE.match(s.strip())
    if not m:
        return None
    return int(m["major"]), int(m["minor"]), int(m["patch"])


def fetch_latest_release(url: str = _RELEASES_URL) -> ReleaseInfo:
    """GET the latest non-prerelease release record from GitHub.

    Uses unauthenticated requests because:
      * The endpoint is public.
      * Authenticated requests would require operators to provision
        a token just to run ``cepheus update`` — not a tradeoff that
        pays for itself.

    Unauthenticated rate limit is 60 req/hour/IP. ``cepheus update``
    is expected to be invoked maybe once a week per operator, so the
    cap is comfortable.
    """
    req = urllib.request.Request(  # noqa: S310 — hardcoded public GitHub API
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "cepheus-update-check",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_SEC) as resp:  # noqa: S310
            raw = resp.read(2 * 1024 * 1024)  # 2 MB cap — releases are tiny JSON blobs
    except urllib.error.HTTPError as exc:
        raise UpdateCheckError(f"GitHub returned HTTP {exc.code}: {exc.reason}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise UpdateCheckError(f"network error: {type(exc).__name__}: {exc}") from exc

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateCheckError(f"response was not valid UTF-8 JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise UpdateCheckError("response was not a JSON object")

    tag = data.get("tag_name")
    if not isinstance(tag, str) or not _TAG_RE.match(tag.strip()):
        raise UpdateCheckError(f"latest release tag_name has unexpected shape: {tag!r}")

    return ReleaseInfo(
        tag=tag.strip(),
        name=data.get("name") or tag,
        html_url=data.get("html_url") or "",
        published_at=data.get("published_at") or "",
        prerelease=bool(data.get("prerelease")),
    )


def is_newer(installed: str, latest_tag: str) -> bool:
    """Return True iff ``latest_tag`` represents a strictly newer
    semver than ``installed``. Both inputs are tag-form (with or
    without the leading ``v``). Returns False on any unparseable
    input — we never claim "you're out of date" without a clean
    comparison."""
    inst = _parse_version(installed if installed.startswith("v") else f"v{installed}")
    cur = _parse_version(latest_tag)
    if inst is None or cur is None:
        return False
    return cur > inst


def detect_install_method() -> str:
    """Best-effort detection of how this Cepheus was installed, to pick
    the right self-upgrade command. Returns one of: ``pipx``, ``brew``,
    ``scoop``, ``pip``, ``binary``, ``unknown``.

    Detection is path-based (where this module and the interpreter live)
    plus the frozen-binary marker. It is intentionally conservative —
    an ``unknown`` result simply means we advise a manual upgrade rather
    than guessing wrong and running the wrong package manager.
    """
    # Nuitka/PyInstaller single-file binary: can't self-replace a running
    # executable across every OS, so report binary and let the caller
    # advise a manual download.
    if getattr(sys, "frozen", False):
        return "binary"

    mod = (__file__ or "").replace("\\", "/").lower()
    exe = (sys.executable or "").replace("\\", "/").lower()
    pipx_home = os.environ.get("PIPX_HOME", "").replace("\\", "/").lower()

    if "/pipx/" in mod or "/pipx/" in exe or (pipx_home and pipx_home in mod):
        return "pipx"
    if "/cellar/" in mod or "/homebrew/" in mod or "/cellar/" in exe or "/homebrew/" in exe:
        return "brew"
    if "/scoop/" in mod or "/scoop/" in exe:
        return "scoop"
    if "/site-packages/" in mod or "/dist-packages/" in mod:
        return "pip"
    return "unknown"


def upgrade_command(method: str) -> list[str] | None:
    """Return the argv to upgrade Cepheus for a detected install method,
    or ``None`` when in-place self-upgrade isn't possible (``binary`` /
    ``unknown``) and the operator must upgrade manually.

    The PyPI distribution is ``cepheus-engine``; the Homebrew formula and
    Scoop manifest are ``cepheus`` (the formula is tap-qualified)."""
    if method == "pipx":
        return ["pipx", "upgrade", "cepheus-engine"]
    if method == "pip":
        return [sys.executable, "-m", "pip", "install", "--upgrade", "cepheus-engine"]
    if method == "brew":
        return ["brew", "upgrade", "su1ph3r/tap/cepheus"]
    if method == "scoop":
        return ["scoop", "update", "cepheus"]
    return None
