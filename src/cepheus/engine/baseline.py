"""Baseline comparison for `cepheus ci --baseline FILE --fail-on-new`.

A baseline is a previous Cepheus report (JSON or SARIF) representing the
known-acceptable security state of a container or image. The CI gate
fails when chains appear in the current scan that weren't in the
baseline — i.e. a regression introduced by the current build.

Two report formats are accepted:
- JSON (`cepheus analyze --format json -o report.json`) — chain IDs come
  from `chains[].id`.
- SARIF (`cepheus analyze --format sarif -o report.sarif`) — chain IDs
  come from `runs[].results[].partialFingerprints.chainFingerprint/v1`.

The chain ID is stable across runs against the same posture (it's a hash
of the chain steps and posture context), so a baseline captured today is
directly comparable to a scan tomorrow.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from cepheus.models.chain import EscapeChain


@dataclass(frozen=True)
class ChainIdentity:
    """Stable identity for a chain across runs.

    Uses both the chain's hash ID AND the sorted technique-ID tuple. The
    hash matches when the same chain reappears in a re-scan; the
    technique tuple matches even when a re-tune of the chain builder
    produces a new hash for the same underlying technique combination.
    """

    chain_id: str
    technique_ids: tuple[str, ...]

    def matches(self, other: "ChainIdentity") -> bool:
        """Two identities match if EITHER the chain_id matches OR the
        technique-tuple matches. Conservative — favours preserving (not
        flagging as new) when there's any plausible match.

        Empty-string chain_ids never match each other, and empty
        technique-tuples never match each other. Otherwise a corrupted
        baseline entry with no id and no steps would silently match
        every degenerate chain — masking real regressions.
        """
        if self.chain_id and self.chain_id == other.chain_id:
            return True
        if self.technique_ids and self.technique_ids == other.technique_ids:
            return True
        return False


@dataclass
class BaselineDiff:
    """Result of comparing a current scan against a baseline."""

    new: list[EscapeChain] = field(default_factory=list)
    """Chains in current that don't match any baseline chain. Regressions."""

    preserved: list[EscapeChain] = field(default_factory=list)
    """Chains in current that match a baseline chain. Known/accepted."""

    removed: list[ChainIdentity] = field(default_factory=list)
    """Baseline chains absent from current. Fixes / improvements."""

    @property
    def has_regressions(self) -> bool:
        return bool(self.new)


def _chain_identity(chain: EscapeChain) -> ChainIdentity:
    """Build a ChainIdentity from a live EscapeChain."""
    return ChainIdentity(
        chain_id=chain.id,
        technique_ids=tuple(sorted(step.technique.id for step in chain.steps if step.technique)),
    )


def load_baseline(path: str | Path) -> set[ChainIdentity]:
    """Parse a previous Cepheus report and return its set of chain identities.

    Format is auto-detected: SARIF has a top-level `$schema` or `version: 2.1.0`
    with a `runs` array; JSON reports have a top-level `chains` array.

    Raises ValueError on an unrecognised structure or unreadable file.
    """
    path = Path(path)
    if not path.exists():
        raise ValueError(f"Baseline file not found: {path}")

    # Wrap the read in ValueError so the CLI's `except ValueError`
    # handler in `ci` produces a polished error message instead of
    # leaking a raw OSError / UnicodeDecodeError traceback for
    # permissions / encoding problems.
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"Cannot read baseline file {path}: {exc}") from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Baseline file is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Baseline must be a JSON object at the top level")

    # SARIF: { "version": "2.1.0", "runs": [...] }. The load-bearing
    # signal is the `runs` array; the version string can drift (some
    # converters emit a numeric 2.1, or trailing NULs) without breaking
    # the structural intent. Accept any dict that has a `runs` list and
    # carries either a SARIF version field or schema reference.
    if isinstance(data.get("runs"), list) and ("version" in data or "$schema" in data):
        return _identities_from_sarif(data)

    # JSON report: dict containing a `chains` array of objects with `id` + `steps`
    if "chains" in data and isinstance(data["chains"], list):
        return _identities_from_json_report(data)

    raise ValueError(
        "Baseline format not recognised — expected a Cepheus JSON report "
        "(top-level `chains` array) or a SARIF 2.1.0 log (top-level `version` "
        "+ `runs`)."
    )


def _identities_from_json_report(data: dict) -> set[ChainIdentity]:
    """Parse a Cepheus JSON report's chains into a set of ChainIdentity.

    Defensive against malformed input (null chains, non-dict steps,
    non-list steps) so a corrupt or hand-edited baseline produces an
    empty/partial identity set rather than an uncaught AttributeError
    that bubbles up as a raw Python traceback in CI.
    """
    out: set[ChainIdentity] = set()
    for chain in data.get("chains", []):
        if not isinstance(chain, dict):
            continue
        chain_id = chain.get("id") or ""
        steps = chain.get("steps", [])
        if not isinstance(steps, list):
            steps = []
        # Drop empty-string technique IDs at extract time so the resulting
        # tuple never contains `""` — pre-0.3.5 this allowed two corrupt
        # baseline entries with `("",)` tuples to silently match each other,
        # masking real regressions.
        tech_ids = []
        for step in steps:
            if not isinstance(step, dict):
                continue
            tech_obj = step.get("technique")
            if not isinstance(tech_obj, dict):
                continue
            tid = tech_obj.get("id")
            if tid:
                tech_ids.append(tid)
        techs = tuple(sorted(tech_ids))
        if chain_id or techs:
            out.add(ChainIdentity(chain_id=chain_id, technique_ids=techs))
    return out


def _identities_from_sarif(data: dict) -> set[ChainIdentity]:
    """Parse a SARIF 2.1.0 log into a set of ChainIdentity.

    Defensive against malformed input the same way `_identities_from_json_report`
    is — third-party SARIF generators (Trivy, Grype, hand-written test
    fixtures) can produce shape-correct-but-element-malformed input that
    we'd otherwise crash on.
    """
    out: set[ChainIdentity] = set()
    for run in data.get("runs", []):
        if not isinstance(run, dict):
            continue
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            fp = result.get("partialFingerprints") or {}
            if not isinstance(fp, dict):
                fp = {}
            chain_id = fp.get("chainFingerprint/v1") or ""
            props = result.get("properties") or {}
            if not isinstance(props, dict):
                props = {}
            techs_raw = props.get("techniques", [])
            if not isinstance(techs_raw, list):
                techs_raw = []
            techs = tuple(sorted(str(t) for t in techs_raw if t))
            if chain_id or techs:
                out.add(ChainIdentity(chain_id=chain_id, technique_ids=techs))
    return out


def diff(current_chains: list[EscapeChain], baseline: set[ChainIdentity]) -> BaselineDiff:
    """Compute a BaselineDiff between a current scan's chains and a baseline.

    Identity match is OR of (chain_id, technique_id_tuple). See
    ChainIdentity.matches for rationale. Iteration of the input set
    has undefined order — sort the baseline view once so match
    selection and the `removed` list are deterministic across runs
    against the same inputs (otherwise consumers diff'ing CI output
    against itself see spurious churn).

    Each baseline identity can preserve AT MOST one current chain. If
    two current chains both match the same baseline entry (e.g. two
    re-tuned chains that hash differently but share a technique tuple),
    the first matches as preserved and the second falls through to
    `new`. Without this consume-on-match semantic, the second chain
    would silently mask a regression for `--fail-on-new`.
    """
    result = BaselineDiff()
    seen_baseline_identities: set[ChainIdentity] = set()
    ordered_baseline = sorted(baseline, key=lambda b: (b.chain_id, b.technique_ids))

    for chain in current_chains:
        cur_id = _chain_identity(chain)
        match = next(
            (b for b in ordered_baseline if b not in seen_baseline_identities and cur_id.matches(b)),
            None,
        )
        if match is None:
            result.new.append(chain)
        else:
            result.preserved.append(chain)
            seen_baseline_identities.add(match)

    result.removed = [b for b in ordered_baseline if b not in seen_baseline_identities]
    return result
