"""``cepheus fleet diff`` — compare two fleet snapshots."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("cepheus.fleet")


@dataclass
class PodDelta:
    """Per-pod delta between two scans. ``state`` is one of:

    * ``added``    — pod present in ``after`` but not ``before``.
    * ``removed``  — present in ``before`` but not ``after``.
    * ``regressed``— pod present in both, gained at least one chain
                     OR its top score increased by >= 0.05.
    * ``improved`` — present in both, lost at least one chain OR
                     its top score decreased by >= 0.05.
    * ``unchanged``— chain id set is identical and score moved less
                     than 0.05. Not emitted in summaries but useful
                     in raw diff output.
    """

    namespace: str
    name: str
    state: str  # added | removed | regressed | improved | unchanged
    chains_added: list[str] = field(default_factory=list)
    chains_removed: list[str] = field(default_factory=list)
    score_before: float = 0.0
    score_after: float = 0.0
    critical_before: int = 0
    critical_after: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "namespace": self.namespace,
            "name": self.name,
            "state": self.state,
            "chains_added": self.chains_added,
            "chains_removed": self.chains_removed,
            "score_before": self.score_before,
            "score_after": self.score_after,
            "critical_before": self.critical_before,
            "critical_after": self.critical_after,
        }


@dataclass
class FleetDiff:
    pods_added: int
    pods_removed: int
    pods_regressed: int
    pods_improved: int
    deltas: list[PodDelta]
    # Subset of pods_added that actually introduced escape chains. A
    # brand-new pod with zero chains (a freshly-rolled hardened
    # workload) is an addition for visibility but NOT a regression —
    # gating CI on it would fail every clean rollout.
    pods_added_with_chains: int = 0

    @property
    def has_regressions(self) -> bool:
        return self.pods_added_with_chains > 0 or self.pods_regressed > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "summary": {
                "pods_added": self.pods_added,
                "pods_added_with_chains": self.pods_added_with_chains,
                "pods_removed": self.pods_removed,
                "pods_regressed": self.pods_regressed,
                "pods_improved": self.pods_improved,
            },
            # Emit only meaningful deltas — `unchanged` rows would
            # dominate any real-cluster diff and make the report
            # unreadable. They're still computed for the totals.
            "deltas": [d.to_dict() for d in self.deltas if d.state != "unchanged"],
        }


# A score move below this floor is treated as noise — small chain
# additions can shift the composite score by tens of millis depending
# on which technique entered first.
_SCORE_DELTA_NOISE_FLOOR = 0.05


def _classify(
    *,
    before_chains: set[str],
    after_chains: set[str],
    score_before: float,
    score_after: float,
) -> str:
    added = after_chains - before_chains
    removed = before_chains - after_chains
    if added and not removed:
        return "regressed"
    if removed and not added:
        return "improved"
    if added and removed:
        # Net change — call it regressed if any new chains appeared.
        # A pod that swaps one critical for two highs is still a
        # regression in volume even if severity nominally improved.
        return "regressed"
    # Same chain set — only score moved.
    if score_after - score_before >= _SCORE_DELTA_NOISE_FLOOR:
        return "regressed"
    if score_before - score_after >= _SCORE_DELTA_NOISE_FLOOR:
        return "improved"
    return "unchanged"


def _index(pods: list[dict]) -> dict[tuple[str, str], dict]:
    """Index pods by ``(namespace, name)``. Analyzer-error pods whose
    metadata was unreadable can share an empty ``("", "")`` key; warn
    rather than let the second silently clobber the first, which would
    drop its recorded ``error`` from the diff and under-report how many
    pods failed."""
    idx: dict[tuple[str, str], dict] = {}
    for p in pods:
        key = (str(p.get("namespace", "")), str(p.get("name", "")))
        if key in idx:
            logger.warning(
                "fleet diff: duplicate pod key %r — earlier entry shadowed; "
                "the diff may under-report malformed/error pods",
                key,
            )
        idx[key] = p
    return idx


def diff_reports(before: dict, after: dict) -> FleetDiff:
    """Compute a posture delta between two fleet reports. Inputs are
    the ``to_dict()`` output of ``FleetReport`` (or anything matching
    that shape) — accepting dicts rather than dataclasses lets callers
    diff serialized JSON straight off disk without rehydrating the
    full type."""
    before_index = _index(before.get("pods") or [])
    after_index = _index(after.get("pods") or [])
    all_keys = set(before_index) | set(after_index)

    deltas: list[PodDelta] = []
    pods_added = pods_removed = pods_regressed = pods_improved = 0
    pods_added_with_chains = 0

    for ns, name in sorted(all_keys):
        b = before_index.get((ns, name))
        a = after_index.get((ns, name))
        if a is None:
            # Pod removed.
            pods_removed += 1
            deltas.append(
                PodDelta(
                    namespace=ns,
                    name=name,
                    state="removed",
                    chains_removed=list(b.get("chain_ids") or []),
                    score_before=float(b.get("top_chain_score") or 0.0),
                    critical_before=int((b.get("severity_counts") or {}).get("critical", 0)),
                )
            )
            continue
        if b is None:
            # New pod. Always an addition for visibility, but it only
            # counts as a regression (and trips --fail-on-regression)
            # when it actually introduced escape chains — a fresh
            # zero-chain pod must not fail a clean rollout.
            pods_added += 1
            added_chains = list(a.get("chain_ids") or [])
            if added_chains:
                pods_added_with_chains += 1
            deltas.append(
                PodDelta(
                    namespace=ns,
                    name=name,
                    state="added",
                    chains_added=added_chains,
                    score_after=float(a.get("top_chain_score") or 0.0),
                    critical_after=int((a.get("severity_counts") or {}).get("critical", 0)),
                )
            )
            continue
        before_chains = set(b.get("chain_ids") or [])
        after_chains = set(a.get("chain_ids") or [])
        score_before = float(b.get("top_chain_score") or 0.0)
        score_after = float(a.get("top_chain_score") or 0.0)
        state = _classify(
            before_chains=before_chains,
            after_chains=after_chains,
            score_before=score_before,
            score_after=score_after,
        )
        if state == "regressed":
            pods_regressed += 1
        elif state == "improved":
            pods_improved += 1
        deltas.append(
            PodDelta(
                namespace=ns,
                name=name,
                state=state,
                chains_added=sorted(after_chains - before_chains),
                chains_removed=sorted(before_chains - after_chains),
                score_before=score_before,
                score_after=score_after,
                critical_before=int((b.get("severity_counts") or {}).get("critical", 0)),
                critical_after=int((a.get("severity_counts") or {}).get("critical", 0)),
            )
        )

    return FleetDiff(
        pods_added=pods_added,
        pods_removed=pods_removed,
        pods_regressed=pods_regressed,
        pods_improved=pods_improved,
        deltas=deltas,
        pods_added_with_chains=pods_added_with_chains,
    )
