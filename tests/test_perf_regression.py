"""Performance regression guard over the K8s Goat posture fixtures.

The analyzer's hot path is the technique-matcher walk: for each
posture, every technique's prerequisites are evaluated, chains are
constructed by combinatorial composition, and the result is scored.
This file pins both the wall-clock budget and the peak-allocation
budget so a future change that — say — turns a list scan into an
O(n^2) walk over technique pairs gets caught at CI time rather than
in a customer's pipeline.

Budgets are sized at ~12-16x the measured baseline on a 2026-era
runner (~50ms wall / ~0.5MB peak alloc on a typical GitHub Actions
ubuntu-latest), giving wide headroom for runner variance while still
failing on a real algorithmic regression. When budgets prove flaky
in CI, widen the multiplier rather than the absolute number — that
way the relationship to the real measurement stays legible.
"""

from __future__ import annotations

import os
import time
import tracemalloc
from pathlib import Path

import pytest

from cepheus.config import CepheusConfig
from cepheus.engine.analyzer import analyze
from cepheus.models.posture import ContainerPosture

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "k8s-goat"

# Generous, but not so generous a real regression slips through.
# Baseline on a 2026-era runner: ~50ms wall, ~0.5MB peak alloc.
# CI variance is usually 1.5-2x; the 12-16x budgets below leave room
# without hiding regressions.
WALL_BUDGET_MS = 600  # ~12x the 50ms baseline — wide CI tolerance
PER_POSTURE_BUDGET_MS = 80  # ~16x the 5ms baseline
PEAK_ALLOC_BUDGET_MB = 8  # ~16x the 0.5MB baseline


def _load_postures() -> list[ContainerPosture]:
    if not FIXTURES_DIR.exists():
        pytest.skip(f"perf fixtures not present at {FIXTURES_DIR}")
    paths = sorted(FIXTURES_DIR.glob("*-posture.json"))
    if not paths:
        pytest.skip(f"no *-posture.json fixtures under {FIXTURES_DIR}")
    return [ContainerPosture.model_validate_json(p.read_text(encoding="utf-8")) for p in paths]


@pytest.fixture(scope="module")
def postures() -> list[ContainerPosture]:
    return _load_postures()


@pytest.mark.skipif(
    os.environ.get("CEPHEUS_SKIP_PERF") == "1",
    reason="perf tests skipped via CEPHEUS_SKIP_PERF=1",
)
def test_analyzer_wall_clock_budget(postures: list[ContainerPosture]) -> None:
    """Total analyze() time over the full fixture set must stay under
    the wall-clock budget. Catches global slow-downs (e.g. an N^2
    walk landing in matcher.py) without being sensitive to individual
    posture outliers."""
    cfg = CepheusConfig()

    # Warm-up: first call pays for cold-cache + technique-db build.
    # We're measuring steady-state analyzer cost, not import cost.
    for p in postures:
        analyze(p, cfg)

    t0 = time.perf_counter()
    for p in postures:
        analyze(p, cfg)
    dt_ms = (time.perf_counter() - t0) * 1000

    assert dt_ms <= WALL_BUDGET_MS, (
        f"analyzer wall clock regressed: {dt_ms:.1f}ms total over "
        f"{len(postures)} K8s Goat fixtures (budget {WALL_BUDGET_MS}ms). "
        f"Per-posture: {dt_ms / len(postures):.1f}ms. "
        f"If the regression is real, profile with `python -m cProfile -s cumulative`; "
        f"if it's CI runner noise, widen the multiplier in WALL_BUDGET_MS."
    )


@pytest.mark.skipif(
    os.environ.get("CEPHEUS_SKIP_PERF") == "1",
    reason="perf tests skipped via CEPHEUS_SKIP_PERF=1",
)
def test_analyzer_per_posture_budget(postures: list[ContainerPosture]) -> None:
    """No individual analyze() call should exceed the per-posture
    budget. Catches a regression that's hidden by averaging — e.g. a
    technique whose matcher walks the FULL posture for every chain
    candidate."""
    cfg = CepheusConfig()
    # Warm-up.
    for p in postures:
        analyze(p, cfg)

    slowest = 0.0
    slowest_idx = -1
    for i, p in enumerate(postures):
        t0 = time.perf_counter()
        analyze(p, cfg)
        dt = (time.perf_counter() - t0) * 1000
        if dt > slowest:
            slowest = dt
            slowest_idx = i

    assert slowest <= PER_POSTURE_BUDGET_MS, (
        f"single-posture analyze regressed: posture #{slowest_idx} took "
        f"{slowest:.1f}ms (budget {PER_POSTURE_BUDGET_MS}ms). "
        f"Run the suite with `-s` and add a per-fixture print to identify "
        f"which fixture is slow."
    )


@pytest.mark.skipif(
    os.environ.get("CEPHEUS_SKIP_PERF") == "1",
    reason="perf tests skipped via CEPHEUS_SKIP_PERF=1",
)
def test_analyzer_peak_alloc_budget(postures: list[ContainerPosture]) -> None:
    """Peak heap allocation across the fixture run must stay under the
    budget. Catches memory blowups (e.g. an unbounded cache, or a
    chain-construction step that materialises the cartesian product
    of techniques)."""
    cfg = CepheusConfig()
    # Warm-up — load technique DB into memory before measurement.
    for p in postures:
        analyze(p, cfg)

    tracemalloc.start()
    try:
        for p in postures:
            analyze(p, cfg)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    peak_mb = peak / (1024 * 1024)
    assert peak_mb <= PEAK_ALLOC_BUDGET_MB, (
        f"analyzer peak allocation regressed: {peak_mb:.2f}MB "
        f"(budget {PEAK_ALLOC_BUDGET_MB}MB). Use tracemalloc snapshots to "
        f"isolate the largest allocators: `tracemalloc.take_snapshot().statistics('lineno')`."
    )
