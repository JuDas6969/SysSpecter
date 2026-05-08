"""Field-review A1: sliding-window leak detection.

Pins the contract that a long run with a clear leak phase followed by
a plateau is detected even when the full-run linear regression is
diluted below threshold. Motivating case: the MotoDB analysis on a
49 309 s run where the leak ran for 8 hours, plateaued for 2, and
the full-run slope was masked by the post-plateau samples.

Tests cover:

- sliding-window analysis returns one entry per stride
- a clean linear leak fires both via full-run and via peak-window
  (slope_source = either path acceptable)
- a leak-then-plateau pattern fires via peak-window (full-run alone
  would miss it) and the finding is annotated with growth_phase_end_s
- a plateau-only series does NOT fire
- the legacy full-run path still works for short runs (window doesn't
  apply when the run is shorter than half a window)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from sysspecter import process_catalog as pc
from sysspecter.analyzer.leaks import (
    _find_plateau_start,
    _sliding_window_stats,
    detect_memory_leaks,
)
from sysspecter.config import Thresholds


def _empty_catalog() -> None:
    """Force the catalog into a clean state so a process classifies as
    'native' (default profile) — keeps the leak math predictable."""
    import tempfile
    tmp = Path(tempfile.mkdtemp()) / "cat.json"
    tmp.write_text(json.dumps({"version": 1, "entries": []}),
                   encoding="utf-8")
    with patch.object(pc, "_candidate_paths", return_value=[str(tmp)]):
        pc.reload()


def _series(name: str, pid: int,
            points: list[tuple[float, float]]) -> list[dict]:
    return [
        {"pid": pid, "name": name, "rel_seconds": rel,
         "rss_bytes": rss, "num_handles": 100, "num_threads": 10}
        for rel, rss in points
    ]


def _linear_then_plateau(
    *, growth_phase_s: float, plateau_phase_s: float,
    start_mb: float, slope_kb_per_s: float,
    samples_per_second: float = 1.0,
) -> list[tuple[float, float]]:
    """Build a series that grows linearly for `growth_phase_s`, then
    plateaus at the peak value for `plateau_phase_s`."""
    out: list[tuple[float, float]] = []
    n_growth = int(growth_phase_s * samples_per_second)
    n_plateau = int(plateau_phase_s * samples_per_second)
    peak_bytes = start_mb * 1024 * 1024 + slope_kb_per_s * 1024 * growth_phase_s
    for i in range(n_growth):
        rel = i / samples_per_second
        rss = start_mb * 1024 * 1024 + slope_kb_per_s * 1024 * rel
        out.append((rel, rss))
    for i in range(n_plateau):
        rel = growth_phase_s + i / samples_per_second
        out.append((rel, peak_bytes))
    return out


# ----------------------------------------------------- sliding-window primitive


def test_sliding_window_returns_one_entry_per_stride() -> None:
    points = [(t, 100.0 + t) for t in range(0, 7200, 1)]   # 7200 s linear
    points_with_name = [(t, v, "x") for (t, v) in points]
    windows = _sliding_window_stats(
        points_with_name,
        window_seconds=3600.0,
        stride_seconds=600.0,
        min_samples=30,
    )
    # 7200 s with 3600 s windows + 600 s stride → starts at 0, 600,
    # …, up to t_max - window*0.25 (= 6300 s) → ~ 11 windows.
    # Allow a generous range so a small change to the half-window
    # cutoff doesn't flake the test.
    assert 6 <= len(windows) <= 14
    for w in windows:
        assert w["slope"] > 0   # series is strictly rising
        assert 0.99 < w["r2"] <= 1.01
        assert w["samples"] >= 30


def test_sliding_window_returns_empty_when_run_too_short() -> None:
    """A 30-minute run is shorter than half a 1-h window — sliding
    doesn't help, and the full-run path is the source of truth."""
    points = [(t, 100.0, "x") for t in range(0, 1800, 1)]
    assert _sliding_window_stats(points, window_seconds=3600.0) == []


def test_find_plateau_start_returns_growth_to_plateau_transition() -> None:
    windows = [
        {"window_start_s": 0,    "slope": 200_000},   # heavy growth
        {"window_start_s": 600,  "slope": 180_000},
        {"window_start_s": 1200, "slope": 150_000},
        {"window_start_s": 1800, "slope": 5_000},     # plateau
        {"window_start_s": 2400, "slope": 2_000},
    ]
    # Trigger plateau search at 50 KB/s growth; transition should be
    # detected at the first sub-10 KB/s window after growth was seen.
    assert _find_plateau_start(
        windows,
        growth_slope_bytes_per_s=50_000,
        plateau_slope_bytes_per_s=10_000,
    ) == 1800.0


def test_find_plateau_start_returns_none_when_no_growth() -> None:
    windows = [{"window_start_s": 0, "slope": 1_000}]
    assert _find_plateau_start(windows, growth_slope_bytes_per_s=50_000) is None


# ----------------------------------------------------- detect_memory_leaks A1


def test_leak_then_plateau_caught_by_sliding_window() -> None:
    """The motivating case: a clear linear leak for 4500 s followed by
    a 1500 s plateau. Full-run slope is diluted to ~ 75% of the
    leak-phase slope, but the sliding window still identifies it."""
    _empty_catalog()
    points = _linear_then_plateau(
        growth_phase_s=4500,
        plateau_phase_s=1500,
        start_mb=100,
        slope_kb_per_s=80,
    )
    rows = _series("notepad.exe", 4242, points)
    leaks = detect_memory_leaks(rows, Thresholds())
    assert len(leaks) == 1, f"expected 1 finding, got {leaks}"
    f = leaks[0]
    # Provenance: peak_window was used (slope_source="peak_window").
    assert f["slope_source"] == "peak_window"
    assert f["peak_window"] is not None
    pw = f["peak_window"]
    assert pw["start_s"] < 3000, "peak window must start in the growth phase"
    assert pw["slope_bytes_per_sec"] > 70 * 1024  # near 80 KB/s
    # Plateau transition annotated.
    assert f["growth_phase_end_s"] is not None
    assert 4000 <= f["growth_phase_end_s"] <= 5400


def test_pure_plateau_does_not_fire() -> None:
    """A flat series at 500 MB for 6000 s must not produce a leak
    finding regardless of which path the analyzer takes."""
    _empty_catalog()
    points = [(float(t), 500.0 * 1024 * 1024) for t in range(0, 6000, 1)]
    rows = _series("notepad.exe", 4242, points)
    leaks = detect_memory_leaks(rows, Thresholds())
    assert leaks == [], f"plateau must not fire; got {leaks}"


def test_clean_linear_leak_still_fires() -> None:
    """The original native-leak case: a 30-minute clean linear ramp
    must still be flagged. C1 + A1 must not regress this."""
    _empty_catalog()
    points = [
        (float(t), 50 * 1024 * 1024 + 100 * 1024 * t)
        for t in range(0, 1800, 1)
    ]
    rows = _series("notepad.exe", 4242, points)
    leaks = detect_memory_leaks(rows, Thresholds())
    assert len(leaks) == 1
    # Either path is fine — both should detect this.
    assert leaks[0]["slope_source"] in ("full_run", "peak_window")
    # A 30-min run is shorter than half a window, so peak_window
    # should be None (legacy full-run path).
    assert leaks[0]["windows_evaluated"] == 0
    assert leaks[0]["peak_window"] is None


def test_finding_annotates_windows_evaluated_count() -> None:
    """The output exposes how many windows the analyzer scanned. A
    long run produces multiple, a short one produces zero."""
    _empty_catalog()
    long_points = _linear_then_plateau(
        growth_phase_s=5400, plateau_phase_s=1800,
        start_mb=100, slope_kb_per_s=80,
    )
    rows = _series("notepad.exe", 4242, long_points)
    leaks = detect_memory_leaks(rows, Thresholds())
    assert leaks[0]["windows_evaluated"] >= 4
