"""Smoke tests for the splitter's change-point detection.

The heuristics are tuned against a real 13-hour reference run. These tests
lock in the behaviour for a handful of synthetic shapes so accidental
regressions show up in CI.
"""

from __future__ import annotations

from sysspecter.splitter.detect import (
    auto_min_phase_seconds,
    build_phases,
    detect_change_points,
)


def _row(t: float, cpu: float, mem: float = 40.0, disk: float = 10.0) -> dict:
    return {
        "rel_seconds": float(t),
        "cpu_total_pct": cpu,
        "mem_percent": mem,
        "disk_active_pct_est": disk,
    }


def test_no_change_points_on_flat_run() -> None:
    rows = [_row(t, 20.0) for t in range(0, 900)]
    cps = detect_change_points(rows, [])
    assert cps == []


def test_detects_step_up_then_flat() -> None:
    # 500 s idle, sharp jump to hot, 500 s hot
    rows = []
    for t in range(0, 500):
        rows.append(_row(t, 8.0))
    for t in range(500, 1000):
        rows.append(_row(t, 80.0))
    cps = detect_change_points(rows, [])
    assert cps, "expected at least one change point"
    # the change should land near 500 (within the window size)
    assert any(400 <= c.rel_seconds <= 600 for c in cps)


def test_inflection_on_slow_memory_fill() -> None:
    # memory fills linearly from 50 to 78 over 7000 s, then stays flat to 49000 s
    rows = []
    for t in range(0, 49000, 25):
        if t < 7000:
            mem = 50.0 + (t / 7000.0) * 28.0
        else:
            mem = 78.0
        rows.append(_row(t, 10.0, mem=mem))
    cps = detect_change_points(rows, [])
    inflections = [c for c in cps if "mem" in c.reason and "flat" in c.reason]
    assert inflections, "memory rising-to-flat inflection should fire"
    # the detected point should be within 20% of the run around t=7000
    ip = inflections[0]
    assert 3000 <= ip.rel_seconds <= 15000


def test_build_phases_absorbs_too_short_segments() -> None:
    # One change-point in the middle of a 2000-second window: should yield 2 phases
    from sysspecter.splitter.detect import ChangePoint
    cps = [ChangePoint(rel_seconds=100.0, reason="step_up", kind="step",
                       evidence="x", score=10.0)]
    # min_phase_seconds 200 forces the 100 s head segment to merge with its neighbour
    phases = build_phases(cps, 2000.0, min_phase_seconds=200.0)
    assert len(phases) == 1
    assert phases[0].duration_seconds == 2000.0


def test_auto_min_phase_scales_with_run_duration() -> None:
    assert auto_min_phase_seconds(10.0) == 60.0         # clamp to 60 s on tiny runs
    assert auto_min_phase_seconds(600.0) == 60.0         # 5 % of 600 = 30 → clamp up
    assert auto_min_phase_seconds(49000.0) == 2450.0     # 5 % of 49000 = 2450
    assert auto_min_phase_seconds(100_000.0) == 3600.0   # clamp to 1 h
