"""Tests for slowdown-window detection + merging."""

from __future__ import annotations

from sysspecter.analyzer.slowdowns import detect_slowdown_windows
from sysspecter.config import Thresholds


def _row(rel: float, cpu: float = 10, mem: float = 40, disk: float = 0) -> dict:
    return {
        "rel_seconds": rel,
        "cpu_total_pct": cpu,
        "mem_percent": mem,
        "disk_active_pct_est": disk,
        "swap_percent": 0.0,
        "cpu_per_core_pct": [cpu],
    }


def test_no_slowdown_on_idle_run() -> None:
    rows = [_row(t) for t in range(120)]
    out = detect_slowdown_windows(rows, process_rows=[],
                                  latency_rows=[], th=Thresholds())
    assert out == []


def test_high_cpu_window_is_detected() -> None:
    # 15 s at 95% CPU surrounded by idle
    rows = [_row(t, cpu=10) for t in range(0, 30)]
    rows += [_row(t, cpu=95) for t in range(30, 50)]
    rows += [_row(t, cpu=10) for t in range(50, 80)]
    out = detect_slowdown_windows(rows, process_rows=[],
                                  latency_rows=[], th=Thresholds())
    assert out, "CPU pressure window should be detected"
    slow = out[0]
    assert slow["duration_s"] >= 10
    assert slow["peak_cpu_pct"] >= 90


def test_short_window_dropped() -> None:
    # 2s spike - below the 3s minimum duration
    rows = [_row(t, cpu=10) for t in range(30)]
    rows += [_row(t, cpu=95) for t in range(30, 32)]
    rows += [_row(t, cpu=10) for t in range(32, 60)]
    out = detect_slowdown_windows(rows, process_rows=[],
                                  latency_rows=[], th=Thresholds())
    assert out == []


def test_adjacent_windows_merge() -> None:
    # Two high-CPU blocks separated by a 2s gap (<= 5s merge window)
    rows = [_row(t, cpu=10) for t in range(20)]
    rows += [_row(t, cpu=95) for t in range(20, 40)]
    rows += [_row(t, cpu=10) for t in range(40, 42)]
    rows += [_row(t, cpu=95) for t in range(42, 60)]
    rows += [_row(t, cpu=10) for t in range(60, 80)]
    out = detect_slowdown_windows(rows, process_rows=[],
                                  latency_rows=[], th=Thresholds())
    # We expect ONE merged window, not two
    assert len(out) == 1
    assert out[0]["duration_s"] >= 35


def test_confidence_tier_scales_with_evidence() -> None:
    rows = [_row(t, cpu=10) for t in range(10)]
    # Long window with CPU + memory both high = multiple reasons
    rows += [_row(t, cpu=95, mem=92) for t in range(10, 40)]
    rows += [_row(t, cpu=10) for t in range(40, 60)]
    out = detect_slowdown_windows(rows, process_rows=[],
                                  latency_rows=[], th=Thresholds())
    assert out
    # Long duration + 2 reasons -> 'strong evidence'
    assert out[0]["confidence"] in ("strong evidence", "likely")
