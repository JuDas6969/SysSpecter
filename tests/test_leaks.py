"""Tests for leak-trend heuristics."""

from __future__ import annotations

from sysspecter.analyzer.leaks import detect_leak_patterns
from sysspecter.config import Thresholds


def _linear_memory_growth(
    pid: int = 1234, name: str = "leaky.exe",
    start_bytes: int = 50_000_000, growth_bps: float = 100_000.0,
    duration_s: int = 240, dt: int = 1,
) -> list[dict]:
    rows = []
    for t in range(0, duration_s, dt):
        rss = int(start_bytes + growth_bps * t)
        rows.append({
            "pid": pid, "name": name, "rel_seconds": float(t),
            "rss_bytes": rss,
            "num_handles": 100, "num_threads": 8,
        })
    return rows


def test_strong_memory_leak_is_detected() -> None:
    """Monotonic growth of 100 kB/s for 4 minutes = strong evidence."""
    rows = _linear_memory_growth(growth_bps=100_000.0, duration_s=240)
    leaks = detect_leak_patterns(rows, Thresholds())
    mem = leaks.get("memory") or []
    assert mem, "should have flagged the leak"
    assert mem[0]["pid"] == 1234
    assert mem[0]["confidence"] in ("strong evidence", "likely", "suspicious")


def test_idle_process_not_flagged() -> None:
    rows = _linear_memory_growth(growth_bps=0.0, duration_s=240)
    leaks = detect_leak_patterns(rows, Thresholds())
    assert leaks.get("memory") == []


def test_short_run_not_flagged() -> None:
    # 30 seconds of growth < threshold (requires >= 120 s duration)
    rows = _linear_memory_growth(growth_bps=500_000.0, duration_s=30)
    leaks = detect_leak_patterns(rows, Thresholds())
    assert leaks.get("memory") == []


def test_tiny_slope_not_flagged() -> None:
    # 1 byte/sec for 5 minutes — well under 50 kB/s slope threshold
    rows = _linear_memory_growth(growth_bps=1.0, duration_s=300)
    leaks = detect_leak_patterns(rows, Thresholds())
    assert leaks.get("memory") == []


def test_leaks_dict_has_all_categories() -> None:
    rows = _linear_memory_growth(duration_s=240)
    leaks = detect_leak_patterns(rows, Thresholds())
    assert set(leaks.keys()) >= {"memory", "handles", "threads"}


def test_handle_leak_detected() -> None:
    # 100 handles/minute for 4 minutes -- hits "likely" tier
    rows = []
    for t in range(0, 240):
        rows.append({
            "pid": 42, "name": "handleHog.exe", "rel_seconds": float(t),
            "rss_bytes": 50_000_000,
            "num_handles": 100 + t * 2,  # 120/min = above 50/min threshold
            "num_threads": 8,
        })
    leaks = detect_leak_patterns(rows, Thresholds())
    assert leaks.get("handles"), "should flag handle growth"
