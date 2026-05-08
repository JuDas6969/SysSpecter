"""Field-review A2: deadlock-after-leak detection.

Pins the contract that a process showing the canonical
"RSS grew steadily, then RSS flat AND CPU near zero" signature is
flagged as `deadlock_suspected`. This catches the specific failure
mode the field review surfaced on the MotoDB analysis (a leaking
worker hits a wedge condition and just sits there).

Tests cover:

- A clean growth-then-deadlock series IS flagged with both phases
  correctly bounded (start / end / duration).
- A leak that's STILL ACTIVELY GROWING at end-of-run is NOT flagged
  as deadlock (no plateau).
- A flat-from-the-start series is NOT flagged (no growth phase).
- A process that's busy-but-flat (high CPU, flat RSS) is NOT flagged
  (CPU != idle).
- A growth phase shorter than 1 hour does NOT qualify.
- A plateau shorter than 10 minutes does NOT qualify.
- Findings carry both phases' aggregate stats so the operator can
  point at the data that supports the call.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from sysspecter import process_catalog as pc
from sysspecter.analyzer.deadlocks import detect_deadlocks
from sysspecter.config import Thresholds


def _empty_catalog() -> None:
    """Force the catalog into a known state — every test process
    classifies as native so the C1 stack-multiplier doesn't change
    the bar mid-test."""
    tmp = Path(tempfile.mkdtemp()) / "cat.json"
    tmp.write_text(json.dumps({"version": 1, "entries": []}),
                   encoding="utf-8")
    with patch.object(pc, "_candidate_paths", return_value=[str(tmp)]):
        pc.reload()


def _row(pid: int, name: str, rel: float,
         rss_mb: float, cpu_pct: float) -> dict:
    return {
        "pid": pid, "name": name, "rel_seconds": rel,
        "rss_bytes": rss_mb * 1024 * 1024,
        "cpu_pct": cpu_pct,
        "num_handles": 100, "num_threads": 10,
    }


def _series(pid: int, name: str,
            phases: list[tuple[float, float, float, float]]) -> list[dict]:
    """phases: [(duration_s, start_rss_mb, end_rss_mb, mean_cpu_pct)] —
    each phase emits one sample/sec over its duration with linear RSS
    interpolation and constant cpu."""
    out = []
    rel = 0.0
    for duration, start_rss, end_rss, cpu in phases:
        n = int(duration)
        for i in range(n):
            t = rel + i
            if n > 1:
                rss = start_rss + (end_rss - start_rss) * (i / (n - 1))
            else:
                rss = start_rss
            out.append(_row(pid, name, t, rss, cpu))
        rel += duration
    return out


# ----------------------------------------------------- happy path


def test_clean_deadlock_pattern_is_flagged() -> None:
    """4500 s (75 min) of clean RSS growth + 900 s (15 min) of low
    CPU + flat RSS = the canonical A2 signature."""
    _empty_catalog()
    # Phase 1: 4500 s, 100 → 450 MB (slope ~ 80 KB/s), 30% CPU
    # Phase 2: 900 s, flat 450 MB, 1% CPU
    rows = _series(4242, "MotoDB.exe", [
        (4500, 100, 450, 30.0),
        (900,  450, 450,  1.0),
    ])
    findings = detect_deadlocks(rows, Thresholds())
    assert len(findings) == 1, f"expected 1 deadlock finding, got {findings}"
    f = findings[0]
    assert f["kind"] == "deadlock_suspected"
    assert f["pid"] == 4242
    assert f["process_name"] == "MotoDB.exe"
    g = f["growth_phase"]
    p = f["plateau_phase"]
    assert g["duration_s"] >= 3600        # ≥ 1 h growth
    assert p["duration_s"] >= 600         # ≥ 10 min plateau
    assert p["mean_cpu_pct"] < 5.0
    assert g["mean_slope_bytes_per_sec"] > 50_000   # well above threshold
    assert "deadlock" in f["description"].lower() or "hung" in f["description"].lower()


def test_finding_carries_both_phase_boundaries() -> None:
    _empty_catalog()
    rows = _series(4242, "X.exe", [
        (4500, 100, 450, 25.0),
        (900,  450, 450,  2.0),
    ])
    f = detect_deadlocks(rows, Thresholds())[0]
    g = f["growth_phase"]
    p = f["plateau_phase"]
    # Boundaries are monotonic and contiguous (plateau starts at or
    # after growth end).
    assert g["start_s"] < g["end_s"]
    assert p["start_s"] >= g["end_s"] - 1   # within rounding


# ----------------------------------------------------- false-positive guards


def test_active_leak_without_plateau_is_not_flagged() -> None:
    """A leak that's STILL growing when the run ends is a leak, not
    a deadlock — the dedicated leak detector handles it."""
    _empty_catalog()
    rows = _series(4242, "leaker.exe", [
        (5400, 100, 600, 30.0),     # 90 min of clean growth
    ])
    assert detect_deadlocks(rows, Thresholds()) == []


def test_pure_plateau_is_not_flagged() -> None:
    """Process that NEVER grew can't be 'deadlocked after a leak'."""
    _empty_catalog()
    rows = _series(4242, "idle.exe", [
        (5400, 200, 200, 1.0),
    ])
    assert detect_deadlocks(rows, Thresholds()) == []


def test_busy_flat_rss_is_not_flagged() -> None:
    """A worker that's hot but isn't growing isn't deadlocked — CPU
    floor of 5% must rule this out even if RSS is flat."""
    _empty_catalog()
    rows = _series(4242, "worker.exe", [
        (4500, 100, 450, 30.0),
        (900,  450, 450, 50.0),     # plateau but high CPU
    ])
    assert detect_deadlocks(rows, Thresholds()) == []


def test_growth_phase_shorter_than_1h_does_not_qualify() -> None:
    _empty_catalog()
    rows = _series(4242, "short.exe", [
        (1800, 100, 300, 30.0),     # only 30 min growth
        (900,  300, 300,  1.0),
    ])
    assert detect_deadlocks(rows, Thresholds()) == []


def test_plateau_shorter_than_10min_does_not_qualify() -> None:
    _empty_catalog()
    rows = _series(4242, "trail.exe", [
        (4500, 100, 450, 30.0),
        (300,  450, 450,  1.0),     # 5 min plateau
    ])
    assert detect_deadlocks(rows, Thresholds()) == []


def test_too_few_samples_does_not_crash() -> None:
    """Edge case: short run, < min_samples_per_window. Must return []
    instead of raising."""
    _empty_catalog()
    rows = _series(4242, "tiny.exe", [(60, 100, 110, 10.0)])
    assert detect_deadlocks(rows, Thresholds()) == []
