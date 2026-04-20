"""Leak and trend heuristics for memory, handles, threads.

Phase 2 upgrades:
- Compute R^2 of the best-fit line over the smoothed series to measure how
  well "monotonic growth" actually fits. True leaks have high R^2; noisy
  sawtooth workloads don't.
- Compute monotonic-nondecreasing ratio to catch sawtooth patterns that slope
  up on average but drop frequently (allocator reuse, GC cycles).
- Compute plateau fraction — if growth stopped in the last chunk of the run,
  the process is not actively leaking right now; downgrade confidence.

Rules:
- do not flag leaks on a single spike
- use moving averages/medians to de-noise
- use linear-regression slope + R^2 to measure monotonic growth
- confidence tiers: suspicious / likely / strong evidence
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..config import Thresholds
from .stats import (
    linear_regression_r2,
    linear_regression_slope,
    monotonic_nondecreasing_ratio,
    moving_average,
    plateau_fraction,
)


def _series_for_pid(
    process_rows: list[dict[str, Any]], metric: str
) -> dict[int, list[tuple[float, float, str]]]:
    """Return pid -> [(rel_seconds, value, name)]. Filters out pids with too few points."""
    buckets: dict[int, list[tuple[float, float, str]]] = defaultdict(list)
    for r in process_rows:
        pid = r.get("pid")
        rel = r.get("rel_seconds")
        v = r.get(metric)
        name = r.get("name") or "?"
        if pid is None or rel is None or v is None:
            continue
        buckets[pid].append((float(rel), float(v), name))
    return buckets


def _trend_stats(
    points: list[tuple[float, float, str]],
) -> dict[str, Any] | None:
    """Compute slope, R^2, monotonicity, plateau fraction on a smoothed series.

    Returns None if series is too short to be meaningful."""
    if len(points) < 20:
        return None
    points = sorted(points, key=lambda p: p[0])
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    smooth = moving_average(ys, max(5, len(ys) // 20))
    slope = linear_regression_slope(xs, smooth)
    if slope is None:
        return None
    r2 = linear_regression_r2(xs, smooth) or 0.0
    mono = monotonic_nondecreasing_ratio(smooth)
    plateau = plateau_fraction(smooth, tolerance_ratio=0.02)
    start_val = smooth[0]
    end_val = smooth[-1]
    peak_val = max(smooth)
    duration = xs[-1] - xs[0] if xs[-1] > xs[0] else 1.0
    name = points[-1][2]
    return {
        "slope": slope,
        "r2": r2,
        "mono": mono,
        "plateau": plateau,
        "start_val": start_val,
        "end_val": end_val,
        "peak_val": peak_val,
        "duration": duration,
        "name": name,
    }


def _grade_confidence(
    slope: float,
    slope_unit: float,
    r2: float,
    mono: float,
    plateau: float,
    growth_ratio: float,
    end_val: float,
    thresholds: dict[str, float],
) -> str | None:
    """Given the series stats, return a confidence tier or None if the trend
    doesn't qualify.

    - slope / slope_unit = how many multiples of the "suspicious" slope threshold
    - Confidence is downgraded if R^2 is low, monotonicity weak, or the series
      has already plateaued (growth stopped)."""
    if slope < slope_unit:
        return None
    # Sawtooth/GC patterns: steep slope but dips all the time -> not a leak
    if mono < 0.55:
        return None
    # Growth clearly stopped in the final chunk — probably a warm-up, not a leak
    if plateau >= 0.35:
        return None

    ratio = slope / slope_unit
    base: str
    if ratio >= 10 and growth_ratio >= thresholds.get("strong_growth", 0.5):
        base = "strong evidence"
    elif ratio >= 3 and growth_ratio >= thresholds.get("likely_growth", 0.2):
        base = "likely"
    else:
        base = "suspicious"

    # Downgrade by fit quality
    if r2 < 0.4 and base == "strong evidence":
        base = "likely"
    if r2 < 0.25 and base == "likely":
        base = "suspicious"
    if r2 < 0.15:
        return None

    # Downgrade if monotonicity is weak (borderline sawtooth)
    if mono < 0.7 and base == "strong evidence":
        base = "likely"
    if mono < 0.6 and base == "likely":
        base = "suspicious"

    return base


def detect_memory_leaks(
    process_rows: list[dict[str, Any]], th: Thresholds
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    buckets = _series_for_pid(process_rows, "rss_bytes")
    for pid, points in buckets.items():
        stats = _trend_stats(points)
        if stats is None or stats["duration"] < th.leak_min_duration_seconds:
            continue
        slope = stats["slope"]
        s_val = stats["start_val"]
        e_val = stats["end_val"]
        dur = stats["duration"]
        name = stats["name"]
        growth_bytes = max(0.0, e_val - s_val)
        if growth_bytes < 20 * 1024 * 1024:
            continue
        growth_ratio = (growth_bytes / s_val) if s_val > 0 else 0.0
        confidence = _grade_confidence(
            slope=slope,
            slope_unit=th.leak_min_slope_bytes_per_sec,
            r2=stats["r2"],
            mono=stats["mono"],
            plateau=stats["plateau"],
            growth_ratio=growth_ratio,
            end_val=e_val,
            thresholds={"strong_growth": 0.5, "likely_growth": 0.2},
        )
        if confidence is None:
            continue

        out.append({
            "kind": "memory_leak_candidate",
            "confidence": confidence,
            "pid": pid,
            "process_name": name,
            "rss_start_mb": round(s_val / (1024 * 1024), 1),
            "rss_end_mb": round(e_val / (1024 * 1024), 1),
            "rss_peak_mb": round(stats["peak_val"] / (1024 * 1024), 1),
            "growth_mb": round(growth_bytes / (1024 * 1024), 1),
            "growth_ratio": round(growth_ratio, 2),
            "duration_s": round(dur, 1),
            "slope_bytes_per_sec": round(slope, 1),
            "r2": round(stats["r2"], 3),
            "monotonic_ratio": round(stats["mono"], 3),
            "plateau_fraction": round(stats["plateau"], 3),
            "description": (
                f"{name} (pid {pid}) RSS grew from {s_val/1024/1024:.1f}MB to "
                f"{e_val/1024/1024:.1f}MB over {dur:.0f}s "
                f"(slope {slope/1024:.1f} KB/s, R²={stats['r2']:.2f}, "
                f"monotonic={stats['mono']*100:.0f}%). Confidence: {confidence}."
            ),
        })
    return sorted(out, key=lambda e: e["growth_mb"], reverse=True)


def detect_handle_leaks(
    process_rows: list[dict[str, Any]], th: Thresholds
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    buckets = _series_for_pid(process_rows, "num_handles")
    for pid, points in buckets.items():
        stats = _trend_stats(points)
        if stats is None or stats["duration"] < th.leak_min_duration_seconds:
            continue
        slope = stats["slope"]
        s_val = stats["start_val"]
        e_val = stats["end_val"]
        dur = stats["duration"]
        name = stats["name"]
        per_min = slope * 60.0
        if per_min < th.handle_growth_per_min_suspicious:
            continue
        if e_val - s_val < 100:
            continue
        growth_ratio = ((e_val - s_val) / s_val) if s_val > 0 else 0.0
        # slope unit = 1 handle / sec (per_min/60)
        confidence = _grade_confidence(
            slope=per_min,
            slope_unit=th.handle_growth_per_min_suspicious,
            r2=stats["r2"],
            mono=stats["mono"],
            plateau=stats["plateau"],
            growth_ratio=growth_ratio,
            end_val=e_val,
            thresholds={"strong_growth": 0.5, "likely_growth": 0.2},
        )
        if confidence is None:
            continue
        if per_min >= th.handle_growth_per_min_likely * 3 and e_val > 5000 and confidence != "suspicious":
            confidence = "strong evidence"
        elif per_min >= th.handle_growth_per_min_likely and confidence == "suspicious":
            confidence = "likely"

        out.append({
            "kind": "handle_leak_candidate",
            "confidence": confidence,
            "pid": pid,
            "process_name": name,
            "handles_start": int(s_val),
            "handles_end": int(e_val),
            "growth_per_min": round(per_min, 1),
            "duration_s": round(dur, 1),
            "r2": round(stats["r2"], 3),
            "monotonic_ratio": round(stats["mono"], 3),
            "plateau_fraction": round(stats["plateau"], 3),
            "description": (
                f"{name} (pid {pid}) handle count rose from {int(s_val)} to {int(e_val)} "
                f"({per_min:.0f}/min) over {dur:.0f}s "
                f"(R²={stats['r2']:.2f}, monotonic={stats['mono']*100:.0f}%). "
                f"Confidence: {confidence}."
            ),
        })
    return sorted(out, key=lambda e: e["growth_per_min"], reverse=True)


def detect_thread_leaks(
    process_rows: list[dict[str, Any]], th: Thresholds
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    buckets = _series_for_pid(process_rows, "num_threads")
    for pid, points in buckets.items():
        stats = _trend_stats(points)
        if stats is None or stats["duration"] < th.leak_min_duration_seconds:
            continue
        slope = stats["slope"]
        s_val = stats["start_val"]
        e_val = stats["end_val"]
        dur = stats["duration"]
        name = stats["name"]
        per_min = slope * 60.0
        if per_min < th.thread_growth_per_min_suspicious:
            continue
        if e_val - s_val < 20:
            continue
        growth_ratio = ((e_val - s_val) / s_val) if s_val > 0 else 0.0
        confidence = _grade_confidence(
            slope=per_min,
            slope_unit=th.thread_growth_per_min_suspicious,
            r2=stats["r2"],
            mono=stats["mono"],
            plateau=stats["plateau"],
            growth_ratio=growth_ratio,
            end_val=e_val,
            thresholds={"strong_growth": 0.5, "likely_growth": 0.2},
        )
        if confidence is None:
            continue
        if per_min >= th.thread_growth_per_min_likely * 3 and confidence != "suspicious":
            confidence = "strong evidence"
        elif per_min >= th.thread_growth_per_min_likely and confidence == "suspicious":
            confidence = "likely"

        out.append({
            "kind": "thread_leak_candidate",
            "confidence": confidence,
            "pid": pid,
            "process_name": name,
            "threads_start": int(s_val),
            "threads_end": int(e_val),
            "growth_per_min": round(per_min, 1),
            "duration_s": round(dur, 1),
            "r2": round(stats["r2"], 3),
            "monotonic_ratio": round(stats["mono"], 3),
            "plateau_fraction": round(stats["plateau"], 3),
            "description": (
                f"{name} (pid {pid}) thread count rose from {int(s_val)} to {int(e_val)} "
                f"({per_min:.1f}/min, R²={stats['r2']:.2f}). Confidence: {confidence}."
            ),
        })
    return sorted(out, key=lambda e: e["growth_per_min"], reverse=True)


def detect_leak_patterns(
    process_rows: list[dict[str, Any]], th: Thresholds
) -> dict[str, list[dict[str, Any]]]:
    return {
        "memory": detect_memory_leaks(process_rows, th),
        "handles": detect_handle_leaks(process_rows, th),
        "threads": detect_thread_leaks(process_rows, th),
    }
