"""Leak and trend heuristics for memory, handles, threads.

Rules:
- do not flag leaks on a single spike
- use moving averages/medians to de-noise
- use linear-regression slope to measure monotonic growth
- confidence tiers: suspicious / likely / strong evidence
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..config import Thresholds
from .stats import linear_regression_slope, moving_average


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


def _slope_and_range(points: list[tuple[float, float, str]]) -> tuple[float | None, float, float, float, str]:
    if len(points) < 20:
        return None, 0.0, 0.0, 0.0, points[-1][2] if points else "?"
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    smooth = moving_average(ys, max(5, len(ys) // 20))
    slope = linear_regression_slope(xs, smooth)
    if slope is None:
        return None, 0.0, 0.0, 0.0, points[-1][2]
    start_val = smooth[0]
    end_val = smooth[-1]
    duration = xs[-1] - xs[0] if xs[-1] > xs[0] else 1.0
    name = points[-1][2]
    return slope, start_val, end_val, duration, name


def detect_memory_leaks(
    process_rows: list[dict[str, Any]], th: Thresholds
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    buckets = _series_for_pid(process_rows, "rss_bytes")
    for pid, points in buckets.items():
        slope, s_val, e_val, dur, name = _slope_and_range(points)
        if slope is None or dur < th.leak_min_duration_seconds:
            continue
        if slope < th.leak_min_slope_bytes_per_sec:
            continue
        growth_bytes = max(0.0, e_val - s_val)
        if growth_bytes < 20 * 1024 * 1024:
            continue
        growth_ratio = (growth_bytes / s_val) if s_val > 0 else 0.0

        if slope >= th.leak_min_slope_bytes_per_sec * 10 and growth_ratio >= 0.5:
            confidence = "strong evidence"
        elif slope >= th.leak_min_slope_bytes_per_sec * 3 and growth_ratio >= 0.2:
            confidence = "likely"
        else:
            confidence = "suspicious"

        out.append({
            "kind": "memory_leak_candidate",
            "confidence": confidence,
            "pid": pid,
            "process_name": name,
            "rss_start_mb": round(s_val / (1024 * 1024), 1),
            "rss_end_mb": round(e_val / (1024 * 1024), 1),
            "growth_mb": round(growth_bytes / (1024 * 1024), 1),
            "growth_ratio": round(growth_ratio, 2),
            "duration_s": round(dur, 1),
            "slope_bytes_per_sec": round(slope, 1),
            "description": (
                f"{name} (pid {pid}) RSS grew from {s_val/1024/1024:.1f}MB to "
                f"{e_val/1024/1024:.1f}MB over {dur:.0f}s "
                f"(slope {slope/1024:.1f} KB/s). Confidence: {confidence}."
            ),
        })
    return sorted(out, key=lambda e: e["growth_mb"], reverse=True)


def detect_handle_leaks(
    process_rows: list[dict[str, Any]], th: Thresholds
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    buckets = _series_for_pid(process_rows, "num_handles")
    for pid, points in buckets.items():
        slope, s_val, e_val, dur, name = _slope_and_range(points)
        if slope is None or dur < th.leak_min_duration_seconds:
            continue
        per_min = slope * 60.0
        if per_min < th.handle_growth_per_min_suspicious:
            continue
        if e_val - s_val < 100:
            continue
        confidence = "suspicious"
        if per_min >= th.handle_growth_per_min_likely:
            confidence = "likely"
        if per_min >= th.handle_growth_per_min_likely * 3 and e_val > 5000:
            confidence = "strong evidence"
        out.append({
            "kind": "handle_leak_candidate",
            "confidence": confidence,
            "pid": pid,
            "process_name": name,
            "handles_start": int(s_val),
            "handles_end": int(e_val),
            "growth_per_min": round(per_min, 1),
            "duration_s": round(dur, 1),
            "description": (
                f"{name} (pid {pid}) handle count rose from {int(s_val)} to {int(e_val)} "
                f"({per_min:.0f}/min) over {dur:.0f}s. Confidence: {confidence}."
            ),
        })
    return sorted(out, key=lambda e: e["growth_per_min"], reverse=True)


def detect_thread_leaks(
    process_rows: list[dict[str, Any]], th: Thresholds
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    buckets = _series_for_pid(process_rows, "num_threads")
    for pid, points in buckets.items():
        slope, s_val, e_val, dur, name = _slope_and_range(points)
        if slope is None or dur < th.leak_min_duration_seconds:
            continue
        per_min = slope * 60.0
        if per_min < th.thread_growth_per_min_suspicious:
            continue
        if e_val - s_val < 20:
            continue
        confidence = "suspicious"
        if per_min >= th.thread_growth_per_min_likely:
            confidence = "likely"
        if per_min >= th.thread_growth_per_min_likely * 3:
            confidence = "strong evidence"
        out.append({
            "kind": "thread_leak_candidate",
            "confidence": confidence,
            "pid": pid,
            "process_name": name,
            "threads_start": int(s_val),
            "threads_end": int(e_val),
            "growth_per_min": round(per_min, 1),
            "duration_s": round(dur, 1),
            "description": (
                f"{name} (pid {pid}) thread count rose from {int(s_val)} to {int(e_val)} "
                f"({per_min:.1f}/min). Confidence: {confidence}."
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
