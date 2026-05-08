"""Plateau / deadlock detection (Field-review A2).

Companion to the A1 sliding-window leak detector. Where A1 says "this
process is leaking", A2 says "this process leaked, then went idle —
likely deadlocked or hung". The pattern is generic across managed and
unmanaged runtimes:

    RSS growth ≥ X KB/s for ≥ 1 hour
                   THEN
    RSS slope < 10 KB/s AND cpu_pct < 5 % for ≥ 10 minutes

A real working application that DOESN'T leak doesn't show the first
phase. A leak that's still actively progressing doesn't show the
second. This signature catches the specific failure mode the field
review surfaced on the MotoDB analysis: a worker leaks, hits a
condition that wedges it, and just sits there until the supervisor
either kills it or the operator notices the queue stuck.

The detector emits its own finding type (`deadlock_suspected`) so
report consumers can prioritise it: a leak alone is "investigate",
a deadlock-after-leak is "this is your bug".
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..config import Thresholds
from ..process_catalog import catalog as _catalog
from .leak_thresholds import for_stack
from .stats import linear_regression_r2, linear_regression_slope, mean

# Per-window granularity for the deadlock detector. Smaller than the
# A1 leak window because the field review's transition criterion is
# "≥ 10 minutes" — we need enough resolution to confirm a 10-min
# plateau without averaging it into a longer growth trail.
_WINDOW_S = 600.0       # 10 minutes
_STRIDE_S = 300.0       # 5 minutes
_MIN_SAMPLES_PER_WINDOW = 30


def _paired_series(
    process_rows: list[dict[str, Any]],
) -> dict[int, list[tuple[float, float, float, str]]]:
    """Return pid -> [(rel_seconds, rss_bytes, cpu_pct, name)]."""
    buckets: dict[int, list[tuple[float, float, float, str]]] = defaultdict(list)
    for r in process_rows:
        pid = r.get("pid")
        rel = r.get("rel_seconds")
        rss = r.get("rss_bytes")
        cpu = r.get("cpu_pct")
        name = r.get("name") or "?"
        if pid is None or rel is None or rss is None or cpu is None:
            continue
        buckets[pid].append((float(rel), float(rss), float(cpu), name))
    return buckets


def _windows_with_cpu(
    points: list[tuple[float, float, float, str]],
    *,
    window_seconds: float = _WINDOW_S,
    stride_seconds: float = _STRIDE_S,
    min_samples: int = _MIN_SAMPLES_PER_WINDOW,
) -> list[dict[str, Any]]:
    """Slide over the (rel, rss, cpu) series, emitting per-window
    rss-slope + mean cpu_pct + R² stats."""
    if not points:
        return []
    pts = sorted(points, key=lambda p: p[0])
    t_min = pts[0][0]
    t_max = pts[-1][0]
    if t_max - t_min < window_seconds * 0.5:
        return []

    out: list[dict[str, Any]] = []
    t_start = t_min
    while t_start < t_max - window_seconds * 0.25:
        t_end = t_start + window_seconds
        win = [(t, r, c) for (t, r, c, _n) in pts if t_start <= t <= t_end]
        if len(win) >= min_samples:
            xs = [p[0] for p in win]
            ys = [p[1] for p in win]
            cpus = [p[2] for p in win]
            slope = linear_regression_slope(xs, ys)
            if slope is not None:
                out.append({
                    "window_start_s": round(xs[0], 2),
                    "window_end_s": round(xs[-1], 2),
                    "rss_slope_bytes_per_sec": slope,
                    "rss_r2": linear_regression_r2(xs, ys) or 0.0,
                    "mean_cpu_pct": mean(cpus) or 0.0,
                    "samples": len(win),
                })
        t_start += stride_seconds
    return out


def _find_sustained_growth(
    windows: list[dict[str, Any]],
    *,
    slope_min_bytes_per_sec: float,
    min_consecutive: int,
) -> list[dict[str, Any]] | None:
    """Find the first run of `min_consecutive` consecutive windows whose
    slope stays at or above `slope_min_bytes_per_sec`. Returns the
    matching window list, or None if no sustained growth was seen."""
    streak: list[dict[str, Any]] = []
    for w in windows:
        if w["rss_slope_bytes_per_sec"] >= slope_min_bytes_per_sec:
            streak.append(w)
            if len(streak) >= min_consecutive:
                return list(streak)
        else:
            streak = []
    return None


def _find_post_growth_plateau(
    windows: list[dict[str, Any]],
    *,
    slope_max_bytes_per_sec: float,
    cpu_max_pct: float,
    min_consecutive: int,
) -> list[dict[str, Any]] | None:
    """Walk forward until we find `min_consecutive` consecutive windows
    that are simultaneously low-slope AND low-cpu. Returns the
    matching window list, or None."""
    streak: list[dict[str, Any]] = []
    for w in windows:
        if (w["rss_slope_bytes_per_sec"] < slope_max_bytes_per_sec
                and w["mean_cpu_pct"] < cpu_max_pct):
            streak.append(w)
            if len(streak) >= min_consecutive:
                return list(streak)
        else:
            streak = []
    return None


def detect_deadlocks(
    process_rows: list[dict[str, Any]], th: Thresholds,
) -> list[dict[str, Any]]:
    """Return one finding per PID that matches the
    growth-then-cpu-drop signature.

    Default constants come from the field review's recommendation:
    ≥ 1 h of growth at ≥ 50 KB/s, ≥ 10 min of plateau with cpu < 5 %.
    Stack-aware: the growth threshold is multiplied by the stack's
    slope_multiplier (so a JVM doesn't trip on its normal heap ramp).
    """
    out: list[dict[str, Any]] = []
    series = _paired_series(process_rows)

    growth_windows_required = max(int(3600 / _STRIDE_S), 6)   # ≥ 1 hour
    plateau_windows_required = max(int(600 / _STRIDE_S), 2)   # ≥ 10 minutes

    for pid, points in series.items():
        if len(points) < _MIN_SAMPLES_PER_WINDOW * 4:
            continue

        # Resolve stack for stack-aware growth threshold (C1 reuse).
        canonical_name = _canonical_name(points)
        stack = _catalog().stack(canonical_name)
        profile = for_stack(stack)
        growth_slope_min = (
            th.leak_min_slope_bytes_per_sec * profile.slope_multiplier
        )

        windows = _windows_with_cpu(points)
        if not windows:
            continue

        growth = _find_sustained_growth(
            windows,
            slope_min_bytes_per_sec=growth_slope_min,
            min_consecutive=growth_windows_required,
        )
        if growth is None:
            continue

        # Plateau search starts strictly AFTER the growth phase.
        post_growth_idx = windows.index(growth[-1]) + 1
        plateau = _find_post_growth_plateau(
            windows[post_growth_idx:],
            slope_max_bytes_per_sec=10_000.0,
            cpu_max_pct=5.0,
            min_consecutive=plateau_windows_required,
        )
        if plateau is None:
            continue

        g_start = growth[0]["window_start_s"]
        g_end = growth[-1]["window_end_s"]
        p_start = plateau[0]["window_start_s"]
        p_end = plateau[-1]["window_end_s"]
        g_slope_avg = mean(w["rss_slope_bytes_per_sec"] for w in growth) or 0.0
        g_r2_avg = mean(w["rss_r2"] for w in growth) or 0.0
        p_slope_avg = mean(w["rss_slope_bytes_per_sec"] for w in plateau) or 0.0
        p_cpu_avg = mean(w["mean_cpu_pct"] for w in plateau) or 0.0

        rss_at_growth_start = _value_at(points, g_start)
        rss_at_plateau_start = _value_at(points, p_start)

        out.append({
            "kind": "deadlock_suspected",
            "pid": pid,
            "process_name": canonical_name,
            "stack": stack or "native",
            "growth_phase": {
                "start_s": round(g_start, 1),
                "end_s": round(g_end, 1),
                "duration_s": round(g_end - g_start, 1),
                "mean_slope_bytes_per_sec": round(g_slope_avg, 1),
                "mean_r2": round(g_r2_avg, 3),
                "rss_at_start_mb": round(rss_at_growth_start / (1024 * 1024), 1),
            },
            "plateau_phase": {
                "start_s": round(p_start, 1),
                "end_s": round(p_end, 1),
                "duration_s": round(p_end - p_start, 1),
                "mean_slope_bytes_per_sec": round(p_slope_avg, 1),
                "mean_cpu_pct": round(p_cpu_avg, 2),
                "rss_at_start_mb": round(rss_at_plateau_start / (1024 * 1024), 1),
            },
            "description": (
                f"{canonical_name} (pid {pid}, stack={stack or 'native'}) "
                f"accumulated RSS at {g_slope_avg / 1024:.0f} KB/s from "
                f"{g_start:.0f} s to {g_end:.0f} s, then went idle "
                f"({p_cpu_avg:.1f}% CPU, slope "
                f"{p_slope_avg / 1024:.1f} KB/s) "
                f"from {p_start:.0f} s onward — possible deadlock or "
                f"hung worker."
            ),
        })

    return sorted(out, key=lambda d: d["growth_phase"]["duration_s"], reverse=True)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _canonical_name(points: list[tuple[float, float, float, str]]) -> str:
    counts: dict[str, int] = {}
    for _t, _r, _c, n in points:
        counts[n] = counts.get(n, 0) + 1
    if not counts:
        return "?"
    return max(counts.items(), key=lambda kv: kv[1])[0]


def _value_at(
    points: list[tuple[float, float, float, str]],
    target_t: float,
) -> float:
    """Nearest-RSS value for the given rel_seconds. Fast linear scan
    is fine — the deadlock detector runs once per PID."""
    if not points:
        return 0.0
    best = points[0]
    best_delta = abs(points[0][0] - target_t)
    for p in points:
        d = abs(p[0] - target_t)
        if d < best_delta:
            best = p
            best_delta = d
    return best[1]
