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
from ..process_catalog import catalog as _catalog
from .leak_thresholds import StackLeakProfile, for_stack
from .stats import (
    linear_regression_r2,
    linear_regression_slope,
    monotonic_nondecreasing_ratio,
    moving_average,
    plateau_fraction,
)


def _stack_for_pid(process_rows: list[dict[str, Any]], pid: int) -> str | None:
    """Pick the canonical exe name for a PID (most-frequent), look up
    its stack tag in the C2 process catalog. Returns None for unknown
    processes — caller falls back to the `native` profile."""
    counts: dict[str, int] = {}
    for r in process_rows:
        if r.get("pid") != pid:
            continue
        name = r.get("name")
        if isinstance(name, str) and name:
            counts[name] = counts.get(name, 0) + 1
    if not counts:
        return None
    canonical = max(counts.items(), key=lambda kv: kv[1])[0]
    return _catalog().stack(canonical)


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


def _sliding_window_stats(
    points: list[tuple[float, float, str]],
    *,
    window_seconds: float = 3600.0,
    stride_seconds: float = 600.0,
    min_samples: int = 30,
) -> list[dict[str, Any]]:
    """Field-review A1: per-PID sliding-window slope/R²/mono.

    The legacy `_trend_stats` regresses over the entire run. On a long
    run with a clear leak phase followed by a plateau (e.g. an 8 h
    leak in a 36 859 s capture), the post-plateau samples dilute the
    slope below the leak threshold and the candidate is missed.

    Sliding-window analysis catches the leak phase even when it's a
    minority of the run. Each window in the returned list carries
    its own slope / R² / mono / sample count so callers can pick the
    peak-slope window for grading.
    """
    if not points:
        return []
    pts = sorted(points, key=lambda p: p[0])
    t_min = pts[0][0]
    t_max = pts[-1][0]
    if t_max - t_min < window_seconds * 0.5:
        # Run shorter than half a window — sliding doesn't help.
        return []

    out: list[dict[str, Any]] = []
    t_start = t_min
    while t_start < t_max - window_seconds * 0.25:
        t_end = t_start + window_seconds
        win = [(t, v) for (t, v, _n) in pts if t_start <= t <= t_end]
        if len(win) >= min_samples:
            xs = [p[0] for p in win]
            ys = [p[1] for p in win]
            smooth = moving_average(ys, max(5, len(ys) // 20))
            slope = linear_regression_slope(xs, smooth)
            if slope is not None:
                out.append({
                    "window_start_s": round(xs[0], 2),
                    "window_end_s": round(xs[-1], 2),
                    "slope": slope,
                    "r2": linear_regression_r2(xs, smooth) or 0.0,
                    "mono": monotonic_nondecreasing_ratio(smooth),
                    "samples": len(win),
                })
        t_start += stride_seconds
    return out


def _find_plateau_start(
    windows: list[dict[str, Any]],
    growth_slope_bytes_per_s: float,
    plateau_slope_bytes_per_s: float = 10_000.0,
) -> float | None:
    """Find the first window where the slope drops below
    `plateau_slope_bytes_per_s` AFTER at least one window with slope
    >= `growth_slope_bytes_per_s`. Returns the window's start time
    (= when the leak phase ended), or None if no transition was seen.

    Default plateau threshold (10 KB/s) per field-review A1.
    """
    if not windows:
        return None
    growth_seen = False
    for w in windows:
        if w["slope"] >= growth_slope_bytes_per_s:
            growth_seen = True
        elif growth_seen and w["slope"] < plateau_slope_bytes_per_s:
            return float(w["window_start_s"])
    return None


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
    stack_profile: StackLeakProfile | None = None,
) -> str | None:
    """Given the series stats, return a confidence tier or None if the trend
    doesn't qualify.

    - slope / slope_unit = how many multiples of the "suspicious" slope threshold
    - Confidence is downgraded if R^2 is low, monotonicity weak, or the series
      has already plateaued (growth stopped).
    - Field-review C1: ``stack_profile`` tunes thresholds for managed-runtime
      saw-tooth (JVM / .NET server-GC / Chromium / V8). For unknown stacks
      the profile is `native` — same numbers as before C1.
    """
    profile = stack_profile or for_stack(None)
    # Stack-aware slope multiplier — JVM/Chromium need a much steeper
    # slope before we even consider this a candidate.
    effective_slope_unit = slope_unit * profile.slope_multiplier
    if slope < effective_slope_unit:
        return None
    # Sawtooth/GC patterns: steep slope but dips all the time -> not a leak.
    # Managed runtimes have stricter mono floors than native code.
    if mono < profile.mono_min:
        return None
    # Growth clearly stopped in the final chunk — probably a warm-up,
    # not a leak. JVM heaps reach -Xmx and STAY there by design, so
    # this guard is suppressed for those.
    if plateau >= 0.35 and not profile.plateau_is_normal:
        return None
    # Stack-specific relative-growth floor: a JVM at 4 GB that grew
    # 50 MB is rounding noise, but the same growth on a 100 MB native
    # process is a real signal.
    if growth_ratio < profile.rss_min_growth_ratio:
        return None

    ratio = slope / effective_slope_unit
    base: str
    if ratio >= 10 and growth_ratio >= thresholds.get("strong_growth", 0.5):
        base = "strong evidence"
    elif ratio >= 3 and growth_ratio >= thresholds.get("likely_growth", 0.2):
        base = "likely"
    else:
        base = "suspicious"

    # Downgrade by fit quality (stack-specific floor).
    if r2 < 0.4 and base == "strong evidence":
        base = "likely"
    if r2 < 0.25 and base == "likely":
        base = "suspicious"
    if r2 < profile.r2_min:
        return None

    # Downgrade if monotonicity is weak (borderline sawtooth)
    if mono < 0.7 and base == "strong evidence":
        base = "likely"
    if mono < 0.6 and base == "likely":
        base = "suspicious"

    return base


def _cadence_broken_fallback(
    process_rows: list[dict[str, Any]],
    th: Thresholds,
    *,
    already_flagged: set[int],
) -> list[dict[str, Any]]:
    """v1.3.3: low-sample-count fallback when the run's cadence is
    broken.

    Production scenario from ATLT4407: 28 samples over 1798 s (median
    gap 68 s, declared `cadence_health: broken`). The full-run
    regression in `_trend_stats` succeeds at 28 points, but the
    sliding-window peak-detection bails (min_samples=30 per window)
    and the resulting confidence drops to "suspicious" — and on
    runs where `_trend_stats` itself returns None (< 20 samples), the
    detector goes silent entirely. Result: a 138 MB self-leak shows
    up in the timeline but produces zero `memory_leak_candidate`
    findings — a false negative that would mislead an operator into
    "no leak found = green light".

    This fallback runs only when cadence is broken. For each PID NOT
    already flagged by the main detector, it computes a simple
    linear regression on the raw RSS series and flags clear linear
    growth with `confidence: low (cadence-degraded)`. The thresholds
    are deliberately permissive (10+ samples, 50 MB+ absolute growth,
    R² ≥ 0.6) — better conservative-positive than false-negative
    when cadence already broken.
    """
    out: list[dict[str, Any]] = []
    buckets = _series_for_pid(process_rows, "rss_bytes")
    for pid, points in buckets.items():
        if pid in already_flagged:
            continue
        if len(points) < 10:
            continue
        pts = sorted(points, key=lambda p: p[0])
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        if xs[-1] - xs[0] < th.leak_min_duration_seconds:
            continue
        slope = linear_regression_slope(xs, ys)
        if slope is None or slope <= 0:
            continue
        r2 = linear_regression_r2(xs, ys) or 0.0
        if r2 < 0.6:
            continue
        s_val = ys[0]
        e_val = ys[-1]
        growth_bytes = e_val - s_val
        # Conservative-permissive threshold: flag only on clearly
        # significant absolute growth so we don't drown the operator
        # in noisy positives on broken-cadence runs.
        if growth_bytes < 50 * 1024 * 1024:  # 50 MB floor
            continue
        name = pts[-1][2]
        dur = xs[-1] - xs[0]
        growth_ratio = (growth_bytes / s_val) if s_val > 0 else 0.0
        out.append({
            "kind": "memory_leak_candidate",
            "confidence": "low (cadence-degraded)",
            "pid": pid,
            "process_name": name,
            "stack": _stack_for_pid(process_rows, pid) or "native",
            "rss_start_mb": round(s_val / (1024 * 1024), 1),
            "rss_end_mb": round(e_val / (1024 * 1024), 1),
            "rss_peak_mb": round(max(ys) / (1024 * 1024), 1),
            "growth_mb": round(growth_bytes / (1024 * 1024), 1),
            "growth_ratio": round(growth_ratio, 2),
            "duration_s": round(dur, 1),
            "slope_bytes_per_sec": round(slope, 1),
            "r2": round(r2, 3),
            "monotonic_ratio": None,
            "plateau_fraction": None,
            "slope_source": "cadence_broken_fallback",
            "windows_evaluated": 0,
            "peak_window": None,
            "growth_phase_end_s": None,
            "description": (
                f"{name} (pid {pid}) RSS grew {growth_bytes/1024/1024:.1f} MB "
                f"over {dur:.0f} s ({slope/1024:.1f} KB/s, R²={r2:.2f}) on "
                f"a broken-cadence run ({len(points)} samples). The main "
                f"detector requires >= 30 samples per window and was "
                f"silent — this fallback flags clear linear growth at "
                f"low confidence so the leak isn't missed entirely. "
                f"Re-capture with a working cadence to grade properly."
            ),
        })
    return sorted(out, key=lambda e: e["growth_mb"], reverse=True)


def detect_memory_leaks(
    process_rows: list[dict[str, Any]], th: Thresholds,
    *,
    cadence_health: str | None = None,
) -> list[dict[str, Any]]:
    """Detect linear RSS growth per PID.

    `cadence_health` (v1.3.3): when "broken", runs an additional
    permissive fallback pass for PIDs the main detector missed due
    to too-few samples. Pass-through `None` reproduces v1.3.2
    behaviour exactly.
    """
    out: list[dict[str, Any]] = []
    buckets = _series_for_pid(process_rows, "rss_bytes")
    for pid, points in buckets.items():
        stats = _trend_stats(points)
        if stats is None or stats["duration"] < th.leak_min_duration_seconds:
            continue
        s_val = stats["start_val"]
        e_val = stats["end_val"]
        dur = stats["duration"]
        name = stats["name"]
        growth_bytes = max(0.0, e_val - s_val)
        stack = _stack_for_pid(process_rows, pid)
        profile = for_stack(stack)
        if growth_bytes < profile.rss_min_growth_mb * 1024 * 1024:
            continue
        growth_ratio = (growth_bytes / s_val) if s_val > 0 else 0.0

        # Field-review A1: sliding-window analysis catches leaks that
        # the full-run regression dilutes (e.g. an 8 h leak followed
        # by a 2 h plateau in a 10 h capture). If the peak window's
        # slope is steeper than the full-run slope, grade by IT — the
        # full-run number is the "average" and hides the leak phase.
        windows = _sliding_window_stats(points)
        peak_window: dict[str, Any] | None = None
        if windows:
            peak_window = max(windows, key=lambda w: w["slope"])

        if peak_window and peak_window["slope"] > stats["slope"]:
            grading_slope = peak_window["slope"]
            grading_r2 = peak_window["r2"]
            grading_mono = peak_window["mono"]
            # The peak window represents the growth phase explicitly,
            # so the full-run plateau heuristic doesn't apply. Pass
            # 0 so it never disqualifies — we already isolated growth.
            grading_plateau = 0.0
            primary_source = "peak_window"
        else:
            grading_slope = stats["slope"]
            grading_r2 = stats["r2"]
            grading_mono = stats["mono"]
            grading_plateau = stats["plateau"]
            primary_source = "full_run"

        confidence = _grade_confidence(
            slope=grading_slope,
            slope_unit=th.leak_min_slope_bytes_per_sec,
            r2=grading_r2,
            mono=grading_mono,
            plateau=grading_plateau,
            growth_ratio=growth_ratio,
            end_val=e_val,
            thresholds={"strong_growth": 0.5, "likely_growth": 0.2},
            stack_profile=profile,
        )
        if confidence is None:
            continue

        # When did the leak phase end? Annotate the transition point
        # for the operator (only set when we found a real growth →
        # plateau transition).
        growth_phase_end_s = _find_plateau_start(
            windows,
            growth_slope_bytes_per_s=th.leak_min_slope_bytes_per_sec
                                     * profile.slope_multiplier,
        ) if windows else None

        finding: dict[str, Any] = {
            "kind": "memory_leak_candidate",
            "confidence": confidence,
            "pid": pid,
            "process_name": name,
            "stack": stack or "native",
            "rss_start_mb": round(s_val / (1024 * 1024), 1),
            "rss_end_mb": round(e_val / (1024 * 1024), 1),
            "rss_peak_mb": round(stats["peak_val"] / (1024 * 1024), 1),
            "growth_mb": round(growth_bytes / (1024 * 1024), 1),
            "growth_ratio": round(growth_ratio, 2),
            "duration_s": round(dur, 1),
            "slope_bytes_per_sec": round(grading_slope, 1),
            "r2": round(grading_r2, 3),
            "monotonic_ratio": round(grading_mono, 3),
            "plateau_fraction": round(stats["plateau"], 3),
            # Field-review A1: provenance + sliding-window detail.
            "slope_source": primary_source,
            "windows_evaluated": len(windows),
            "peak_window": (
                {
                    "start_s": peak_window["window_start_s"],
                    "end_s": peak_window["window_end_s"],
                    "slope_bytes_per_sec": round(peak_window["slope"], 1),
                    "r2": round(peak_window["r2"], 3),
                    "samples": peak_window["samples"],
                }
                if peak_window else None
            ),
            "growth_phase_end_s": (
                round(growth_phase_end_s, 1) if growth_phase_end_s is not None
                else None
            ),
        }
        if peak_window:
            finding["description"] = (
                f"{name} (pid {pid}, stack={stack or 'native'}) RSS grew from "
                f"{s_val/1024/1024:.1f}MB to {e_val/1024/1024:.1f}MB over "
                f"{dur:.0f}s. Peak growth-window "
                f"{peak_window['window_start_s']:.0f}–"
                f"{peak_window['window_end_s']:.0f} s at "
                f"{peak_window['slope']/1024:.1f} KB/s "
                f"(R²={peak_window['r2']:.2f})"
                + (f"; plateaued at {growth_phase_end_s:.0f} s"
                   if growth_phase_end_s is not None else "")
                + f". Confidence: {confidence}."
            )
        else:
            finding["description"] = (
                f"{name} (pid {pid}, stack={stack or 'native'}) RSS grew from "
                f"{s_val/1024/1024:.1f}MB to {e_val/1024/1024:.1f}MB over "
                f"{dur:.0f}s (slope {grading_slope/1024:.1f} KB/s, "
                f"R²={grading_r2:.2f}, monotonic={grading_mono*100:.0f}%). "
                f"Confidence: {confidence}."
            )
        out.append(finding)

    # v1.3.3: cadence-broken fallback for PIDs the main detector missed.
    # Skipped on healthy cadence — keeps the historical behaviour identical.
    if cadence_health == "broken":
        already = {f["pid"] for f in out}
        out.extend(_cadence_broken_fallback(
            process_rows, th, already_flagged=already,
        ))

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
        stack = _stack_for_pid(process_rows, pid)
        profile = for_stack(stack)
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
            stack_profile=profile,
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
            "stack": stack or "native",
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
        stack = _stack_for_pid(process_rows, pid)
        profile = for_stack(stack)
        confidence = _grade_confidence(
            slope=per_min,
            slope_unit=th.thread_growth_per_min_suspicious,
            r2=stats["r2"],
            mono=stats["mono"],
            plateau=stats["plateau"],
            growth_ratio=growth_ratio,
            end_val=e_val,
            thresholds={"strong_growth": 0.5, "likely_growth": 0.2},
            stack_profile=profile,
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
            "stack": stack or "native",
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
    process_rows: list[dict[str, Any]], th: Thresholds,
    *,
    cadence_health: str | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Detect memory / handle / thread leak patterns.

    `cadence_health` (v1.3.3): forwarded to `detect_memory_leaks` so the
    cadence-broken fallback can fire on degraded runs. Default `None`
    reproduces pre-v1.3.3 behaviour.
    """
    return {
        "memory": detect_memory_leaks(
            process_rows, th, cadence_health=cadence_health,
        ),
        "handles": detect_handle_leaks(process_rows, th),
        "threads": detect_thread_leaks(process_rows, th),
    }
