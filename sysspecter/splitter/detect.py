"""Change-point detection on the system + process timelines.

Approach:
- Scan each primary metric (CPU, memory, disk) SEPARATELY plus the combined
  intensity. Emit step-shift and slope-shift candidates per metric, so a
  regime change that is visible on one metric (e.g. memory going from
  rising to flat) is not smeared out by the others.
- Detect "workload_end" when the activity drops from elevated to quiet
  for a sustained period.
- Detect "process_end" strictly: only for processes that peaked at >= 40%
  CPU AND were active for >= 120 s; keep the strongest handful.
- Window size, step threshold, and min_phase_seconds auto-scale with the
  total run duration: a 10-minute run needs tight windows, a 13-hour run
  needs ~10-minute windows to stop treating every sample as noise.
- Merge candidates within a proximity window, keeping the strongest.
- Drop candidates whose surrounding phase would be shorter than
  min_phase_seconds.

Every candidate carries a reason + evidence string so the downstream UX
can show *why* a split happened.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ChangePoint:
    rel_seconds: float
    reason: str
    kind: str           # "step" | "slope" | "quiet" | "process_end"
    evidence: str       # short human sentence
    score: float        # magnitude of the change (higher = stronger)


def _ema(values: list[float], alpha: float) -> list[float]:
    if not values:
        return []
    out = [values[0]]
    for v in values[1:]:
        out.append(alpha * v + (1 - alpha) * out[-1])
    return out


def _extract_series(system_rows: list[dict[str, Any]]) -> dict[str, tuple[list[float], list[float]]]:
    xs: list[float] = []
    cpu_y: list[float] = []
    mem_y: list[float] = []
    disk_y: list[float] = []
    for r in system_rows:
        rel = r.get("rel_seconds")
        if rel is None:
            continue
        xs.append(float(rel))
        cpu_y.append(float(r.get("cpu_total_pct") or 0.0))
        mem_y.append(float(r.get("mem_percent") or 0.0))
        disk_y.append(float(r.get("disk_active_pct_est") or 0.0))
    intensity = [0.5 * c + 0.3 * m + 0.2 * d
                 for c, m, d in zip(cpu_y, mem_y, disk_y, strict=False)]
    return {
        "cpu": (xs, cpu_y),
        "mem": (xs, mem_y),
        "disk": (xs, disk_y),
        "intensity": (xs, intensity),
    }


def _mean(vals: list[float]) -> float:
    return sum(vals) / len(vals) if vals else 0.0


def _auto_window_samples(xs: list[float], window_seconds: float | None) -> tuple[int, float]:
    """Pick a sample-count window. Uses explicit window_seconds if given, else
    auto-scales to ~2% of the run's total duration (clipped 30s..600s).

    Average sample spacing is derived from total_duration / (n-1) rather
    than the first two samples, because an initial jitter at run start
    can easily mislead a first-pair estimate on a long run.
    """
    if len(xs) < 2:
        return (0, 1.0)
    total = xs[-1] - xs[0]
    dt = total / max(1, len(xs) - 1)
    if dt <= 0:
        dt = 1.0
    if window_seconds is None:
        window_seconds = max(30.0, min(600.0, total * 0.02))
    w = max(3, int(window_seconds / dt))
    return w, dt


def _detect_step_per_metric(
    name: str,
    xs: list[float],
    ys_smooth: list[float],
    window: int,
    step_threshold: float,
    slope_threshold: float,
) -> list[ChangePoint]:
    """Flag step (mean shift) and slope (derivative change) events in one metric."""
    out: list[ChangePoint] = []
    n = len(xs)
    if n < 2 * window + 2:
        return out

    for i in range(window, n - window):
        left = ys_smooth[i - window:i]
        right = ys_smooth[i:i + window]
        left_mean = _mean(left)
        right_mean = _mean(right)
        delta = right_mean - left_mean

        if abs(delta) >= step_threshold:
            direction = "up" if delta > 0 else "down"
            out.append(ChangePoint(
                rel_seconds=xs[i],
                reason=f"{name}_step_{direction}",
                kind="step",
                evidence=(f"{name} mean shifted from {left_mean:.1f} to {right_mean:.1f} "
                          f"across +/-{int(window)}s"),
                score=abs(delta),
            ))
            continue

        if len(left) >= 2 and len(right) >= 2:
            left_slope = (left[-1] - left[0]) / max(window, 1)
            right_slope = (right[-1] - right[0]) / max(window, 1)
            slope_delta = right_slope - left_slope
            if abs(slope_delta) >= slope_threshold:
                if left_slope > 0 and abs(right_slope) < 0.25 * abs(left_slope):
                    reason_kind = "rising_to_flat"
                elif left_slope < 0 and abs(right_slope) < 0.25 * abs(left_slope):
                    reason_kind = "falling_to_flat"
                elif abs(left_slope) < 0.25 * abs(right_slope) and right_slope > 0:
                    reason_kind = "flat_to_rising"
                elif left_slope > 0 and right_slope < 0:
                    reason_kind = "rising_to_falling"
                elif left_slope < 0 and right_slope > 0:
                    reason_kind = "falling_to_rising"
                else:
                    reason_kind = "slope_shift"
                out.append(ChangePoint(
                    rel_seconds=xs[i],
                    reason=f"{name}_{reason_kind}",
                    kind="slope",
                    evidence=(f"{name} slope change {left_slope:+.2f} -> {right_slope:+.2f} "
                              f"(delta {slope_delta:+.2f}/s)"),
                    score=abs(slope_delta) * 20.0,
                ))
    return out


def _detect_inflections(
    name: str,
    xs: list[float],
    ys_smooth: list[float],
    window: int,
    min_change: float,
) -> list[ChangePoint]:
    """Detect 'rising-then-flat' / 'falling-then-flat' inflection points.

    Compares the cumulative change across the left window to that of the
    right window. When the left moved strongly and the right is basically
    flat (< 20% of left's motion), that is the regime boundary. This is
    the classic fill-up-then-plateau pattern that slope thresholds miss
    on very slow signals.
    """
    out: list[ChangePoint] = []
    n = len(xs)
    if n < 2 * window + 2:
        return out
    for i in range(window, n - window):
        left_change = ys_smooth[i] - ys_smooth[i - window]
        right_change = ys_smooth[i + window - 1] - ys_smooth[i]
        if abs(left_change) < min_change:
            continue
        if abs(right_change) >= 0.25 * abs(left_change):
            continue
        direction = "rising" if left_change > 0 else "falling"
        out.append(ChangePoint(
            rel_seconds=xs[i],
            reason=f"{name}_{direction}_to_flat",
            kind="slope",
            evidence=(f"{name} {direction} by {abs(left_change):.1f} points then flattened "
                      f"(right window moved only {right_change:+.1f})"),
            score=abs(left_change) * 2.0,
        ))
    return out


def _detect_quiet_periods(
    xs: list[float],
    ys_smooth: list[float],
    window: int,
    active_threshold: float,
    quiet_threshold: float,
) -> list[ChangePoint]:
    out: list[ChangePoint] = []
    n = len(xs)
    if n < 2 * window + 2:
        return out
    for i in range(window, n - window):
        prev = ys_smooth[i - window:i]
        post = ys_smooth[i:i + window]
        if _mean(prev) >= active_threshold and _mean(post) <= quiet_threshold:
            out.append(ChangePoint(
                rel_seconds=xs[i],
                reason="workload_end",
                kind="quiet",
                evidence=(f"activity dropped from {_mean(prev):.1f} to {_mean(post):.1f} "
                          f"- looks like a workload finished"),
                score=_mean(prev) - _mean(post),
            ))
    return out


def _detect_process_ends(
    process_rows: list[dict[str, Any]],
    *,
    drop_threshold: float = 10.0,
    min_peak_cpu: float = 40.0,
    min_active_seconds: float = 120.0,
    max_results: int = 5,
) -> list[ChangePoint]:
    """Only flag a process-end when the process was really significant:
    peak CPU >= min_peak_cpu AND it spent min_active_seconds above
    drop_threshold. Then we keep only the top max_results by score so a
    13-hour desktop run doesn't emit dozens of these."""
    series: dict[int, dict[str, Any]] = {}
    for r in process_rows:
        pid = r.get("pid")
        if pid is None:
            continue
        rel = r.get("rel_seconds")
        if rel is None:
            continue
        e = series.setdefault(int(pid), {"name": r.get("name") or "?", "xs": [], "ys": []})
        e["xs"].append(float(rel))
        try:
            e["ys"].append(float(r.get("cpu_pct") or 0.0))
        except (TypeError, ValueError):
            e["ys"].append(0.0)

    candidates: list[tuple[float, ChangePoint]] = []
    for pid, s in series.items():
        xs = s["xs"]
        ys = s["ys"]
        if len(xs) < 4:
            continue
        peak = max(ys) if ys else 0.0
        if peak < min_peak_cpu:
            continue
        # sum time above drop_threshold
        if len(xs) >= 2:
            dt = max(0.1, xs[1] - xs[0])
        else:
            dt = 1.0
        active_seconds = sum(dt for v in ys if v >= drop_threshold)
        if active_seconds < min_active_seconds:
            continue
        # find last index where cpu >= drop_threshold, then the end-rel
        last_active_idx = -1
        for i, v in enumerate(ys):
            if v >= drop_threshold:
                last_active_idx = i
        if last_active_idx < 0 or last_active_idx >= len(xs) - 1:
            continue
        end_rel = xs[last_active_idx]
        tail = xs[-1] - end_rel
        if tail < min_active_seconds:
            continue
        score = peak * (active_seconds / 60.0)
        candidates.append((score, ChangePoint(
            rel_seconds=end_rel,
            reason="process_end",
            kind="process_end",
            evidence=(f"process {s['name']} (pid {pid}) ended: "
                      f"peak {peak:.0f}%, active {active_seconds:.0f}s"),
            score=score,
        )))
    candidates.sort(key=lambda c: c[0], reverse=True)
    return [cp for _, cp in candidates[:max_results]]


def _dedupe(cps: list[ChangePoint], proximity_seconds: float) -> list[ChangePoint]:
    cps_sorted = sorted(cps, key=lambda c: c.rel_seconds)
    out: list[ChangePoint] = []
    for c in cps_sorted:
        if out and c.rel_seconds - out[-1].rel_seconds < proximity_seconds:
            # keep the stronger; prefer step/slope over process_end at a tie
            kind_rank = {"step": 3, "slope": 2, "quiet": 2, "process_end": 1}
            cur_score = c.score * 0.9 + kind_rank.get(c.kind, 0)
            prev_score = out[-1].score * 0.9 + kind_rank.get(out[-1].kind, 0)
            if cur_score > prev_score:
                out[-1] = c
            continue
        out.append(c)
    return out


@dataclass
class Phase:
    phase_id: int
    start_rel: float
    end_rel: float
    duration_seconds: float
    reason_at_start: str | None
    evidence_at_start: str | None


def build_phases(
    change_points: list[ChangePoint],
    total_duration: float,
    min_phase_seconds: float,
) -> list[Phase]:
    if total_duration <= 0:
        return []
    cps_sorted = sorted(change_points, key=lambda c: c.rel_seconds)

    boundaries: list[tuple[float, ChangePoint | None]] = [(0.0, None)]
    for c in cps_sorted:
        boundaries.append((c.rel_seconds, c))
    boundaries.append((total_duration, None))

    phases: list[Phase] = []
    for i in range(len(boundaries) - 1):
        start, cp = boundaries[i]
        end, _ = boundaries[i + 1]
        dur = end - start
        phases.append(Phase(
            phase_id=i + 1,
            start_rel=start,
            end_rel=end,
            duration_seconds=dur,
            reason_at_start=(cp.reason if cp else None),
            evidence_at_start=(cp.evidence if cp else None),
        ))

    # Merge short phases into the longer neighbour
    changed = True
    while changed and len(phases) > 1:
        changed = False
        for i, p in enumerate(phases):
            if p.duration_seconds >= min_phase_seconds:
                continue
            left_dur = phases[i - 1].duration_seconds if i > 0 else -1
            right_dur = phases[i + 1].duration_seconds if i < len(phases) - 1 else -1
            if left_dur >= right_dur and i > 0:
                phases[i - 1] = Phase(
                    phase_id=phases[i - 1].phase_id,
                    start_rel=phases[i - 1].start_rel,
                    end_rel=p.end_rel,
                    duration_seconds=p.end_rel - phases[i - 1].start_rel,
                    reason_at_start=phases[i - 1].reason_at_start,
                    evidence_at_start=phases[i - 1].evidence_at_start,
                )
                phases.pop(i)
            elif i < len(phases) - 1:
                phases[i + 1] = Phase(
                    phase_id=phases[i + 1].phase_id,
                    start_rel=p.start_rel,
                    end_rel=phases[i + 1].end_rel,
                    duration_seconds=phases[i + 1].end_rel - p.start_rel,
                    reason_at_start=p.reason_at_start,
                    evidence_at_start=p.evidence_at_start,
                )
                phases.pop(i)
            else:
                break
            changed = True
            break

    for i, p in enumerate(phases):
        phases[i] = Phase(
            phase_id=i + 1,
            start_rel=p.start_rel,
            end_rel=p.end_rel,
            duration_seconds=p.duration_seconds,
            reason_at_start=p.reason_at_start,
            evidence_at_start=p.evidence_at_start,
        )
    return phases


def auto_min_phase_seconds(total_duration: float) -> float:
    """Default min-phase: ~5% of total, clipped to 60..3600 s."""
    return max(60.0, min(3600.0, total_duration * 0.05))


def detect_change_points(
    system_rows: list[dict[str, Any]],
    process_rows: list[dict[str, Any]],
    *,
    window_seconds: float | None = None,
    step_threshold: float = 6.0,
    slope_threshold: float = 0.6,
    proximity_seconds: float | None = None,
) -> list[ChangePoint]:
    series = _extract_series(system_rows)
    xs = series["intensity"][0]
    if len(xs) < 4:
        return []

    total = xs[-1] - xs[0] if len(xs) >= 2 else 0
    if proximity_seconds is None:
        # a change point must be at least ~2.5% of the run apart from the next
        proximity_seconds = max(30.0, min(1800.0, total * 0.025))

    window, _dt = _auto_window_samples(xs, window_seconds)
    if window <= 0:
        return []

    # Larger window for inflection detection -- slow "fill then flat"
    # patterns need roughly 5% of the run on each side to be visible.
    inflection_window_s = max(60.0, min(3600.0, total * 0.05))
    inflection_window = max(window, int(inflection_window_s / _dt))

    out: list[ChangePoint] = []
    # Per-metric step/slope detection on a short window (captures abrupt moves).
    for name, (mxs, mys) in series.items():
        smooth = _ema(mys, alpha=0.3)
        out.extend(_detect_step_per_metric(name, mxs, smooth, window,
                                           step_threshold, slope_threshold))

    # Per-metric inflection on a longer window (captures "rising then flat").
    for name, (mxs, mys) in series.items():
        smooth = _ema(mys, alpha=0.3)
        out.extend(_detect_inflections(name, mxs, smooth, inflection_window,
                                       min_change=max(step_threshold, 5.0)))

    # Quiet periods on combined intensity only (CPU alone is too jittery).
    intensity_smooth = _ema(series["intensity"][1], alpha=0.3)
    out.extend(_detect_quiet_periods(xs, intensity_smooth, window,
                                     active_threshold=30.0, quiet_threshold=10.0))

    # Process ends: strict + top-5 only, AND must have moved the system.
    pends = _detect_process_ends(process_rows)
    pends = _filter_process_ends_by_system_impact(
        pends, xs, intensity_smooth, window, step_threshold,
    )
    out.extend(pends)

    merged = _dedupe(out, proximity_seconds)
    return merged


def _filter_process_ends_by_system_impact(
    process_ends: list[ChangePoint],
    xs: list[float],
    intensity_smooth: list[float],
    window: int,
    step_threshold: float,
) -> list[ChangePoint]:
    """Keep only process_end candidates where the SYSTEM intensity also
    dropped around the same time. A huge process ending is irrelevant to
    phase detection if the host had other equally-busy processes keeping
    the overall signal flat."""
    if not process_ends or len(xs) < 2 * window + 2:
        return []
    kept: list[ChangePoint] = []
    for cp in process_ends:
        # find the nearest system-sample index
        target = cp.rel_seconds
        idx = min(range(len(xs)), key=lambda i: abs(xs[i] - target))
        if idx < window or idx >= len(xs) - window:
            continue
        left_mean = sum(intensity_smooth[idx - window:idx]) / window
        right_mean = sum(intensity_smooth[idx:idx + window]) / window
        if abs(right_mean - left_mean) >= step_threshold * 0.8:
            cp_updated = ChangePoint(
                rel_seconds=cp.rel_seconds,
                reason=cp.reason,
                kind=cp.kind,
                evidence=(cp.evidence
                          + f"; system intensity {left_mean:.1f} -> {right_mean:.1f}"),
                score=cp.score,
            )
            kept.append(cp_updated)
    return kept


def change_point_to_dict(c: ChangePoint) -> dict[str, Any]:
    return {
        "rel_seconds": round(c.rel_seconds, 2),
        "reason": c.reason,
        "kind": c.kind,
        "evidence": c.evidence,
        "score": round(c.score, 2),
    }


def phase_to_dict(p: Phase) -> dict[str, Any]:
    return {
        "phase_id": p.phase_id,
        "start_rel": round(p.start_rel, 2),
        "end_rel": round(p.end_rel, 2),
        "duration_seconds": round(p.duration_seconds, 2),
        "reason_at_start": p.reason_at_start,
        "evidence_at_start": p.evidence_at_start,
    }
