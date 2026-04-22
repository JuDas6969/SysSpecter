"""Change-point detection on the system + process timelines.

Approach:
- Build a 1-D "intensity" signal from cpu/mem/disk. Smooth with EMA.
- Detect three families of candidates on the intensity signal:
    step:     rolling-mean delta across an asymmetric window
    slope:    regime change of the first difference (rising -> flat, etc.)
    quiet:    sustained drop to a baseline after elevated activity
- Separately detect "process end" points from per-process timelines:
  top CPU consumers that sustain near-zero CPU after having been active.
- Merge candidates within a proximity window, keeping the strongest.
- Drop candidates whose surrounding phase would be shorter than min_phase_seconds.

The algorithm is explainable: every candidate carries the reason + a numeric
evidence value, so downstream UX can show *why* a split happened. No numpy
dependency (the project already avoids heavy deps).
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


def _combined_intensity(system_rows: list[dict[str, Any]]) -> tuple[list[float], list[float]]:
    xs: list[float] = []
    ys: list[float] = []
    for r in system_rows:
        rel = r.get("rel_seconds")
        if rel is None:
            continue
        cpu = float(r.get("cpu_total_pct") or 0.0)
        mem = float(r.get("mem_percent") or 0.0)
        disk = float(r.get("disk_active_pct_est") or 0.0)
        xs.append(float(rel))
        ys.append(0.5 * cpu + 0.3 * mem + 0.2 * disk)
    return xs, ys


def _mean(vals: list[float]) -> float:
    return sum(vals) / len(vals) if vals else 0.0


def _detect_step_and_slope(
    xs: list[float],
    ys_smooth: list[float],
    window: int,
    step_threshold: float,
    slope_threshold: float,
) -> list[ChangePoint]:
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
                reason=f"step_{direction}",
                kind="step",
                evidence=(f"intensity mean shifted from {left_mean:.1f} to {right_mean:.1f} "
                          f"across ±{int(window)}s"),
                score=abs(delta),
            ))
            continue  # skip slope test at exact same point to avoid duplicates

        # slope: compare first-diff of left vs right window
        if len(left) >= 2 and len(right) >= 2:
            left_slope = (left[-1] - left[0]) / max(window, 1)
            right_slope = (right[-1] - right[0]) / max(window, 1)
            slope_delta = right_slope - left_slope
            if abs(slope_delta) >= slope_threshold:
                if left_slope > 0 and abs(right_slope) < 0.2 * abs(left_slope):
                    reason = "rising_to_flat"
                elif left_slope < 0 and abs(right_slope) < 0.2 * abs(left_slope):
                    reason = "falling_to_flat"
                elif abs(left_slope) < 0.2 * abs(right_slope) and right_slope > 0:
                    reason = "flat_to_rising"
                elif left_slope > 0 and right_slope < 0:
                    reason = "rising_to_falling"
                elif left_slope < 0 and right_slope > 0:
                    reason = "falling_to_rising"
                else:
                    reason = "slope_shift"
                out.append(ChangePoint(
                    rel_seconds=xs[i],
                    reason=reason,
                    kind="slope",
                    evidence=(f"slope change {left_slope:+.2f} -> {right_slope:+.2f} "
                              f"(Δ {slope_delta:+.2f}/s)"),
                    score=abs(slope_delta) * 20.0,  # make comparable with step score
                ))
    return out


def _detect_quiet_periods(
    xs: list[float],
    ys_smooth: list[float],
    window: int,
    active_threshold: float,
    quiet_threshold: float,
) -> list[ChangePoint]:
    """Flag the point where activity drops below quiet_threshold after sustained above active_threshold."""
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
    min_active_seconds: float,
    drop_threshold: float,
) -> list[ChangePoint]:
    """Find the moment where a previously top-CPU process goes quiet for good."""
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
    out: list[ChangePoint] = []
    for pid, s in series.items():
        xs = s["xs"]
        ys = s["ys"]
        if len(xs) < 4:
            continue
        # skip pid if total cpu contribution is trivial
        if sum(ys) < 30.0:
            continue
        # find the last sample above drop_threshold; if the run continued >= min_active after that, emit end
        last_active_idx = -1
        for i, v in enumerate(ys):
            if v >= drop_threshold:
                last_active_idx = i
        if last_active_idx < 0 or last_active_idx >= len(xs) - 1:
            continue
        end_rel = xs[last_active_idx]
        tail = xs[-1] - end_rel
        peak = max(ys) if ys else 0.0
        if tail >= min_active_seconds and peak >= drop_threshold + 5:
            out.append(ChangePoint(
                rel_seconds=end_rel,
                reason="process_end",
                kind="process_end",
                evidence=(f"process {s['name']} (pid {pid}) dropped below "
                          f"{drop_threshold:.0f}% CPU; peak was {peak:.1f}%"),
                score=peak,
            ))
    return out


def _dedupe(cps: list[ChangePoint], proximity_seconds: float) -> list[ChangePoint]:
    cps_sorted = sorted(cps, key=lambda c: c.rel_seconds)
    out: list[ChangePoint] = []
    for c in cps_sorted:
        if out and c.rel_seconds - out[-1].rel_seconds < proximity_seconds:
            if c.score > out[-1].score:
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

    def _mk(boundaries: list[tuple[float, ChangePoint | None]]) -> list[Phase]:
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
        return phases

    boundaries: list[tuple[float, ChangePoint | None]] = [(0.0, None)]
    for c in cps_sorted:
        boundaries.append((c.rel_seconds, c))
    boundaries.append((total_duration, None))

    phases = _mk(boundaries)

    # Merge short phases into the longer neighbour (absorb the boundary).
    changed = True
    while changed and len(phases) > 1:
        changed = False
        for i, p in enumerate(phases):
            if p.duration_seconds >= min_phase_seconds:
                continue
            # merge into longer neighbour
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

    # renumber
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


def detect_change_points(
    system_rows: list[dict[str, Any]],
    process_rows: list[dict[str, Any]],
    *,
    window_seconds: float = 20.0,
    step_threshold: float = 12.0,
    slope_threshold: float = 0.8,
    proximity_seconds: float = 30.0,
) -> list[ChangePoint]:
    xs, ys = _combined_intensity(system_rows)
    if len(xs) < 4:
        return []

    # estimate sample cadence
    dt = xs[1] - xs[0] if len(xs) >= 2 else 1.0
    if dt <= 0:
        dt = 1.0
    window = max(3, int(window_seconds / dt))

    ys_smooth = _ema(ys, alpha=0.3)

    step_slope = _detect_step_and_slope(xs, ys_smooth, window, step_threshold, slope_threshold)
    quiet = _detect_quiet_periods(xs, ys_smooth, window,
                                  active_threshold=30.0, quiet_threshold=12.0)
    pends = _detect_process_ends(process_rows,
                                 min_active_seconds=max(30.0, 2 * dt),
                                 drop_threshold=10.0)
    merged = _dedupe(step_slope + quiet + pends, proximity_seconds)
    return merged


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
