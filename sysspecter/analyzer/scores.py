"""Scoring model.

Produces multiple evidence-based scores (0-100, higher = better) plus an overall.
Each score is documented — the report shows the inputs so thresholds are explainable.
"""

from __future__ import annotations

from typing import Any

from .stats import mean, percentile


def _clip(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, v))


def stability_score(system_rows: list[dict[str, Any]], anomalies: list[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    if not system_rows:
        return 50.0, {"note": "no samples"}
    cpu_vals = [r.get("cpu_total_pct") or 0.0 for r in system_rows]
    mem_vals = [r.get("mem_percent") or 0.0 for r in system_rows]
    from statistics import pstdev
    cpu_std = pstdev(cpu_vals) if len(cpu_vals) > 1 else 0.0
    mem_std = pstdev(mem_vals) if len(mem_vals) > 1 else 0.0
    anomaly_count = sum(1 for a in anomalies if a.get("severity") in ("medium", "high"))
    score = 100.0 - _clip(cpu_std * 1.2, 0, 40) - _clip(mem_std * 1.5, 0, 30) - _clip(anomaly_count * 5, 0, 40)
    return _clip(score), {
        "cpu_stddev": round(cpu_std, 2),
        "memory_stddev": round(mem_std, 2),
        "anomaly_count": anomaly_count,
        "formula": "100 - cpu_std*1.2 - mem_std*1.5 - anomaly_count*5",
    }


def efficiency_score(system_rows: list[dict[str, Any]], offenders: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    if not system_rows:
        return 50.0, {"note": "no samples"}
    idle_pct = mean(100.0 - (r.get("cpu_total_pct") or 0.0) for r in system_rows) or 0.0
    mem_free_pct = mean(100.0 - (r.get("mem_percent") or 0.0) for r in system_rows) or 0.0
    bg_items = offenders.get("background_noise") or []
    bg_cpu = sum(e.get("cpu_pct_avg") or 0.0 for e in bg_items)
    score = _clip(idle_pct * 0.5 + mem_free_pct * 0.4 - bg_cpu * 0.2 + 20)
    return score, {
        "avg_idle_cpu_pct": round(idle_pct, 1),
        "avg_free_mem_pct": round(mem_free_pct, 1),
        "background_cpu_sum": round(bg_cpu, 1),
        "formula": "clip(idle*0.5 + mem_free*0.4 - bg_cpu*0.2 + 20)",
    }


def workload_suitability_score(
    system_rows: list[dict[str, Any]],
    slowdowns: list[dict[str, Any]],
    mode: str,
) -> tuple[float, dict[str, Any]]:
    if mode != "workload":
        return 50.0, {"note": "workload mode not active", "neutral_baseline": True}
    if not system_rows:
        return 50.0, {"note": "no samples"}
    total_sec = len(system_rows)
    slowdown_sec = sum(s.get("duration_s") or 0 for s in slowdowns)
    slowdown_ratio = slowdown_sec / max(total_sec, 1)
    score = _clip(100.0 - slowdown_ratio * 100.0)
    return score, {
        "total_samples": total_sec,
        "slowdown_samples": slowdown_sec,
        "slowdown_ratio": round(slowdown_ratio, 3),
        "formula": "100 - slowdown_ratio*100",
    }


def security_overhead_score(offenders: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    sec = offenders.get("security") or []
    if not sec:
        return 90.0, {"note": "no security processes observed in candidate set"}
    top_cpu = sum(e.get("cpu_pct_avg") or 0.0 for e in sec[:3])
    top_rss = sum(e.get("rss_mb_max") or 0.0 for e in sec[:3])
    score = _clip(100.0 - top_cpu * 1.5 - top_rss * 0.05)
    return score, {
        "top_sec_cpu_sum": round(top_cpu, 1),
        "top_sec_rss_mb_sum": round(top_rss, 1),
        "formula": "100 - sec_cpu*1.5 - sec_rss_mb*0.05",
    }


def network_impact_score(latency_rows: list[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    if not latency_rows:
        return 70.0, {"note": "no latency data"}
    avgs = [r.get("avg_ms") for r in latency_rows if r.get("avg_ms") is not None]
    losses = [r.get("loss_pct") or 0.0 for r in latency_rows]
    if not avgs:
        loss_m = mean(losses) or 0.0
        return _clip(100.0 - loss_m), {"avg_loss_pct": round(loss_m, 1), "note": "no latency values, only loss"}
    p95 = percentile(avgs, 95) or 0.0
    avg_m = mean(avgs) or 0.0
    loss_m = mean(losses) or 0.0
    score = _clip(100.0 - avg_m * 0.2 - p95 * 0.1 - loss_m * 2)
    return score, {
        "avg_ms": round(avg_m, 1),
        "p95_ms": round(p95, 1),
        "avg_loss_pct": round(loss_m, 1),
        "formula": "100 - avg_ms*0.2 - p95_ms*0.1 - loss*2",
    }


def resource_hygiene_score(
    leaks: dict[str, list[dict[str, Any]]],
    offenders: dict[str, Any],
) -> tuple[float, dict[str, Any]]:
    def _penalty(items: list[dict[str, Any]]) -> float:
        p = 0.0
        for it in items:
            c = it.get("confidence")
            if c == "strong evidence":
                p += 20
            elif c == "likely":
                p += 10
            else:
                p += 3
        return p

    penalty = _penalty(leaks.get("memory", []))
    penalty += _penalty(leaks.get("handles", []))
    penalty += _penalty(leaks.get("threads", []))
    churn_starts = len(offenders.get("top_handle_growth") or [])
    penalty += churn_starts * 1.5
    score = _clip(100.0 - penalty)
    return score, {
        "memory_leak_candidates": len(leaks.get("memory", [])),
        "handle_leak_candidates": len(leaks.get("handles", [])),
        "thread_leak_candidates": len(leaks.get("threads", [])),
        "formula": "100 - sum(penalty per leak by confidence tier) - 1.5*handle_growers",
    }


# ---------------------------------------------------------------------------
# Field-review A6: cap-window-aware scoring.
#
# Scores computed over a fixed canonical window (e.g. "the last 1 h",
# "the last 8 h") are comparable across runs of different lengths. The
# legacy full-run score answers "how was the whole run?", a tail window
# answers "how does this machine look RIGHT NOW?" — much more useful
# for fleet trending and cross-run comparison.
# ---------------------------------------------------------------------------


_TAIL_WINDOWS_S = (
    ("last_1h", 3600.0),
    ("last_8h", 28800.0),
)


def _filter_by_rel(rows: list[dict[str, Any]], lo: float, hi: float
                   ) -> list[dict[str, Any]]:
    """Return only the rows whose `rel_seconds` falls in [lo, hi]."""
    out: list[dict[str, Any]] = []
    for r in rows:
        rel = r.get("rel_seconds")
        if rel is None:
            continue
        try:
            v = float(rel)
        except (TypeError, ValueError):
            continue
        if lo <= v <= hi:
            out.append(r)
    return out


def _filter_slowdowns(slowdowns: list[dict[str, Any]],
                      lo: float, hi: float) -> list[dict[str, Any]]:
    """Slowdown windows have their own start_rel/end_rel bounds."""
    out: list[dict[str, Any]] = []
    for s in slowdowns:
        try:
            start = float(s.get("start_rel") or s.get("rel_seconds") or 0.0)
        except (TypeError, ValueError):
            start = 0.0
        try:
            end = float(s.get("end_rel") or start)
        except (TypeError, ValueError):
            end = start
        # A slowdown intersects the window if it overlaps at all.
        if end >= lo and start <= hi:
            out.append(s)
    return out


def compute_tail_window_scores(
    system_rows: list[dict[str, Any]],
    anomalies: list[dict[str, Any]],
    slowdowns: list[dict[str, Any]],
    offenders: dict[str, Any],
    leaks: dict[str, Any],
    latency_rows: list[dict[str, Any]],
    mode: str,
    bottlenecks: dict[str, Any],
    *,
    full_window_start: float,
    full_window_end: float,
) -> list[dict[str, Any]]:
    """Compute scores over canonical tail windows so two runs of
    different total length can be compared apples-to-apples.

    Each entry in the returned list mirrors the shape of
    ``calculate_scores`` plus the window label and bounds. Only
    windows that fit inside the run's analysis window are emitted —
    a 30-minute run won't produce a 1-h or 8-h tail.
    """
    out: list[dict[str, Any]] = []
    duration = max(0.0, full_window_end - full_window_start)
    for label, window_s in _TAIL_WINDOWS_S:
        if duration < window_s:
            continue
        lo = max(full_window_start, full_window_end - window_s)
        hi = full_window_end
        win_system = _filter_by_rel(system_rows, lo, hi)
        win_latency = _filter_by_rel(latency_rows, lo, hi)
        win_anomalies = _filter_by_rel(anomalies, lo, hi)
        win_slowdowns = _filter_slowdowns(slowdowns, lo, hi)
        # Offenders + leaks are aggregated over the full run already;
        # re-aggregating per window would change the meaning of
        # security/hygiene. We keep the run-level dicts so those two
        # scores represent "what was running", and let the
        # window-sensitive scores (stability, efficiency, network
        # impact, workload suitability) reflect the tail.
        if len(win_system) < 5:
            # Too few samples in the tail to score meaningfully.
            continue
        s = calculate_scores(
            win_system, win_anomalies, win_slowdowns,
            offenders, leaks, win_latency, mode, bottlenecks,
        )
        s["window_label"] = label
        s["window_start_seconds"] = round(lo, 2)
        s["window_end_seconds"] = round(hi, 2)
        s["window_duration_seconds"] = round(hi - lo, 2)
        s["window_samples"] = len(win_system)
        out.append(s)
    return out


def calculate_scores(
    system_rows: list[dict[str, Any]],
    anomalies: list[dict[str, Any]],
    slowdowns: list[dict[str, Any]],
    offenders: dict[str, Any],
    leaks: dict[str, Any],
    latency_rows: list[dict[str, Any]],
    mode: str,
    bottlenecks: dict[str, Any],
) -> dict[str, Any]:
    stab, stab_d = stability_score(system_rows, anomalies)
    eff, eff_d = efficiency_score(system_rows, offenders)
    ws, ws_d = workload_suitability_score(system_rows, slowdowns, mode)
    sec, sec_d = security_overhead_score(offenders)
    net, net_d = network_impact_score(latency_rows)
    hyg, hyg_d = resource_hygiene_score(leaks, offenders)

    weights = {"stability": 0.25, "efficiency": 0.15, "workload": 0.15,
               "security": 0.10, "network": 0.15, "hygiene": 0.20}
    weighted_sum = (
        stab * weights["stability"]
        + eff * weights["efficiency"]
        + ws * weights["workload"]
        + sec * weights["security"]
        + net * weights["network"]
        + hyg * weights["hygiene"]
    )
    confidence = "medium"
    total_samples = len(system_rows)
    if total_samples < 60:
        confidence = "low (short run)"
    elif total_samples >= 600:
        confidence = "high"

    return {
        "stability": {"score": round(stab, 1), "details": stab_d},
        "efficiency": {"score": round(eff, 1), "details": eff_d},
        "workload_suitability": {"score": round(ws, 1), "details": ws_d},
        "security_overhead": {"score": round(sec, 1), "details": sec_d},
        "network_impact": {"score": round(net, 1), "details": net_d},
        "resource_hygiene": {"score": round(hyg, 1), "details": hyg_d},
        "overall": round(weighted_sum, 1),
        "weights": weights,
        "primary_bottleneck": bottlenecks.get("primary"),
        "secondary_bottlenecks": bottlenecks.get("secondary") or [],
        "confidence": confidence,
        "sample_count": total_samples,
    }
