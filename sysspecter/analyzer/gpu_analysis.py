"""Phase 3: summarize the GPU counters captured by the collector.

Produces per-engine and per-process GPU aggregates so the report can say
"which app is on the 3D engine at 80%?" and "is GPU memory pressured?"."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .grouping import _app_key, _display_name


def _avg(vals: list[float]) -> float | None:
    if not vals:
        return None
    return sum(vals) / len(vals)


def _peak(vals: list[float]) -> float | None:
    if not vals:
        return None
    return max(vals)


def analyze_gpu(
    engine_rows: list[dict[str, Any]],
    process_rows: list[dict[str, Any]],
    adapter_rows: list[dict[str, Any]],
    process_name_map: dict[int, str],
) -> dict[str, Any]:
    if not engine_rows and not process_rows and not adapter_rows:
        return {"enabled": False, "samples": 0}

    # Per-engine stats
    by_engine: dict[tuple[str, str], list[float]] = defaultdict(list)
    for r in engine_rows:
        try:
            util = float(r.get("utilization_pct") or 0.0)
        except (TypeError, ValueError):
            util = 0.0
        key = (r.get("engine_type") or "?", r.get("luid") or "?")
        by_engine[key].append(util)
    engine_stats = []
    for (et, luid), vals in by_engine.items():
        engine_stats.append({
            "engine_type": et,
            "luid": luid,
            "avg_pct": round(_avg(vals) or 0.0, 2),
            "peak_pct": round(_peak(vals) or 0.0, 2),
            "samples": len(vals),
        })
    engine_stats.sort(key=lambda e: e["peak_pct"], reverse=True)

    # Per-process memory (rollup by PID, then by app)
    by_pid_ded: dict[int, list[int]] = defaultdict(list)
    by_pid_shr: dict[int, list[int]] = defaultdict(list)
    for r in process_rows:
        try:
            pid = int(r.get("pid") or 0)
            ded = int(r.get("dedicated_bytes") or 0)
            shr = int(r.get("shared_bytes") or 0)
        except (TypeError, ValueError):
            continue
        if pid <= 0:
            continue
        by_pid_ded[pid].append(ded)
        by_pid_shr[pid].append(shr)
    pid_rows = []
    for pid, ded_vals in by_pid_ded.items():
        shr_vals = by_pid_shr.get(pid, [])
        name = process_name_map.get(pid, "?")
        pid_rows.append({
            "pid": pid,
            "name": name,
            "app_key": _app_key(name),
            "display_name": _display_name(_app_key(name)),
            "dedicated_peak_mb": round(max(ded_vals) / (1024 * 1024), 1) if ded_vals else 0.0,
            "dedicated_avg_mb": round(sum(ded_vals) / len(ded_vals) / (1024 * 1024), 1) if ded_vals else 0.0,
            "shared_peak_mb": round(max(shr_vals) / (1024 * 1024), 1) if shr_vals else 0.0,
        })
    pid_rows.sort(key=lambda e: e["dedicated_peak_mb"], reverse=True)

    # Roll up to apps
    app_agg: dict[str, dict[str, Any]] = {}
    for p in pid_rows:
        key = p["app_key"]
        entry = app_agg.setdefault(key, {
            "app_key": key,
            "display_name": p["display_name"],
            "pid_count": 0,
            "dedicated_peak_mb": 0.0,
            "dedicated_avg_mb": 0.0,
            "shared_peak_mb": 0.0,
        })
        entry["pid_count"] += 1
        entry["dedicated_peak_mb"] = max(entry["dedicated_peak_mb"], p["dedicated_peak_mb"])
        entry["dedicated_avg_mb"] += p["dedicated_avg_mb"]
        entry["shared_peak_mb"] = max(entry["shared_peak_mb"], p["shared_peak_mb"])
    app_rows = sorted(app_agg.values(), key=lambda e: e["dedicated_peak_mb"], reverse=True)

    # Adapter (nvidia-smi) stats
    adapter_stats = []
    adapters: dict[str, dict[str, list[float]]] = defaultdict(
        lambda: {"temp": [], "power": [], "used": [], "util": []}
    )
    for r in adapter_rows:
        name = r.get("adapter") or "?"

        def _push(key: str, val: Any):
            if val in (None, ""):
                return
            try:
                adapters[name][key].append(float(val))
            except (TypeError, ValueError):
                pass

        _push("temp", r.get("temperature_c"))
        _push("power", r.get("power_w"))
        _push("used", r.get("mem_used_mb"))
        _push("util", r.get("utilization_pct"))
    for name, d in adapters.items():
        adapter_stats.append({
            "adapter": name,
            "temp_avg_c": round(_avg(d["temp"]) or 0.0, 1) if d["temp"] else None,
            "temp_peak_c": round(_peak(d["temp"]) or 0.0, 1) if d["temp"] else None,
            "power_avg_w": round(_avg(d["power"]) or 0.0, 1) if d["power"] else None,
            "power_peak_w": round(_peak(d["power"]) or 0.0, 1) if d["power"] else None,
            "mem_used_avg_mb": round(_avg(d["used"]) or 0.0, 0) if d["used"] else None,
            "mem_used_peak_mb": round(_peak(d["used"]) or 0.0, 0) if d["used"] else None,
            "util_avg_pct": round(_avg(d["util"]) or 0.0, 1) if d["util"] else None,
            "util_peak_pct": round(_peak(d["util"]) or 0.0, 1) if d["util"] else None,
        })

    findings: list[dict[str, Any]] = []
    for e in engine_stats:
        if e["avg_pct"] >= 70.0:
            findings.append({
                "kind": "gpu_engine_saturated",
                "severity": "high" if e["avg_pct"] >= 85.0 else "medium",
                "detail": f"GPU engine {e['engine_type']} averaged "
                          f"{e['avg_pct']:.0f}% (peak {e['peak_pct']:.0f}%)",
            })

    return {
        "enabled": True,
        "samples": len(engine_rows) + len(process_rows) + len(adapter_rows),
        "engines": engine_stats,
        "top_pids": pid_rows[:10],
        "top_apps": app_rows[:10],
        "adapters": adapter_stats,
        "findings": findings,
    }
