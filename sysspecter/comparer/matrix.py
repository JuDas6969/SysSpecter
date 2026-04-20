"""Build comparison matrix + rankings across loaded runs."""

from __future__ import annotations

import csv
from typing import Any

from ..analyzer.stats import mean, percentile


def _score_val(scores: dict[str, Any], key: str) -> float | None:
    v = scores.get(key)
    if isinstance(v, dict):
        v = v.get("score")
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def build_matrix(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """runs = [{"manifest":..., "scores":..., "findings":..., "rd": RunData}, ...]"""
    rows: list[dict[str, Any]] = []
    for r in runs:
        m = r["manifest"]
        s = r["scores"]
        f = r["findings"]
        rd = r["rd"]
        cpu_vals = [row.get("cpu_total_pct") or 0.0 for row in rd.system_rows]
        mem_vals = [row.get("mem_percent") or 0.0 for row in rd.system_rows]
        disk_vals = [row.get("disk_active_pct_est") or 0.0 for row in rd.system_rows]
        lat_vals = [row.get("avg_ms") for row in rd.latency_rows if row.get("avg_ms") is not None]
        rows.append({
            "run_id": m.get("run_id"),
            "hostname": m.get("hostname"),
            "mode": m.get("mode"),
            "tags": ",".join(m.get("tags") or []),
            "duration_s": m.get("duration_actual_seconds"),
            "samples": len(rd.system_rows),
            "overall": _score_val(s, "overall"),
            "stability": _score_val(s, "stability"),
            "efficiency": _score_val(s, "efficiency"),
            "workload": _score_val(s, "workload_suitability"),
            "security": _score_val(s, "security_overhead"),
            "network": _score_val(s, "network_impact"),
            "hygiene": _score_val(s, "resource_hygiene"),
            "primary": s.get("primary_bottleneck"),
            "cpu_avg": round(mean(cpu_vals) or 0, 1) if cpu_vals else None,
            "cpu_p95": round(percentile(cpu_vals, 95) or 0, 1) if cpu_vals else None,
            "mem_avg": round(mean(mem_vals) or 0, 1) if mem_vals else None,
            "disk_avg": round(mean(disk_vals) or 0, 1) if disk_vals else None,
            "latency_p95_ms": round(percentile(lat_vals, 95) or 0, 1) if lat_vals else None,
            "anomalies": len(f.get("anomalies") or []),
            "slowdowns": len(f.get("slowdowns") or []),
            "memory_leaks": len((f.get("leaks") or {}).get("memory") or []),
            "handle_leaks": len((f.get("leaks") or {}).get("handles") or []),
            "process_starts": (f.get("process_churn") or {}).get("total_process_starts", 0),
        })

    rankings: dict[str, list[tuple[str, float]]] = {}
    for metric in ("overall", "stability", "efficiency", "workload",
                   "security", "network", "hygiene"):
        pairs = [(r["run_id"], r[metric]) for r in rows if r[metric] is not None]
        rankings[f"best_{metric}"] = sorted(pairs, key=lambda kv: kv[1], reverse=True)
    rankings["lowest_cpu_avg"] = sorted(
        [(r["run_id"], r["cpu_avg"]) for r in rows if r["cpu_avg"] is not None],
        key=lambda kv: kv[1])
    rankings["lowest_latency_p95"] = sorted(
        [(r["run_id"], r["latency_p95_ms"]) for r in rows if r["latency_p95_ms"] is not None],
        key=lambda kv: kv[1])
    rankings["fewest_anomalies"] = sorted(
        [(r["run_id"], r["anomalies"]) for r in rows], key=lambda kv: kv[1])

    return {"rows": rows, "rankings": rankings}


def write_matrix_csv(matrix: dict[str, Any], path: str) -> None:
    rows = matrix["rows"]
    if not rows:
        return
    fields = list(rows[0].keys())
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
