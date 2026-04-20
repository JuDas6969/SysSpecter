"""Classify primary/secondary bottlenecks based on sustained pressure + anomalies."""

from __future__ import annotations

from typing import Any


def classify_bottlenecks(
    system_rows: list[dict[str, Any]],
    anomalies: list[dict[str, Any]],
    latency_rows: list[dict[str, Any]],
    slowdowns: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return primary + secondary + reasoning."""
    scores: dict[str, float] = {
        "cpu": 0.0, "memory": 0.0, "disk": 0.0, "network": 0.0,
        "security": 0.0, "background_noise": 0.0,
    }
    reasons: dict[str, list[str]] = {k: [] for k in scores}

    if system_rows:
        total_len = len(system_rows)
        cpu_pressure = sum(1 for r in system_rows if (r.get("cpu_total_pct") or 0.0) >= 80) / total_len
        mem_pressure = sum(1 for r in system_rows if (r.get("mem_percent") or 0.0) >= 80) / total_len
        disk_pressure = sum(1 for r in system_rows if (r.get("disk_active_pct_est") or 0.0) >= 80) / total_len
        scores["cpu"] += cpu_pressure * 100
        scores["memory"] += mem_pressure * 100
        scores["disk"] += disk_pressure * 100
        if cpu_pressure > 0.1:
            reasons["cpu"].append(f"CPU >=80% for {cpu_pressure*100:.0f}% of samples")
        if mem_pressure > 0.1:
            reasons["memory"].append(f"memory >=80% for {mem_pressure*100:.0f}% of samples")
        if disk_pressure > 0.1:
            reasons["disk"].append(f"disk active >=80% for {disk_pressure*100:.0f}% of samples")

    kind_weights = {
        "cpu_sustained_high": ("cpu", 25),
        "cpu_single_core_saturation": ("cpu", 10),
        "memory_pressure": ("memory", 25),
        "swap_usage": ("memory", 10),
        "disk_active_high": ("disk", 25),
        "network_latency_spike": ("network", 20),
        "network_unreachable": ("network", 25),
    }
    for a in anomalies:
        mapped = kind_weights.get(a.get("kind") or "")
        if not mapped:
            continue
        dim, w = mapped
        if a.get("severity") == "high":
            w *= 1.5
        scores[dim] += w
        reasons[dim].append(a.get("description") or a["kind"])

    if latency_rows:
        from .stats import mean
        avgs = [r.get("avg_ms") for r in latency_rows if r.get("avg_ms") is not None]
        if avgs:
            m = mean(avgs) or 0.0
            if m >= 200:
                scores["network"] += 10
                reasons["network"].append(f"sustained high mean latency {m:.0f}ms")

    for s in slowdowns:
        for tag in s.get("reason_tags") or []:
            if tag in scores:
                scores[tag] += 5
        if "top_cpu" in (s.get("offenders") or {}):
            for o in s["offenders"]["top_cpu"][:3]:
                name = (o.get("name") or "").lower()
                if name in {"msmpeng.exe", "mssense.exe", "mpcmdrun.exe"}:
                    scores["security"] += 10
                    reasons["security"].append(
                        f"{name} among top CPU offenders during slowdown s={s.get('start_rel'):.0f}"
                    )

    ordered = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    primary = ordered[0][0] if ordered and ordered[0][1] > 15 else None
    secondary = [k for k, v in ordered[1:4] if v > 10]

    return {
        "primary": primary,
        "secondary": secondary,
        "scores": {k: round(v, 1) for k, v in scores.items()},
        "reasons": {k: v[:5] for k, v in reasons.items() if v},
    }
