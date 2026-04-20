"""Anomaly detection across CPU, RAM, disk, network, security."""

from __future__ import annotations

from typing import Any

from ..config import Thresholds
from .stats import sustained_windows, merge_windows, percentile, mean, max_opt


def detect_cpu_anomalies(
    system_rows: list[dict[str, Any]], th: Thresholds
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    cpu = [r.get("cpu_total_pct") or 0.0 for r in system_rows]
    if not cpu:
        return out

    min_samples = th.cpu_sustained_seconds
    sust = sustained_windows(cpu, th.cpu_sustained_pct, min_samples)
    sust = merge_windows(sust, gap=3)
    for s, e in sust:
        out.append({
            "kind": "cpu_sustained_high",
            "severity": "high",
            "start_rel": system_rows[s].get("rel_seconds"),
            "end_rel": system_rows[e].get("rel_seconds"),
            "duration_s": e - s + 1,
            "peak_pct": max(cpu[s:e + 1]),
            "avg_pct": sum(cpu[s:e + 1]) / (e - s + 1),
            "threshold_pct": th.cpu_sustained_pct,
            "description": (
                f"CPU stayed above {th.cpu_sustained_pct:.0f}% for "
                f"{e - s + 1}s (peak {max(cpu[s:e+1]):.1f}%)."
            ),
        })

    core_counts = {len(r.get("cpu_per_core_pct") or []) for r in system_rows}
    if core_counts:
        n_cores = max(core_counts)
        for ci in range(n_cores):
            series = [
                (r.get("cpu_per_core_pct") or [0.0] * n_cores)[ci]
                if ci < len(r.get("cpu_per_core_pct") or []) else 0.0
                for r in system_rows
            ]
            sw = sustained_windows(series, th.cpu_single_core_pct, th.cpu_single_core_seconds)
            sw = merge_windows(sw, gap=3)
            for s, e in sw:
                others = []
                for j in range(s, e + 1):
                    cores = system_rows[j].get("cpu_per_core_pct") or []
                    if not cores:
                        continue
                    others.extend(v for k, v in enumerate(cores) if k != ci)
                others_avg = (sum(others) / len(others)) if others else 0.0
                if others_avg < 50.0:
                    out.append({
                        "kind": "cpu_single_core_saturation",
                        "severity": "medium",
                        "core": ci,
                        "start_rel": system_rows[s].get("rel_seconds"),
                        "end_rel": system_rows[e].get("rel_seconds"),
                        "duration_s": e - s + 1,
                        "peak_pct": max(series[s:e + 1]),
                        "other_cores_avg_pct": round(others_avg, 1),
                        "description": (
                            f"Core {ci} pinned >{th.cpu_single_core_pct:.0f}% for "
                            f"{e - s + 1}s while other cores averaged {others_avg:.1f}%. "
                            "Suggests a single-threaded bottleneck."
                        ),
                    })
    return out


def detect_memory_anomalies(
    system_rows: list[dict[str, Any]], th: Thresholds
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    mem = [r.get("mem_percent") or 0.0 for r in system_rows]
    if not mem:
        return out

    high = sustained_windows(mem, th.mem_used_pct_high, 10)
    high = merge_windows(high, gap=5)
    for s, e in high:
        peak = max(mem[s:e + 1])
        sev = "high" if peak >= th.mem_used_pct_critical else "medium"
        out.append({
            "kind": "memory_pressure",
            "severity": sev,
            "start_rel": system_rows[s].get("rel_seconds"),
            "end_rel": system_rows[e].get("rel_seconds"),
            "duration_s": e - s + 1,
            "peak_pct": peak,
            "description": (
                f"Memory usage held above {th.mem_used_pct_high:.0f}% for "
                f"{e - s + 1}s (peak {peak:.1f}%)."
            ),
        })

    swap = [r.get("swap_percent") or 0.0 for r in system_rows]
    if swap and max(swap) > 20.0:
        out.append({
            "kind": "swap_usage",
            "severity": "medium" if max(swap) > 40 else "low",
            "peak_pct": max(swap),
            "avg_pct": round(sum(swap) / len(swap), 1),
            "description": (
                f"Swap/pagefile usage reached {max(swap):.1f}% "
                f"(avg {sum(swap)/len(swap):.1f}%). Indicates RAM pressure spilling to disk."
            ),
        })
    return out


def detect_disk_anomalies(
    system_rows: list[dict[str, Any]], th: Thresholds
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    active = [r.get("disk_active_pct_est") or 0.0 for r in system_rows]
    if not active:
        return out
    sw = sustained_windows(active, th.disk_active_pct, th.disk_active_seconds)
    sw = merge_windows(sw, gap=3)
    for s, e in sw:
        peak = max(active[s:e + 1])
        out.append({
            "kind": "disk_active_high",
            "severity": "high" if peak > 95 else "medium",
            "start_rel": system_rows[s].get("rel_seconds"),
            "end_rel": system_rows[e].get("rel_seconds"),
            "duration_s": e - s + 1,
            "peak_pct": peak,
            "description": (
                f"Disk active time held above {th.disk_active_pct:.0f}% for "
                f"{e - s + 1}s (peak {peak:.1f}%). Storage is likely saturated."
            ),
        })
    return out


def detect_network_latency_anomalies(
    latency_rows: list[dict[str, Any]], th: Thresholds
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    by_target: dict[str, list[dict[str, Any]]] = {}
    for r in latency_rows:
        by_target.setdefault(r.get("target") or "?", []).append(r)
    for target, rows in by_target.items():
        avgs = [r.get("avg_ms") for r in rows if r.get("avg_ms") is not None]
        losses = [r.get("loss_pct") or 0.0 for r in rows]
        if not avgs:
            if losses and mean(losses) and mean(losses) >= 50:
                out.append({
                    "kind": "network_unreachable",
                    "severity": "high",
                    "target": target,
                    "avg_loss_pct": round(mean(losses) or 0.0, 1),
                    "description": (
                        f"Target {target} was mostly unreachable "
                        f"(avg loss {mean(losses) or 0:.1f}%)."
                    ),
                })
            continue
        p95 = percentile(avgs, 95)
        peak = max_opt(avgs)
        avg_mean = mean(avgs)
        loss_mean = mean(losses) or 0.0
        severity = "low"
        if peak and peak >= th.net_latency_ms_critical:
            severity = "high"
        elif peak and peak >= th.net_latency_ms_high:
            severity = "medium"
        if severity != "low" or loss_mean >= 5.0:
            out.append({
                "kind": "network_latency_spike",
                "severity": severity,
                "target": target,
                "avg_ms": round(avg_mean or 0.0, 1),
                "p95_ms": round(p95 or 0.0, 1),
                "peak_ms": round(peak or 0.0, 1),
                "loss_pct": round(loss_mean, 1),
                "description": (
                    f"Latency to {target}: avg {avg_mean:.1f}ms, p95 {p95:.1f}ms, "
                    f"peak {peak:.1f}ms, loss {loss_mean:.1f}%."
                ),
            })
    return out


def detect_anomalies(
    system_rows: list[dict[str, Any]],
    latency_rows: list[dict[str, Any]],
    th: Thresholds,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    out.extend(detect_cpu_anomalies(system_rows, th))
    out.extend(detect_memory_anomalies(system_rows, th))
    out.extend(detect_disk_anomalies(system_rows, th))
    out.extend(detect_network_latency_anomalies(latency_rows, th))
    return out
