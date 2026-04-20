"""Slowdown window detection.

A slowdown window is any contiguous stretch where at least one resource
dimension is under pressure (CPU sustained / RAM high / swap active /
disk saturated / latency spiked). Overlapping/adjacent windows are merged
and annotated with suspected causes and top offenders."""

from __future__ import annotations

from typing import Any

from ..config import Thresholds
from .stats import merge_windows


def _build_pressure_mask(
    system_rows: list[dict[str, Any]],
    th: Thresholds,
) -> list[tuple[bool, list[str]]]:
    """For each row, return (is_pressure, list_of_reason_tags)."""
    mask: list[tuple[bool, list[str]]] = []
    for r in system_rows:
        reasons: list[str] = []
        cpu = r.get("cpu_total_pct") or 0.0
        mem = r.get("mem_percent") or 0.0
        swp = r.get("swap_percent") or 0.0
        disk = r.get("disk_active_pct_est") or 0.0
        if cpu >= th.cpu_sustained_pct:
            reasons.append("cpu")
        if mem >= th.mem_used_pct_high:
            reasons.append("memory")
        if swp >= 15.0:
            reasons.append("swap")
        if disk >= th.disk_active_pct:
            reasons.append("disk")
        mask.append((bool(reasons), reasons))
    return mask


def _rank_offenders_in_window(
    process_rows_by_rel: dict[float, list[dict[str, Any]]],
    start_rel: float,
    end_rel: float,
) -> dict[str, list[dict[str, Any]]]:
    by_proc_cpu: dict[str, float] = {}
    by_proc_rss: dict[str, float] = {}
    by_proc_io: dict[str, float] = {}
    for rel, rows in process_rows_by_rel.items():
        if rel is None or rel < start_rel or rel > end_rel:
            continue
        for p in rows:
            name = p.get("name") or "?"
            by_proc_cpu[name] = max(by_proc_cpu.get(name, 0.0), p.get("cpu_pct") or 0.0)
            by_proc_rss[name] = max(by_proc_rss.get(name, 0.0), (p.get("rss_bytes") or 0) / (1024 * 1024))
            io = (p.get("io_read_bps") or 0.0) + (p.get("io_write_bps") or 0.0)
            by_proc_io[name] = max(by_proc_io.get(name, 0.0), io)

    def _top(d: dict[str, float], n: int = 5) -> list[dict[str, Any]]:
        items = sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:n]
        return [{"name": k, "value": round(v, 1)} for k, v in items if v > 0]

    return {
        "top_cpu": _top(by_proc_cpu),
        "top_rss_mb": _top(by_proc_rss),
        "top_io_bps": _top(by_proc_io),
    }


def detect_slowdown_windows(
    system_rows: list[dict[str, Any]],
    process_rows: list[dict[str, Any]],
    latency_rows: list[dict[str, Any]],
    th: Thresholds,
) -> list[dict[str, Any]]:
    if not system_rows:
        return []

    mask = _build_pressure_mask(system_rows, th)
    raw_ranges: list[tuple[int, int]] = []
    start: int | None = None
    for i, (is_p, _) in enumerate(mask):
        if is_p:
            if start is None:
                start = i
        else:
            if start is not None:
                raw_ranges.append((start, i - 1))
                start = None
    if start is not None:
        raw_ranges.append((start, len(mask) - 1))

    gap_samples = th.slowdown_merge_gap_seconds
    merged = merge_windows(raw_ranges, gap=gap_samples)
    merged = [r for r in merged if (r[1] - r[0] + 1) >= th.slowdown_min_duration_seconds]

    process_by_rel: dict[float, list[dict[str, Any]]] = {}
    for p in process_rows:
        rel = p.get("rel_seconds")
        process_by_rel.setdefault(rel, []).append(p)

    results: list[dict[str, Any]] = []
    for s, e in merged:
        reasons: dict[str, int] = {}
        for i in range(s, e + 1):
            for r in mask[i][1]:
                reasons[r] = reasons.get(r, 0) + 1
        primary_reasons = sorted(reasons.items(), key=lambda kv: kv[1], reverse=True)
        start_rel = system_rows[s].get("rel_seconds") or 0.0
        end_rel = system_rows[e].get("rel_seconds") or 0.0

        peak_cpu = max((system_rows[i].get("cpu_total_pct") or 0.0) for i in range(s, e + 1))
        peak_mem = max((system_rows[i].get("mem_percent") or 0.0) for i in range(s, e + 1))
        peak_disk = max((system_rows[i].get("disk_active_pct_est") or 0.0) for i in range(s, e + 1))
        peak_swap = max((system_rows[i].get("swap_percent") or 0.0) for i in range(s, e + 1))

        latency_hits = [
            r for r in latency_rows
            if r.get("rel_seconds") is not None
            and start_rel - 10 <= r["rel_seconds"] <= end_rel + 10
            and (r.get("avg_ms") or 0.0) >= th.net_latency_ms_high
        ]
        if latency_hits:
            primary_reasons.append(("network", len(latency_hits)))

        offenders = _rank_offenders_in_window(process_by_rel, start_rel, end_rel)

        confidence = "suspicious"
        if (e - s + 1) >= 10:
            confidence = "likely"
        if (e - s + 1) >= 20 and len(primary_reasons) >= 2:
            confidence = "strong evidence"

        top_reasons = [r for r, _ in primary_reasons]
        description_bits: list[str] = []
        if peak_cpu >= th.cpu_sustained_pct:
            description_bits.append(f"CPU peaked at {peak_cpu:.1f}%")
        if peak_mem >= th.mem_used_pct_high:
            description_bits.append(f"memory at {peak_mem:.1f}%")
        if peak_swap >= 15.0:
            description_bits.append(f"swap at {peak_swap:.1f}%")
        if peak_disk >= th.disk_active_pct:
            description_bits.append(f"disk active at {peak_disk:.1f}%")
        if latency_hits:
            lat_peak = max((l.get("avg_ms") or 0.0) for l in latency_hits)
            description_bits.append(f"network latency up to {lat_peak:.0f}ms")
        suspects_names = [
            o["name"] for o in offenders.get("top_cpu", [])[:2]
        ]
        suspect_text = (", suspects: " + ", ".join(suspects_names)) if suspects_names else ""

        results.append({
            "kind": "slowdown_window",
            "start_rel": start_rel,
            "end_rel": end_rel,
            "duration_s": e - s + 1,
            "reason_tags": top_reasons,
            "peak_cpu_pct": round(peak_cpu, 1),
            "peak_mem_pct": round(peak_mem, 1),
            "peak_disk_pct": round(peak_disk, 1),
            "peak_swap_pct": round(peak_swap, 1),
            "latency_hits": len(latency_hits),
            "offenders": offenders,
            "confidence": confidence,
            "description": (
                f"Between s={start_rel:.0f} and s={end_rel:.0f} "
                + ("; ".join(description_bits) if description_bits else "pressure observed")
                + suspect_text + "."
            ),
        })
    return results
