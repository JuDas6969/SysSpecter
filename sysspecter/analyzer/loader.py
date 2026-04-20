"""Load a run's artifacts back into memory for analysis."""

from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass
from typing import Any


def _read_csv(path: str) -> list[dict[str, Any]]:
    if not os.path.exists(path):
        return []
    rows: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def _to_float(x: Any) -> float | None:
    if x is None or x == "":
        return None
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _to_int(x: Any, default: int = 0) -> int:
    if x is None or x == "":
        return default
    try:
        return int(float(x))
    except (TypeError, ValueError):
        return default


@dataclass
class RunData:
    run_dir: str
    manifest: dict[str, Any]
    static: dict[str, Any]
    system_rows: list[dict[str, Any]]
    process_rows: list[dict[str, Any]]
    network_rows: list[dict[str, Any]]
    latency_rows: list[dict[str, Any]]
    connection_rows: list[dict[str, Any]]
    process_events: list[dict[str, Any]]
    service_events: list[dict[str, Any]]
    # Phase 3 optional data
    gpu_engine_rows: list[dict[str, Any]]
    gpu_process_rows: list[dict[str, Any]]
    gpu_adapter_rows: list[dict[str, Any]]
    event_log: dict[str, Any]
    etw_disk: dict[str, Any]


def _coerce_system_row(r: dict[str, Any]) -> dict[str, Any]:
    out = dict(r)
    for k in (
        "cpu_total_pct", "cpu_freq_current_mhz",
        "ctx_switches_per_sec", "interrupts_per_sec",
        "mem_percent", "swap_percent",
        "disk_read_bytes_per_sec", "disk_write_bytes_per_sec",
        "disk_read_count_per_sec", "disk_write_count_per_sec", "disk_active_pct_est",
        "net_sent_bytes_per_sec", "net_recv_bytes_per_sec",
        "net_packets_sent_per_sec", "net_packets_recv_per_sec",
        "net_errin_per_sec", "net_errout_per_sec",
        "net_dropin_per_sec", "net_dropout_per_sec",
        "rel_seconds", "timestamp",
    ):
        if k in out:
            out[k] = _to_float(out[k])
    for k in ("mem_total_bytes", "mem_available_bytes", "mem_used_bytes",
              "swap_total_bytes", "swap_used_bytes"):
        if k in out:
            out[k] = _to_int(out[k])
    per_core_raw = out.get("cpu_per_core_pct") or ""
    if isinstance(per_core_raw, str) and per_core_raw:
        out["cpu_per_core_pct"] = [_to_float(v) or 0.0 for v in per_core_raw.split(";")]
    else:
        out["cpu_per_core_pct"] = []
    return out


def _coerce_process_row(r: dict[str, Any]) -> dict[str, Any]:
    out = dict(r)
    for k in ("rel_seconds", "timestamp", "cpu_pct", "io_read_bps", "io_write_bps",
              "cpu_time_user", "cpu_time_system"):
        if k in out:
            out[k] = _to_float(out[k])
    for k in ("pid", "rss_bytes", "vms_bytes", "num_threads", "num_handles", "ppid", "is_target"):
        if k in out:
            out[k] = _to_int(out[k])
    return out


def _coerce_network_row(r: dict[str, Any]) -> dict[str, Any]:
    out = dict(r)
    for k in ("rel_seconds", "timestamp",
              "bytes_sent_per_sec", "bytes_recv_per_sec",
              "packets_sent_per_sec", "packets_recv_per_sec",
              "errin_per_sec", "errout_per_sec",
              "dropin_per_sec", "dropout_per_sec"):
        if k in out:
            out[k] = _to_float(out[k])
    for k in ("is_up", "speed_mbps", "connections_established"):
        if k in out:
            out[k] = _to_int(out[k], default=-1 if k == "connections_established" else 0)
    return out


def _coerce_latency_row(r: dict[str, Any]) -> dict[str, Any]:
    out = dict(r)
    for k in ("rel_seconds", "timestamp", "avg_ms", "min_ms", "max_ms", "jitter_ms",
              "loss_pct", "resolve_ms"):
        if k in out:
            out[k] = _to_float(out[k])
    out["count"] = _to_int(out.get("count"))
    return out


def _coerce_connection_row(r: dict[str, Any]) -> dict[str, Any]:
    out = dict(r)
    for k in ("rel_seconds", "timestamp"):
        if k in out:
            out[k] = _to_float(out[k])
    out["pid"] = _to_int(out.get("pid"))
    return out


def _coerce_gpu_engine_row(r: dict[str, Any]) -> dict[str, Any]:
    out = dict(r)
    for k in ("rel_seconds", "timestamp", "utilization_pct"):
        if k in out:
            out[k] = _to_float(out[k])
    return out


def _coerce_gpu_process_row(r: dict[str, Any]) -> dict[str, Any]:
    out = dict(r)
    for k in ("rel_seconds", "timestamp"):
        if k in out:
            out[k] = _to_float(out[k])
    for k in ("pid", "dedicated_bytes", "shared_bytes"):
        if k in out:
            out[k] = _to_int(out[k])
    return out


def _coerce_gpu_adapter_row(r: dict[str, Any]) -> dict[str, Any]:
    out = dict(r)
    for k in ("rel_seconds", "timestamp", "temperature_c", "power_w",
              "mem_used_mb", "mem_total_mb", "utilization_pct"):
        if k in out:
            out[k] = _to_float(out[k])
    return out


def load_run(run_dir: str) -> RunData:
    def _read_json(name: str, default):
        path = os.path.join(run_dir, name)
        if not os.path.exists(path):
            return default
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    return RunData(
        run_dir=run_dir,
        manifest=_read_json("manifest.json", {}),
        static=_read_json("static_snapshot.json", {}),
        system_rows=[_coerce_system_row(r) for r in _read_csv(os.path.join(run_dir, "timeline_system.csv"))],
        process_rows=[_coerce_process_row(r) for r in _read_csv(os.path.join(run_dir, "timeline_processes.csv"))],
        network_rows=[_coerce_network_row(r) for r in _read_csv(os.path.join(run_dir, "timeline_network.csv"))],
        latency_rows=[_coerce_latency_row(r) for r in _read_csv(os.path.join(run_dir, "timeline_latency.csv"))],
        connection_rows=[_coerce_connection_row(r) for r in _read_csv(os.path.join(run_dir, "timeline_connections.csv"))],
        process_events=_read_json("process_events.json", []),
        service_events=_read_json("service_events.json", []),
        gpu_engine_rows=[_coerce_gpu_engine_row(r) for r in _read_csv(os.path.join(run_dir, "timeline_gpu_engine.csv"))],
        gpu_process_rows=[_coerce_gpu_process_row(r) for r in _read_csv(os.path.join(run_dir, "timeline_gpu_process.csv"))],
        gpu_adapter_rows=[_coerce_gpu_adapter_row(r) for r in _read_csv(os.path.join(run_dir, "timeline_gpu_adapter.csv"))],
        event_log=_read_json("event_log.json", {}),
        etw_disk=_read_json("etw_disk_summary.json", {}),
    )
