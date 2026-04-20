"""Per-second system sample: CPU, RAM, disk, network totals."""

from __future__ import annotations

import time
from dataclasses import dataclass, asdict
from typing import Any

import psutil

_last_disk: dict[str, Any] | None = None
_last_net: dict[str, Any] | None = None
_last_ts: float | None = None


@dataclass
class SystemSample:
    timestamp: float
    rel_seconds: float
    cpu_total_pct: float
    cpu_per_core_pct: list[float]
    cpu_freq_current_mhz: float | None
    ctx_switches_per_sec: float | None
    interrupts_per_sec: float | None
    proc_queue_len: float | None
    mem_total_bytes: int
    mem_available_bytes: int
    mem_used_bytes: int
    mem_percent: float
    swap_total_bytes: int
    swap_used_bytes: int
    swap_percent: float
    commit_used_bytes: int | None
    commit_total_bytes: int | None
    disk_read_bytes_per_sec: float
    disk_write_bytes_per_sec: float
    disk_read_count_per_sec: float
    disk_write_count_per_sec: float
    disk_active_pct_est: float
    net_sent_bytes_per_sec: float
    net_recv_bytes_per_sec: float
    net_packets_sent_per_sec: float
    net_packets_recv_per_sec: float
    net_errin_per_sec: float
    net_errout_per_sec: float
    net_dropin_per_sec: float
    net_dropout_per_sec: float


_last_cpu_stats: tuple[float, int, int] | None = None


def _cpu_stats_rates() -> tuple[float | None, float | None]:
    global _last_cpu_stats
    try:
        st = psutil.cpu_stats()
    except Exception:
        return None, None
    now = time.monotonic()
    if _last_cpu_stats is None:
        _last_cpu_stats = (now, st.ctx_switches, st.interrupts)
        return None, None
    prev_t, prev_ctx, prev_int = _last_cpu_stats
    dt = max(now - prev_t, 1e-3)
    ctx_rate = (st.ctx_switches - prev_ctx) / dt
    int_rate = (st.interrupts - prev_int) / dt
    _last_cpu_stats = (now, st.ctx_switches, st.interrupts)
    return ctx_rate, int_rate


def _freq_mhz() -> float | None:
    try:
        f = psutil.cpu_freq()
        return float(f.current) if f else None
    except Exception:
        return None


def _disk_totals() -> tuple[float, float, float, float, int, int]:
    try:
        io = psutil.disk_io_counters()
    except Exception:
        return 0.0, 0.0, 0.0, 0.0, 0, 0
    if io is None:
        return 0.0, 0.0, 0.0, 0.0, 0, 0
    return (
        float(io.read_bytes), float(io.write_bytes),
        float(io.read_count), float(io.write_count),
        int(getattr(io, "busy_time", 0) or 0),
        int(getattr(io, "read_time", 0) + getattr(io, "write_time", 0) or 0),
    )


def _net_totals() -> dict[str, float]:
    try:
        n = psutil.net_io_counters()
    except Exception:
        return {}
    if n is None:
        return {}
    return {
        "bytes_sent": float(n.bytes_sent),
        "bytes_recv": float(n.bytes_recv),
        "packets_sent": float(n.packets_sent),
        "packets_recv": float(n.packets_recv),
        "errin": float(n.errin),
        "errout": float(n.errout),
        "dropin": float(n.dropin),
        "dropout": float(n.dropout),
    }


def collect_system_sample(started_mono: float) -> SystemSample:
    """Collect one per-second system sample. Uses monotonic clock for rate math."""
    global _last_disk, _last_net, _last_ts

    now_wall = time.time()
    now_mono = time.monotonic()
    rel = now_mono - started_mono

    cpu_total = psutil.cpu_percent(interval=None)
    cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
    freq = _freq_mhz()
    ctx_rate, int_rate = _cpu_stats_rates()

    vm = psutil.virtual_memory()
    sm = psutil.swap_memory()

    read_b, write_b, read_c, write_c, busy_time, total_rw_time = _disk_totals()
    net = _net_totals()

    if _last_ts is None:
        dt = 1.0
    else:
        dt = max(now_mono - _last_ts, 1e-3)

    if _last_disk is None:
        d_read_bps = d_write_bps = d_read_cps = d_write_cps = 0.0
        d_active_pct = 0.0
    else:
        d_read_bps = (read_b - _last_disk["read_b"]) / dt
        d_write_bps = (write_b - _last_disk["write_b"]) / dt
        d_read_cps = (read_c - _last_disk["read_c"]) / dt
        d_write_cps = (write_c - _last_disk["write_c"]) / dt
        busy_delta_ms = busy_time - _last_disk["busy_time"]
        d_active_pct = max(0.0, min(100.0, (busy_delta_ms / (dt * 1000.0)) * 100.0))

    if _last_net is None or not net:
        ns_bps = nr_bps = nps_ps = npr_ps = 0.0
        ein = eout = din = dout = 0.0
    else:
        ns_bps = (net["bytes_sent"] - _last_net["bytes_sent"]) / dt
        nr_bps = (net["bytes_recv"] - _last_net["bytes_recv"]) / dt
        nps_ps = (net["packets_sent"] - _last_net["packets_sent"]) / dt
        npr_ps = (net["packets_recv"] - _last_net["packets_recv"]) / dt
        ein = (net["errin"] - _last_net["errin"]) / dt
        eout = (net["errout"] - _last_net["errout"]) / dt
        din = (net["dropin"] - _last_net["dropin"]) / dt
        dout = (net["dropout"] - _last_net["dropout"]) / dt

    _last_disk = {
        "read_b": read_b, "write_b": write_b,
        "read_c": read_c, "write_c": write_c,
        "busy_time": busy_time,
    }
    if net:
        _last_net = dict(net)
    _last_ts = now_mono

    return SystemSample(
        timestamp=now_wall,
        rel_seconds=round(rel, 3),
        cpu_total_pct=float(cpu_total),
        cpu_per_core_pct=[float(c) for c in cpu_per_core],
        cpu_freq_current_mhz=freq,
        ctx_switches_per_sec=round(ctx_rate, 1) if ctx_rate is not None else None,
        interrupts_per_sec=round(int_rate, 1) if int_rate is not None else None,
        proc_queue_len=None,
        mem_total_bytes=int(vm.total),
        mem_available_bytes=int(vm.available),
        mem_used_bytes=int(vm.used),
        mem_percent=float(vm.percent),
        swap_total_bytes=int(sm.total),
        swap_used_bytes=int(sm.used),
        swap_percent=float(sm.percent),
        commit_used_bytes=None,
        commit_total_bytes=None,
        disk_read_bytes_per_sec=round(d_read_bps, 1),
        disk_write_bytes_per_sec=round(d_write_bps, 1),
        disk_read_count_per_sec=round(d_read_cps, 2),
        disk_write_count_per_sec=round(d_write_cps, 2),
        disk_active_pct_est=round(d_active_pct, 2),
        net_sent_bytes_per_sec=round(ns_bps, 1),
        net_recv_bytes_per_sec=round(nr_bps, 1),
        net_packets_sent_per_sec=round(nps_ps, 2),
        net_packets_recv_per_sec=round(npr_ps, 2),
        net_errin_per_sec=round(ein, 2),
        net_errout_per_sec=round(eout, 2),
        net_dropin_per_sec=round(din, 2),
        net_dropout_per_sec=round(dout, 2),
    )


def sample_to_dict(s: SystemSample) -> dict[str, Any]:
    d = asdict(s)
    d["cpu_per_core_pct"] = ";".join(f"{c:.1f}" for c in s.cpu_per_core_pct)
    return d
