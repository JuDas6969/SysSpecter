"""Per-second system sample: CPU, RAM, disk, network totals."""

from __future__ import annotations

import ctypes
import time
from ctypes import wintypes
from dataclasses import asdict, dataclass
from typing import Any

import psutil

from ..logging_setup import get_logger

_log = get_logger(__name__)


# ---- Win32 GlobalMemoryStatusEx for commit charge ---------------------
# psutil's swap_memory() reports a derived "swap" number that subtracts
# physical RAM from the page-file total — useful, but NOT the same as
# Windows' commit charge. The Task-Manager "Commit (KB)" is exactly
# ullTotalPageFile - ullAvailPageFile, so we read it directly.

class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def _commit_charge() -> tuple[int | None, int | None]:
    """Return (commit_used_bytes, commit_total_bytes) from Win32, or
    (None, None) on non-Windows / API failure."""
    try:
        m = _MEMORYSTATUSEX()
        m.dwLength = ctypes.sizeof(m)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
            used = int(m.ullTotalPageFile - m.ullAvailPageFile)
            total = int(m.ullTotalPageFile)
            return used, total
    except Exception:
        _log.debug("GlobalMemoryStatusEx failed", exc_info=True)
    return None, None


# ---- CallNtPowerInformation for real per-CPU current frequency --------
# Field-review B4: WMI's CurrentClockSpeed (which psutil.cpu_freq reads
# via the same registry path) reports the chipset's NOMINAL P-state and
# never reflects turbo on modern parts — every value across six runs on
# an i7-13800H read 1532 / 2500 MHz, never the 5.2 GHz the silicon
# was actually running at. The kernel-power API exposes per-logical-CPU
# CurrentMhz, which DOES reflect P-state changes including turbo.
# Reporting `max(CurrentMhz)` across all logical CPUs catches even
# single-core boosts that a single-CPU read would miss.

class _PROCESSOR_POWER_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Number", wintypes.ULONG),
        ("MaxMhz", wintypes.ULONG),
        ("CurrentMhz", wintypes.ULONG),
        ("MhzLimit", wintypes.ULONG),
        ("MaxIdleState", wintypes.ULONG),
        ("CurrentIdleState", wintypes.ULONG),
    ]


_PROCESSOR_INFORMATION = 11  # ProcessorInformation enum value
_STATUS_SUCCESS = 0


def _cpu_freq_via_ntpower() -> tuple[float | None, float | None, float | None]:
    """Return (peak_current_mhz, avg_current_mhz, max_documented_mhz)
    across all logical CPUs, or (None, None, None) on failure.

    `peak_current_mhz` is what we surface as the timeline's primary
    frequency value: max CurrentMhz across all logical CPUs at this
    instant, so any single-core turbo boost is captured.
    """
    try:
        n_cpus = psutil.cpu_count(logical=True) or 1
        arr_t = _PROCESSOR_POWER_INFORMATION * n_cpus
        arr = arr_t()
        rc = ctypes.windll.powrprof.CallNtPowerInformation(
            _PROCESSOR_INFORMATION, None, 0,
            ctypes.byref(arr), ctypes.sizeof(arr_t),
        )
    except Exception:
        _log.debug("CallNtPowerInformation unavailable", exc_info=True)
        return None, None, None
    if rc != _STATUS_SUCCESS:
        _log.debug("CallNtPowerInformation rc=%s", rc)
        return None, None, None
    current = [int(c.CurrentMhz) for c in arr if c.CurrentMhz > 0]
    max_vals = [int(c.MaxMhz) for c in arr if c.MaxMhz > 0]
    if not current:
        return None, None, None
    peak = float(max(current))
    avg = float(sum(current)) / len(current)
    max_doc = float(max(max_vals)) if max_vals else None
    return peak, avg, max_doc

_last_disk: dict[str, Any] | None = None
_last_net: dict[str, Any] | None = None
_last_ts: float | None = None


@dataclass
class SystemSample:
    timestamp: float
    rel_seconds: float
    cpu_total_pct: float
    cpu_per_core_pct: list[float]
    # Peak CurrentMhz across all logical CPUs from the kernel-power
    # API (CallNtPowerInformation). Reflects turbo boost on at least
    # one core when any core is boosting. Field-review B4-fixed; the
    # legacy WMI / psutil.cpu_freq path that capped at the nominal
    # P-state is no longer used.
    cpu_freq_current_mhz: float | None
    ctx_switches_per_sec: float | None
    interrupts_per_sec: float | None
    # Deprecated — never populated. Kept as None for CSV-schema
    # backwards compatibility; will be removed in schema v3.
    proc_queue_len: float | None
    mem_total_bytes: int
    mem_available_bytes: int
    mem_used_bytes: int
    mem_percent: float
    swap_total_bytes: int
    swap_used_bytes: int
    swap_percent: float
    # Windows commit charge from GlobalMemoryStatusEx, NOT the same as
    # swap_used (which subtracts RAM). This is the value Task Manager
    # shows as "Committed".
    commit_used_bytes: int | None
    commit_total_bytes: int | None
    disk_read_bytes_per_sec: float
    disk_write_bytes_per_sec: float
    disk_read_count_per_sec: float
    disk_write_count_per_sec: float
    # Estimated from psutil disk_io_counters().busy_time delta —
    # accurate on HDDs, biased LOW on NVMe (where the controller can
    # service many concurrent ops without blocking). Treat as a
    # qualitative indicator, not a measurement. The full fix is to
    # consume the `\PhysicalDisk(*)\% Disk Time` perfcounter; tracked
    # in ROADMAP.md "B5".
    disk_active_pct_est: float
    net_sent_bytes_per_sec: float
    net_recv_bytes_per_sec: float
    net_packets_sent_per_sec: float
    net_packets_recv_per_sec: float
    net_errin_per_sec: float
    net_errout_per_sec: float
    net_dropin_per_sec: float
    net_dropout_per_sec: float
    # How many milliseconds late this sample fired vs. its scheduled
    # tick. > 500 ms means the sampler was preempted under load — a
    # consumer can use this to distinguish "system idle" from "we
    # missed it" when reading the timeline.
    sample_late_ms: float


_last_cpu_stats: tuple[float, int, int] | None = None


def _cpu_stats_rates() -> tuple[float | None, float | None]:
    """Return (ctx_switches_per_sec, interrupts_per_sec).

    psutil exposes the underlying PDH counters which are 32-bit on some
    Windows builds and roll over after several days of uptime — when
    that happens the raw delta goes massively negative (~ -1.5e8 in
    field reports). We detect any negative delta and surface it as
    ``None`` instead of poisoning the timeline with a fake huge spike.
    """
    global _last_cpu_stats
    try:
        st = psutil.cpu_stats()
    except Exception:
        _log.debug("cpu_stats unavailable", exc_info=True)
        return None, None
    now = time.monotonic()
    if _last_cpu_stats is None:
        _last_cpu_stats = (now, st.ctx_switches, st.interrupts)
        return None, None
    prev_t, prev_ctx, prev_int = _last_cpu_stats
    dt = max(now - prev_t, 1e-3)
    ctx_delta = st.ctx_switches - prev_ctx
    int_delta = st.interrupts - prev_int
    _last_cpu_stats = (now, st.ctx_switches, st.interrupts)
    # Guard against PDH counter rollover (delta would go negative).
    ctx_rate = (ctx_delta / dt) if ctx_delta >= 0 else None
    int_rate = (int_delta / dt) if int_delta >= 0 else None
    if ctx_rate is None or int_rate is None:
        _log.debug("cpu_stats counter rollover detected (skipped)")
    return ctx_rate, int_rate


def _freq_mhz() -> float | None:
    """Return the peak CurrentMhz across all logical CPUs.

    Falls back to psutil.cpu_freq() (which reads WMI's nominal value)
    only when CallNtPowerInformation is unavailable — e.g. inside very
    locked-down sandboxes that block powrprof.dll. The fall-back is
    documented as a known soft-degrade.
    """
    peak, _avg, _max_doc = _cpu_freq_via_ntpower()
    if peak is not None:
        return peak
    try:
        f = psutil.cpu_freq()
        return float(f.current) if f else None
    except Exception:
        _log.debug("cpu_freq fallback unavailable", exc_info=True)
        return None


def _disk_totals() -> tuple[float, float, float, float, int, int]:
    try:
        io = psutil.disk_io_counters()
    except Exception:
        _log.debug("disk_io_counters unavailable", exc_info=True)
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
        _log.debug("net_io_counters unavailable", exc_info=True)
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


def collect_system_sample(
    started_mono: float, scheduled_at: float | None = None
) -> SystemSample:
    """Collect one per-second system sample. Uses monotonic clock for rate math.

    `scheduled_at` is the monotonic time the runner originally intended
    this tick to fire. Late samples (sampler preempted under load) are
    surfaced as ``sample_late_ms`` so consumers can distinguish "system
    was idle" from "we missed a tick."
    """
    global _last_disk, _last_net, _last_ts

    now_wall = time.time()
    now_mono = time.monotonic()
    rel = now_mono - started_mono
    if scheduled_at is None:
        late_ms = 0.0
    else:
        late_ms = max(0.0, (now_mono - scheduled_at) * 1000.0)

    cpu_total = psutil.cpu_percent(interval=None)
    cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
    freq = _freq_mhz()
    ctx_rate, int_rate = _cpu_stats_rates()

    vm = psutil.virtual_memory()
    sm = psutil.swap_memory()
    commit_used, commit_total = _commit_charge()

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
        commit_used_bytes=commit_used,
        commit_total_bytes=commit_total,
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
        sample_late_ms=round(late_ms, 1),
    )


def sample_to_dict(s: SystemSample) -> dict[str, Any]:
    d = asdict(s)
    d["cpu_per_core_pct"] = ";".join(f"{c:.1f}" for c in s.cpu_per_core_pct)
    return d
