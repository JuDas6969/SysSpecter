"""Per-second process sampling with rolling top-N candidate set.

We don't enumerate every process every second. Instead:
- Every PROCESS_ENUM_REFRESH_INTERVAL seconds, enumerate all processes and
  refresh the candidate set = top-N by CPU ∪ top-N by RAM ∪ top-N by handles ∪
  top-N by I/O ∪ explicit target + known critical processes.
- Every second, sample only the candidate set (cheap).

This keeps per-second overhead low while still capturing offenders."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Iterable

import psutil

from ..config import TOP_N_PROCESSES, PROCESS_ENUM_REFRESH_INTERVAL

CRITICAL_NAMES = {
    "msmpeng.exe", "mssense.exe", "mpcmdrun.exe", "smartscreen.exe",
    "system", "system idle process", "registry", "secure system",
    "memory compression", "wmiprvse.exe", "svchost.exe", "lsass.exe",
    "csrss.exe", "services.exe", "wininit.exe",
}

_last_enum_time: float = 0.0
_candidate_pids: set[int] = set()
_proc_cache: dict[int, psutil.Process] = {}
_last_io: dict[int, tuple[int, int]] = {}  # pid -> (read_bytes, write_bytes)
_last_cpu_time: dict[int, tuple[float, float]] = {}  # pid -> (user, system) cumulative seconds
_last_sample_mono: float | None = None


@dataclass
class ProcessSample:
    pid: int
    name: str
    cpu_pct: float
    rss_bytes: int
    vms_bytes: int
    num_threads: int
    num_handles: int
    io_read_bps: float
    io_write_bps: float
    cpu_time_user: float
    cpu_time_system: float
    username: str | None
    ppid: int | None
    create_time: float | None
    is_target: bool


def _iter_enum(attrs: list[str]) -> Iterable[dict[str, Any]]:
    for p in psutil.process_iter(attrs=attrs):
        try:
            yield p.info, p
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def refresh_candidates(
    target_pid: int | None,
    target_name: str | None,
    target_path: str | None,
    top_n: int = TOP_N_PROCESSES,
) -> tuple[set[int], dict[int, str]]:
    """Enumerate processes and choose the candidate set. Returns (pids, names)."""
    global _candidate_pids, _proc_cache, _last_enum_time

    cpu_list: list[tuple[float, int, str]] = []
    rss_list: list[tuple[int, int, str]] = []
    handle_list: list[tuple[int, int, str]] = []
    io_list: list[tuple[int, int, str]] = []
    name_map: dict[int, str] = {}

    pid_to_proc: dict[int, psutil.Process] = {}
    target_hits: set[int] = set()
    target_name_lc = (target_name or "").lower()
    target_path_lc = (target_path or "").lower()

    for info, proc in _iter_enum([
        "pid", "name", "cpu_percent", "memory_info", "num_threads",
        "num_handles", "io_counters", "exe",
    ]):
        pid = info.get("pid")
        if pid is None:
            continue
        name = info.get("name") or "?"
        name_map[pid] = name
        pid_to_proc[pid] = proc

        if target_pid is not None and pid == target_pid:
            target_hits.add(pid)
        if target_name_lc and name.lower() == target_name_lc:
            target_hits.add(pid)
        if target_path_lc:
            exe = (info.get("exe") or "").lower()
            if exe == target_path_lc:
                target_hits.add(pid)

        try:
            cpu_pct = float(info.get("cpu_percent") or 0.0)
        except Exception:
            cpu_pct = 0.0
        cpu_list.append((cpu_pct, pid, name))

        mi = info.get("memory_info")
        rss = int(mi.rss) if mi else 0
        rss_list.append((rss, pid, name))

        handles = int(info.get("num_handles") or 0)
        handle_list.append((handles, pid, name))

        io = info.get("io_counters")
        io_total = int((io.read_bytes + io.write_bytes)) if io else 0
        io_list.append((io_total, pid, name))

    cpu_list.sort(reverse=True)
    rss_list.sort(reverse=True)
    handle_list.sort(reverse=True)
    io_list.sort(reverse=True)

    chosen: set[int] = set(target_hits)
    for coll in (cpu_list, rss_list, handle_list, io_list):
        for _, pid, _ in coll[:top_n]:
            chosen.add(pid)

    for pid, name in list(name_map.items()):
        if name.lower() in CRITICAL_NAMES:
            chosen.add(pid)

    _candidate_pids = {pid for pid in chosen if pid in pid_to_proc}
    _proc_cache = {pid: pid_to_proc[pid] for pid in _candidate_pids}
    _last_enum_time = time.monotonic()
    return _candidate_pids, name_map


def maybe_refresh_candidates(
    target_pid: int | None,
    target_name: str | None,
    target_path: str | None,
) -> bool:
    if (time.monotonic() - _last_enum_time) >= PROCESS_ENUM_REFRESH_INTERVAL:
        refresh_candidates(target_pid, target_name, target_path)
        return True
    return False


def collect_process_sample(
    target_pid: int | None,
    target_name: str | None,
    target_path: str | None,
) -> list[ProcessSample]:
    """Sample the candidate set. Cheap — only candidate processes are touched."""
    global _last_io, _last_sample_mono, _last_cpu_time

    now_mono = time.monotonic()
    dt = max(now_mono - _last_sample_mono, 1e-3) if _last_sample_mono else 1.0
    _last_sample_mono = now_mono

    target_name_lc = (target_name or "").lower()
    target_path_lc = (target_path or "").lower()

    samples: list[ProcessSample] = []
    dropped: list[int] = []

    for pid, proc in list(_proc_cache.items()):
        try:
            with proc.oneshot():
                name = proc.name()
                cpu_pct = proc.cpu_percent(interval=None)
                mi = proc.memory_info()
                nt = proc.num_threads()
                nh = None
                try:
                    nh = proc.num_handles()
                except Exception:
                    nh = 0
                io = None
                try:
                    io = proc.io_counters()
                except Exception:
                    io = None
                ct = proc.cpu_times()
                ppid = proc.ppid()
                try:
                    username = proc.username()
                except Exception:
                    username = None
                create_time = proc.create_time()
                exe_lc = ""
                if target_path_lc:
                    try:
                        exe_lc = (proc.exe() or "").lower()
                    except Exception:
                        exe_lc = ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            dropped.append(pid)
            continue
        except Exception:
            dropped.append(pid)
            continue

        if io is not None:
            prev = _last_io.get(pid)
            if prev is None:
                r_bps = w_bps = 0.0
            else:
                r_bps = max(0.0, (io.read_bytes - prev[0]) / dt)
                w_bps = max(0.0, (io.write_bytes - prev[1]) / dt)
            _last_io[pid] = (io.read_bytes, io.write_bytes)
        else:
            r_bps = w_bps = 0.0

        is_target = (
            (target_pid is not None and pid == target_pid)
            or (target_name_lc and name.lower() == target_name_lc)
            or (target_path_lc and exe_lc == target_path_lc)
        )

        samples.append(ProcessSample(
            pid=pid,
            name=name,
            cpu_pct=float(cpu_pct),
            rss_bytes=int(mi.rss),
            vms_bytes=int(mi.vms),
            num_threads=int(nt),
            num_handles=int(nh or 0),
            io_read_bps=round(r_bps, 1),
            io_write_bps=round(w_bps, 1),
            cpu_time_user=float(ct.user),
            cpu_time_system=float(ct.system),
            username=username,
            ppid=ppid,
            create_time=create_time,
            is_target=is_target,
        ))

    for pid in dropped:
        _proc_cache.pop(pid, None)
        _candidate_pids.discard(pid)
        _last_io.pop(pid, None)

    return samples


def sample_to_csv_row(s: ProcessSample, rel_seconds: float, timestamp: float) -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "rel_seconds": round(rel_seconds, 3),
        "pid": s.pid,
        "name": s.name,
        "cpu_pct": round(s.cpu_pct, 2),
        "rss_bytes": s.rss_bytes,
        "vms_bytes": s.vms_bytes,
        "num_threads": s.num_threads,
        "num_handles": s.num_handles,
        "io_read_bps": s.io_read_bps,
        "io_write_bps": s.io_write_bps,
        "cpu_time_user": round(s.cpu_time_user, 3),
        "cpu_time_system": round(s.cpu_time_system, 3),
        "username": s.username or "",
        "ppid": s.ppid or 0,
        "is_target": 1 if s.is_target else 0,
    }
