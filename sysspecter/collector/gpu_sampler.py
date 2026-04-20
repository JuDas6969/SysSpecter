"""Phase 3 (optional): GPU deep metrics via Windows performance counters.

Uses PowerShell `Get-Counter` to sample the public `\\GPU Engine(*)` and
`\\GPU Process Memory(*)` counters Windows 10/11 exposes. This gives:

- per-engine utilization percentage (engine = 3D / Compute / Copy / VideoDecode
  / VideoEncode, per physical GPU)
- per-process dedicated GPU memory usage (rollup per PID, in bytes)

Runs on the expensive tier (every EXPENSIVE_COLLECTOR_INTERVAL seconds) so
PowerShell invocation cost is amortized. Gracefully returns empty lists if
counters are unavailable or the call fails.

Optional: `nvidia-smi` is queried if present for adapter temperature / power,
which Windows counters do not expose."""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Any

CREATE_NO_WINDOW = 0x08000000

_PS_FLAGS = [
    "powershell.exe",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-Command",
]


@dataclass
class GpuEngineSample:
    timestamp: float
    rel_seconds: float
    engine_type: str
    luid: str
    utilization_pct: float


@dataclass
class GpuProcessSample:
    timestamp: float
    rel_seconds: float
    pid: int
    dedicated_bytes: int
    shared_bytes: int


@dataclass
class GpuAdapterSample:
    timestamp: float
    rel_seconds: float
    adapter: str
    temperature_c: float | None
    power_w: float | None
    mem_used_mb: float | None
    mem_total_mb: float | None
    utilization_pct: float | None


# Counter-instance pattern for GPU Engine, e.g.:
# "pid_1234_luid_0x00000000_0x0000A234_phys_0_eng_3_engtype_3D"
_ENGINE_PID_RE = re.compile(r"pid_(\d+)", re.I)
_ENGINE_LUID_RE = re.compile(r"luid_(0x[0-9A-Fa-f]+_0x[0-9A-Fa-f]+)", re.I)
_ENGINE_TYPE_RE = re.compile(r"engtype_([A-Za-z0-9]+)", re.I)
_PROC_MEM_PID_RE = re.compile(r"pid_(\d+)", re.I)


def _run_ps(script: str, timeout: float = 15.0) -> str | None:
    try:
        proc = subprocess.run(
            _PS_FLAGS + [script],
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        return None
    return (proc.stdout or "").strip() or None


def _get_counter_json(counter: str, logger: logging.Logger | None = None) -> list[dict[str, Any]]:
    """Returns list of {InstanceName, Value} for the given counter path."""
    script = (
        f"try {{ "
        f"  $c = Get-Counter -Counter '{counter}' -ErrorAction Stop; "
        f"  $c.CounterSamples | Select-Object InstanceName,CookedValue | ConvertTo-Json -Compress -Depth 2 "
        f"}} catch {{ '[]' }}"
    )
    out = _run_ps(script, timeout=12.0)
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        if logger:
            logger.warning("gpu counter parse failed for %s: %s", counter, out[:120])
        return []
    if isinstance(data, dict):
        data = [data]
    result: list[dict[str, Any]] = []
    for row in data:
        if not isinstance(row, dict):
            continue
        inst = row.get("InstanceName") or ""
        val = row.get("CookedValue")
        try:
            fval = float(val) if val is not None else 0.0
        except (TypeError, ValueError):
            fval = 0.0
        result.append({"instance": inst, "value": fval})
    return result


def _nvidia_smi_query() -> list[GpuAdapterSample]:
    exe = shutil.which("nvidia-smi")
    if not exe:
        return []
    try:
        proc = subprocess.run(
            [
                exe, "--query-gpu=name,temperature.gpu,power.draw,memory.used,memory.total,utilization.gpu",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=5.0, creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        return []
    if proc.returncode != 0:
        return []
    out: list[GpuAdapterSample] = []
    now_wall = time.time()
    for line in (proc.stdout or "").splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 6:
            continue

        def _f(s: str) -> float | None:
            try:
                return float(s)
            except (TypeError, ValueError):
                return None

        out.append(GpuAdapterSample(
            timestamp=now_wall,
            rel_seconds=0.0,
            adapter=parts[0],
            temperature_c=_f(parts[1]),
            power_w=_f(parts[2]),
            mem_used_mb=_f(parts[3]),
            mem_total_mb=_f(parts[4]),
            utilization_pct=_f(parts[5]),
        ))
    return out


def collect_gpu_snapshot(
    started_mono: float, logger: logging.Logger | None = None
) -> tuple[list[GpuEngineSample], list[GpuProcessSample], list[GpuAdapterSample]]:
    now_wall = time.time()
    rel = round(time.monotonic() - started_mono, 3)

    engine_raw = _get_counter_json(r"\GPU Engine(*)\Utilization Percentage", logger)
    # Bucket engine samples by (engine_type, luid), taking the max across pids
    # (Windows exposes one row per PID-using-engine; the machine total for an
    # engine is essentially the max over PIDs at a given instant).
    engine_buckets: dict[tuple[str, str], float] = {}
    for row in engine_raw:
        inst = row["instance"]
        m_type = _ENGINE_TYPE_RE.search(inst)
        m_luid = _ENGINE_LUID_RE.search(inst)
        engtype = m_type.group(1) if m_type else "?"
        luid = m_luid.group(1) if m_luid else "?"
        key = (engtype, luid)
        prev = engine_buckets.get(key, 0.0)
        # Windows sometimes returns values > 100 briefly; clamp.
        v = min(100.0, max(0.0, row["value"]))
        if v > prev:
            engine_buckets[key] = v

    engine_samples = [
        GpuEngineSample(
            timestamp=now_wall, rel_seconds=rel,
            engine_type=et, luid=luid, utilization_pct=round(util, 2),
        )
        for (et, luid), util in engine_buckets.items()
    ]

    # Per-process memory
    dedicated_raw = _get_counter_json(r"\GPU Process Memory(*)\Dedicated Usage", logger)
    shared_raw = _get_counter_json(r"\GPU Process Memory(*)\Shared Usage", logger)
    ded_by_pid: dict[int, int] = {}
    for row in dedicated_raw:
        m = _PROC_MEM_PID_RE.search(row["instance"])
        if not m:
            continue
        pid = int(m.group(1))
        ded_by_pid[pid] = ded_by_pid.get(pid, 0) + int(row["value"])
    shr_by_pid: dict[int, int] = {}
    for row in shared_raw:
        m = _PROC_MEM_PID_RE.search(row["instance"])
        if not m:
            continue
        pid = int(m.group(1))
        shr_by_pid[pid] = shr_by_pid.get(pid, 0) + int(row["value"])

    pids = set(ded_by_pid.keys()) | set(shr_by_pid.keys())
    proc_samples = [
        GpuProcessSample(
            timestamp=now_wall, rel_seconds=rel, pid=pid,
            dedicated_bytes=ded_by_pid.get(pid, 0),
            shared_bytes=shr_by_pid.get(pid, 0),
        )
        for pid in pids
    ]

    adapter_samples = _nvidia_smi_query()
    for a in adapter_samples:
        a.timestamp = now_wall
        a.rel_seconds = rel

    return engine_samples, proc_samples, adapter_samples


def engine_to_dict(s: GpuEngineSample) -> dict[str, Any]:
    return {
        "timestamp": s.timestamp, "rel_seconds": s.rel_seconds,
        "engine_type": s.engine_type, "luid": s.luid,
        "utilization_pct": s.utilization_pct,
    }


def proc_to_dict(s: GpuProcessSample) -> dict[str, Any]:
    return {
        "timestamp": s.timestamp, "rel_seconds": s.rel_seconds,
        "pid": s.pid,
        "dedicated_bytes": s.dedicated_bytes,
        "shared_bytes": s.shared_bytes,
    }


def adapter_to_dict(s: GpuAdapterSample) -> dict[str, Any]:
    return {
        "timestamp": s.timestamp, "rel_seconds": s.rel_seconds,
        "adapter": s.adapter,
        "temperature_c": s.temperature_c if s.temperature_c is not None else "",
        "power_w": s.power_w if s.power_w is not None else "",
        "mem_used_mb": s.mem_used_mb if s.mem_used_mb is not None else "",
        "mem_total_mb": s.mem_total_mb if s.mem_total_mb is not None else "",
        "utilization_pct": s.utilization_pct if s.utilization_pct is not None else "",
    }
