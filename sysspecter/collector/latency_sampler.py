"""Latency sampler — ICMP via PowerShell `Test-Connection`.

Uses PowerShell because its output is structured (JSON) and locale-independent,
unlike `ping.exe` which emits localized text (German/French/etc.) that the
regex-based parser cannot reliably handle.

Low-overhead: 2 packets per target per probe cycle, summarized to one
avg/min/max/jitter/loss record. Probe cycle is expensive-tier
(every LATENCY_PROBE_INTERVAL seconds)."""

from __future__ import annotations

import json
import logging
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
class LatencySample:
    timestamp: float
    rel_seconds: float
    target: str
    count: int
    avg_ms: float | None
    min_ms: float | None
    max_ms: float | None
    jitter_ms: float | None
    loss_pct: float
    raw_times_ms: list[int]


def _probe_one(target: str, count: int, logger: logging.Logger | None) -> list[int]:
    """Return list of response times in ms for successful replies (may be empty)."""
    script = (
        f"$r = Test-Connection -Count {count} -ComputerName '{target}' "
        f"-ErrorAction SilentlyContinue; "
        f"if ($r) {{ $r | Select-Object ResponseTime,StatusCode | ConvertTo-Json -Compress }} "
        f"else {{ '[]' }}"
    )
    try:
        proc = subprocess.run(
            _PS_FLAGS + [script],
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=count * 2.0 + 5.0,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception as e:
        if logger:
            logger.warning("Test-Connection failed for %s: %s", target, e)
        return []
    out = (proc.stdout or "").strip()
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        if logger:
            logger.warning("Test-Connection json parse failed for %s: %s", target, out[:120])
        return []
    if isinstance(data, dict):
        data = [data]
    times: list[int] = []
    for row in data:
        if not isinstance(row, dict):
            continue
        if row.get("StatusCode") != 0:
            continue
        rt = row.get("ResponseTime")
        if rt is None:
            continue
        try:
            times.append(int(rt))
        except (TypeError, ValueError):
            pass
    return times


def collect_latency_sample(
    targets: list[str], started_mono: float, count: int = 2,
    logger: logging.Logger | None = None,
) -> list[LatencySample]:
    now_wall = time.time()
    rel = time.monotonic() - started_mono
    out: list[LatencySample] = []
    for t in targets:
        times = _probe_one(t, count=count, logger=logger)
        if times:
            avg = sum(times) / len(times)
            mn = float(min(times))
            mx = float(max(times))
            loss = round((1.0 - len(times) / count) * 100.0, 1) if count > 0 else 0.0
        else:
            avg = mn = mx = None
            loss = 100.0
        if len(times) >= 2:
            jitter = sum(abs(times[i] - times[i - 1]) for i in range(1, len(times))) / (len(times) - 1)
        else:
            jitter = None
        out.append(LatencySample(
            timestamp=now_wall,
            rel_seconds=round(rel, 3),
            target=t,
            count=count,
            avg_ms=avg,
            min_ms=mn,
            max_ms=mx,
            jitter_ms=round(jitter, 2) if jitter is not None else None,
            loss_pct=loss,
            raw_times_ms=times,
        ))
    return out


def sample_to_dict(s: LatencySample) -> dict[str, Any]:
    return {
        "timestamp": s.timestamp,
        "rel_seconds": s.rel_seconds,
        "target": s.target,
        "count": s.count,
        "avg_ms": s.avg_ms if s.avg_ms is not None else "",
        "min_ms": s.min_ms if s.min_ms is not None else "",
        "max_ms": s.max_ms if s.max_ms is not None else "",
        "jitter_ms": s.jitter_ms if s.jitter_ms is not None else "",
        "loss_pct": s.loss_pct,
        "raw_times_ms": ";".join(str(t) for t in s.raw_times_ms),
    }
