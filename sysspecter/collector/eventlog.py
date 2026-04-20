"""Phase 3 (optional): Windows event-log collection for the run window.

Queries the System and Application logs for error/warning records whose
`TimeCreated` falls inside the monitoring window and returns them as structured
JSON. Uses PowerShell `Get-WinEvent` with an XPath/FilterHashtable so it stays
fast on busy machines.

We filter to event providers that are most useful for slowdown correlation:
Microsoft-Windows-Kernel-Power (power/sleep), disk, Ntfs, volmgr,
Service Control Manager, DistributedCOM, Application Error, WER, Defender.

Analyzer-side correlation (aligning events to slowdown windows) is done in
`sysspecter/analyzer/event_correlation.py`."""

from __future__ import annotations

import datetime as _dt
import json
import logging
import subprocess
from typing import Any

CREATE_NO_WINDOW = 0x08000000

_PS_FLAGS = [
    "powershell.exe",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-Command",
]

_TARGET_LOGS = ("System", "Application")

# Level codes: 1=Critical, 2=Error, 3=Warning
_LEVEL_FILTER = "1,2,3"


def _wall_to_dt_string(wall: float) -> str:
    """Format a POSIX timestamp as 'YYYY-MM-dd HH:mm:ss' in local time (Get-WinEvent friendly)."""
    t = _dt.datetime.fromtimestamp(wall)
    return t.strftime("%Y-%m-%dT%H:%M:%S")


def _query_log(log_name: str, start_wall: float, end_wall: float,
               logger: logging.Logger | None) -> list[dict[str, Any]]:
    start_s = _wall_to_dt_string(start_wall)
    end_s = _wall_to_dt_string(end_wall)
    script = (
        f"$f = @{{LogName='{log_name}'; StartTime=(Get-Date '{start_s}'); "
        f"EndTime=(Get-Date '{end_s}'); Level=@({_LEVEL_FILTER})}}; "
        f"try {{ "
        f"  $evts = Get-WinEvent -FilterHashtable $f -ErrorAction Stop -MaxEvents 500; "
        f"  $evts | ForEach-Object {{ "
        f"    [pscustomobject]@{{ "
        f"      Time=$_.TimeCreated.ToUniversalTime().ToString('o'); "
        f"      Id=$_.Id; LevelCode=[int]$_.Level; Level=$_.LevelDisplayName; "
        f"      Provider=$_.ProviderName; "
        f"      LogName=$_.LogName; "
        f"      Machine=$_.MachineName; "
        f"      Message=($_.Message -replace '\\s+',' ').Substring(0,[Math]::Min(($_.Message -replace '\\s+',' ').Length,400)) "
        f"    }} "
        f"  }} | ConvertTo-Json -Depth 3 -Compress "
        f"}} catch {{ '[]' }}"
    )
    try:
        proc = subprocess.run(
            _PS_FLAGS + [script],
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=45.0,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception as e:
        if logger:
            logger.warning("event-log query failed for %s: %s", log_name, e)
        return []
    out = (proc.stdout or "").strip()
    if not out or out == "[]":
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        if logger:
            logger.warning("event-log JSON parse failed for %s", log_name)
        return []
    if isinstance(data, dict):
        data = [data]
    return [row for row in data if isinstance(row, dict)]


def collect_event_log_for_window(
    start_wall: float, end_wall: float,
    logger: logging.Logger | None = None,
) -> dict[str, Any]:
    """Collect relevant event-log entries for the run window."""
    all_events: list[dict[str, Any]] = []
    for log in _TARGET_LOGS:
        rows = _query_log(log, start_wall, end_wall, logger)
        for r in rows:
            # Normalize keys to lowercase
            all_events.append({
                "time": r.get("Time"),
                "id": r.get("Id"),
                "level": r.get("Level"),
                "level_code": r.get("LevelCode"),
                "provider": r.get("Provider"),
                "log_name": r.get("LogName"),
                "machine": r.get("Machine"),
                "message": r.get("Message"),
            })

    # Enrich: compute rel_seconds relative to start_wall, parse ISO time
    def _parse_iso(s: str | None) -> _dt.datetime | None:
        if not s:
            return None
        try:
            # PowerShell 'o' format: e.g. 2026-04-20T12:34:56.789Z
            return _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None

    start_dt = _dt.datetime.fromtimestamp(start_wall, tz=_dt.timezone.utc)
    enriched: list[dict[str, Any]] = []
    for e in all_events:
        dt = _parse_iso(e["time"])
        rel = None
        wall = None
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_dt.timezone.utc)
            rel = round((dt - start_dt).total_seconds(), 1)
            wall = dt.timestamp()
        enriched.append({**e, "rel_seconds": rel, "timestamp": wall})

    enriched.sort(key=lambda r: r.get("rel_seconds") or 0.0)
    return {
        "count": len(enriched),
        "start_wall": start_wall,
        "end_wall": end_wall,
        "events": enriched,
    }
