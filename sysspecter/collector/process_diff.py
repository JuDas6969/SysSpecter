"""Detect process start/stop events by diffing enumeration snapshots."""

from __future__ import annotations

from typing import Any


def diff_process_snapshot(
    prev_pids: dict[int, dict[str, Any]],
    curr_pids: dict[int, dict[str, Any]],
    rel_seconds: float,
    timestamp: float,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for pid, info in curr_pids.items():
        if pid not in prev_pids:
            events.append({
                "event": "process_started",
                "pid": pid,
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "cmdline": info.get("cmdline"),
                "username": info.get("username"),
                "create_time": info.get("create_time"),
                "rel_seconds": round(rel_seconds, 3),
                "timestamp": timestamp,
            })
    for pid, info in prev_pids.items():
        if pid not in curr_pids:
            events.append({
                "event": "process_ended",
                "pid": pid,
                "name": info.get("name"),
                "rel_seconds": round(rel_seconds, 3),
                "timestamp": timestamp,
            })
    return events
