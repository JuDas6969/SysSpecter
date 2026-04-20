"""Periodic service-state snapshot + diff. Emits start/stop events."""

from __future__ import annotations

from typing import Any

import psutil

from .static import collect_service_snapshot


def diff_service_snapshot(
    prev: list[dict[str, Any]], curr: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Return events describing service state changes between two snapshots."""
    prev_map = {s["name"]: s for s in prev if s.get("name")}
    curr_map = {s["name"]: s for s in curr if s.get("name")}
    events: list[dict[str, Any]] = []

    for name, svc in curr_map.items():
        if name not in prev_map:
            events.append({
                "event": "service_added",
                "name": name,
                "display_name": svc.get("display_name"),
                "status": svc.get("status"),
                "start_type": svc.get("start_type"),
            })
            continue
        prev_svc = prev_map[name]
        if prev_svc.get("status") != svc.get("status"):
            events.append({
                "event": "service_status_change",
                "name": name,
                "display_name": svc.get("display_name"),
                "from_status": prev_svc.get("status"),
                "to_status": svc.get("status"),
            })
        if prev_svc.get("pid") != svc.get("pid") and svc.get("pid"):
            events.append({
                "event": "service_pid_change",
                "name": name,
                "display_name": svc.get("display_name"),
                "from_pid": prev_svc.get("pid"),
                "to_pid": svc.get("pid"),
            })

    for name, svc in prev_map.items():
        if name not in curr_map:
            events.append({
                "event": "service_removed",
                "name": name,
                "display_name": svc.get("display_name"),
            })

    return events


def refresh_and_diff_services(
    prev_snapshot: list[dict[str, Any]], rel_seconds: float, timestamp: float
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    curr = collect_service_snapshot()
    events = diff_service_snapshot(prev_snapshot, curr)
    for e in events:
        e["rel_seconds"] = round(rel_seconds, 3)
        e["timestamp"] = timestamp
    return curr, events
