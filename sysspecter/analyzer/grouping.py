"""Phase 2: group PIDs into logical applications.

Rationale: the per-PID offender list is noisy because a single app often spawns
many processes (Chrome renderers, svchost instances, multiple python.exe
workers). Grouping by executable name collapses these into one "app" row with
totals across instances, so the report surfaces "Chrome is using 2.4 GB"
instead of 40 separate chrome.exe entries.

Grouping strategy: by lowercased exe name, with display names looked up in
the C2 process catalog (`assets/process_catalog.json` plus user override).
Per-tick totals are computed by summing concurrent instances at each sample,
then aggregating across ticks — this yields correct peak concurrent CPU/RSS,
not just the max of any single PID."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..process_catalog import catalog as _catalog


def _app_key(name: str | None) -> str:
    if not name:
        return "?"
    return name.lower().strip()


def _display_name(key: str) -> str:
    """Pretty display name from the catalog, with fallback to title-case."""
    return _catalog().display_name(key)


def group_processes_by_app(
    process_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build per-app aggregates by summing concurrent PIDs at each sample.

    Returns a list of dicts mirroring the per-PID offender shape, with the
    addition of `pid_count`, `pids`, `app_key`, and `display_name`.
    """
    # Step 1: sum metrics per (app_key, rel_seconds) across PIDs
    per_tick: dict[tuple[str, float], dict[str, float]] = defaultdict(
        lambda: {"cpu_pct": 0.0, "rss_bytes": 0.0, "num_handles": 0.0,
                 "num_threads": 0.0, "io_read_bps": 0.0, "io_write_bps": 0.0}
    )
    app_pids: dict[str, set[int]] = defaultdict(set)
    app_is_target: dict[str, bool] = defaultdict(bool)
    app_first: dict[str, float] = {}
    app_last: dict[str, float] = {}

    for r in process_rows:
        key = _app_key(r.get("name"))
        pid = r.get("pid")
        rel = r.get("rel_seconds")
        if rel is None:
            continue
        rel = float(rel)
        t = per_tick[(key, rel)]
        t["cpu_pct"] += float(r.get("cpu_pct") or 0.0)
        t["rss_bytes"] += float(r.get("rss_bytes") or 0)
        t["num_handles"] += float(r.get("num_handles") or 0)
        t["num_threads"] += float(r.get("num_threads") or 0)
        t["io_read_bps"] += float(r.get("io_read_bps") or 0.0)
        t["io_write_bps"] += float(r.get("io_write_bps") or 0.0)
        if pid is not None:
            app_pids[key].add(int(pid))
        if int(r.get("is_target") or 0) == 1:
            app_is_target[key] = True
        if key not in app_first or rel < app_first[key]:
            app_first[key] = rel
        if key not in app_last or rel > app_last[key]:
            app_last[key] = rel

    # Step 2: per-app aggregates across ticks
    per_app: dict[str, dict[str, Any]] = {}
    for (key, _rel), metrics in per_tick.items():
        a = per_app.setdefault(key, {
            "app_key": key,
            "display_name": _display_name(key),
            "samples": 0,
            "cpu_pct_sum": 0.0, "cpu_pct_max": 0.0,
            "rss_bytes_max": 0.0,
            "num_handles_max": 0.0,
            "num_threads_max": 0.0,
            "io_read_bps_sum": 0.0, "io_write_bps_sum": 0.0,
            "io_read_bps_max": 0.0, "io_write_bps_max": 0.0,
        })
        a["samples"] += 1
        a["cpu_pct_sum"] += metrics["cpu_pct"]
        a["cpu_pct_max"] = max(a["cpu_pct_max"], metrics["cpu_pct"])
        a["rss_bytes_max"] = max(a["rss_bytes_max"], metrics["rss_bytes"])
        a["num_handles_max"] = max(a["num_handles_max"], metrics["num_handles"])
        a["num_threads_max"] = max(a["num_threads_max"], metrics["num_threads"])
        a["io_read_bps_sum"] += metrics["io_read_bps"]
        a["io_write_bps_sum"] += metrics["io_write_bps"]
        a["io_read_bps_max"] = max(a["io_read_bps_max"], metrics["io_read_bps"])
        a["io_write_bps_max"] = max(a["io_write_bps_max"], metrics["io_write_bps"])

    out: list[dict[str, Any]] = []
    for key, a in per_app.items():
        s = max(a["samples"], 1)
        pids = sorted(app_pids.get(key, set()))
        out.append({
            "app_key": key,
            "display_name": a["display_name"],
            "pid_count": len(pids),
            "pids": pids[:25],  # cap for readability
            "samples": a["samples"],
            "cpu_pct_avg": round(a["cpu_pct_sum"] / s, 2),
            "cpu_pct_max": round(a["cpu_pct_max"], 1),
            "rss_mb_max": round(a["rss_bytes_max"] / (1024 * 1024), 1),
            "num_handles_max": int(a["num_handles_max"]),
            "num_threads_max": int(a["num_threads_max"]),
            "io_read_bps_avg": round(a["io_read_bps_sum"] / s, 1),
            "io_write_bps_avg": round(a["io_write_bps_sum"] / s, 1),
            "io_read_bps_max": round(a["io_read_bps_max"], 1),
            "io_write_bps_max": round(a["io_write_bps_max"], 1),
            "is_target": app_is_target.get(key, False),
            "first_seen": app_first.get(key),
            "last_seen": app_last.get(key),
        })
    return out


def rank_apps(
    process_rows: list[dict[str, Any]], top_n: int = 10
) -> dict[str, list[dict[str, Any]]]:
    """Produce top-N ranked app lists across axes (mirrors rank_offenders shape)."""
    groups = group_processes_by_app(process_rows)

    # exclude synthetic "System Idle Process" since it's idle time, not workload
    groups = [g for g in groups if g["app_key"] != "system idle process"]

    cpu = sorted(groups, key=lambda g: (g["cpu_pct_avg"], g["cpu_pct_max"]), reverse=True)
    rss = sorted(groups, key=lambda g: g["rss_mb_max"], reverse=True)
    handles = sorted(groups, key=lambda g: g["num_handles_max"], reverse=True)
    threads = sorted(groups, key=lambda g: g["num_threads_max"], reverse=True)
    io = sorted(groups, key=lambda g: g["io_read_bps_avg"] + g["io_write_bps_avg"], reverse=True)

    return {
        "top_cpu": cpu[:top_n],
        "top_rss": rss[:top_n],
        "top_handles": handles[:top_n],
        "top_threads": threads[:top_n],
        "top_io": io[:top_n],
        "all_apps": sorted(groups, key=lambda g: g["cpu_pct_avg"] + g["rss_mb_max"] / 100, reverse=True),
    }
