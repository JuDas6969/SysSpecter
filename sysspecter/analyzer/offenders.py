"""Rank processes across multiple axes across the full run."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


def _aggregate_per_pid(
    process_rows: list[dict[str, Any]],
) -> dict[int, dict[str, Any]]:
    agg: dict[int, dict[str, Any]] = {}
    for r in process_rows:
        pid = r.get("pid")
        if pid is None:
            continue
        a = agg.setdefault(pid, {
            "pid": pid,
            "name": r.get("name") or "?",
            "ppid": r.get("ppid"),
            "samples": 0,
            "cpu_pct_sum": 0.0,
            "cpu_pct_max": 0.0,
            "rss_bytes_max": 0,
            "vms_bytes_max": 0,
            "num_handles_max": 0,
            "num_handles_min": 10**9,
            "num_threads_max": 0,
            "num_threads_min": 10**9,
            "io_read_bps_sum": 0.0,
            "io_write_bps_sum": 0.0,
            "io_read_bps_max": 0.0,
            "io_write_bps_max": 0.0,
            "cpu_time_user_last": 0.0,
            "cpu_time_system_last": 0.0,
            "is_target": int(r.get("is_target") or 0) == 1,
            "first_seen": r.get("rel_seconds"),
            "last_seen": r.get("rel_seconds"),
        })
        a["samples"] += 1
        a["name"] = r.get("name") or a["name"]
        cpu = r.get("cpu_pct") or 0.0
        a["cpu_pct_sum"] += cpu
        a["cpu_pct_max"] = max(a["cpu_pct_max"], cpu)
        a["rss_bytes_max"] = max(a["rss_bytes_max"], int(r.get("rss_bytes") or 0))
        a["vms_bytes_max"] = max(a["vms_bytes_max"], int(r.get("vms_bytes") or 0))
        nh = int(r.get("num_handles") or 0)
        if nh > 0:
            a["num_handles_max"] = max(a["num_handles_max"], nh)
            a["num_handles_min"] = min(a["num_handles_min"], nh)
        nt = int(r.get("num_threads") or 0)
        if nt > 0:
            a["num_threads_max"] = max(a["num_threads_max"], nt)
            a["num_threads_min"] = min(a["num_threads_min"], nt)
        a["io_read_bps_sum"] += r.get("io_read_bps") or 0.0
        a["io_write_bps_sum"] += r.get("io_write_bps") or 0.0
        a["io_read_bps_max"] = max(a["io_read_bps_max"], r.get("io_read_bps") or 0.0)
        a["io_write_bps_max"] = max(a["io_write_bps_max"], r.get("io_write_bps") or 0.0)
        a["cpu_time_user_last"] = r.get("cpu_time_user") or 0.0
        a["cpu_time_system_last"] = r.get("cpu_time_system") or 0.0
        a["is_target"] = a["is_target"] or (int(r.get("is_target") or 0) == 1)
        if a.get("first_seen") is None or (r.get("rel_seconds") is not None and r["rel_seconds"] < a["first_seen"]):
            a["first_seen"] = r.get("rel_seconds")
        if a.get("last_seen") is None or (r.get("rel_seconds") is not None and r["rel_seconds"] > a["last_seen"]):
            a["last_seen"] = r.get("rel_seconds")
    return agg


def rank_offenders(
    process_rows: list[dict[str, Any]], top_n: int = 10
) -> dict[str, list[dict[str, Any]]]:
    agg = _aggregate_per_pid(process_rows)
    items = list(agg.values())
    for it in items:
        s = max(it["samples"], 1)
        it["cpu_pct_avg"] = round(it["cpu_pct_sum"] / s, 2)
        it["io_read_bps_avg"] = round(it["io_read_bps_sum"] / s, 1)
        it["io_write_bps_avg"] = round(it["io_write_bps_sum"] / s, 1)
        it["rss_mb_max"] = round(it["rss_bytes_max"] / (1024 * 1024), 1)
        if it["num_handles_min"] == 10**9:
            it["num_handles_min"] = 0
        if it["num_threads_min"] == 10**9:
            it["num_threads_min"] = 0
        it["handle_growth"] = it["num_handles_max"] - it["num_handles_min"]
        it["thread_growth"] = it["num_threads_max"] - it["num_threads_min"]

    def _trim(e: dict[str, Any]) -> dict[str, Any]:
        return {
            "pid": e["pid"], "name": e["name"], "ppid": e.get("ppid"),
            "samples": e["samples"],
            "cpu_pct_avg": e["cpu_pct_avg"], "cpu_pct_max": round(e["cpu_pct_max"], 1),
            "rss_mb_max": e["rss_mb_max"],
            "num_handles_max": e["num_handles_max"], "handle_growth": e["handle_growth"],
            "num_threads_max": e["num_threads_max"], "thread_growth": e["thread_growth"],
            "io_read_bps_avg": e["io_read_bps_avg"], "io_write_bps_avg": e["io_write_bps_avg"],
            "is_target": e["is_target"],
        }

    cpu_sorted = sorted(items, key=lambda e: (e["cpu_pct_avg"], e["cpu_pct_max"]), reverse=True)
    rss_sorted = sorted(items, key=lambda e: e["rss_mb_max"], reverse=True)
    handles_sorted = sorted(items, key=lambda e: e["num_handles_max"], reverse=True)
    hgrow_sorted = sorted(items, key=lambda e: e["handle_growth"], reverse=True)
    threads_sorted = sorted(items, key=lambda e: e["num_threads_max"], reverse=True)
    tgrow_sorted = sorted(items, key=lambda e: e["thread_growth"], reverse=True)
    io_sorted = sorted(items, key=lambda e: e["io_read_bps_avg"] + e["io_write_bps_avg"], reverse=True)

    security_names = {"msmpeng.exe", "mssense.exe", "mpcmdrun.exe", "smartscreen.exe",
                      "nissrv.exe", "windowsdefender.exe"}
    sec_items = [e for e in items if (e["name"] or "").lower() in security_names]
    sec_sorted = sorted(sec_items, key=lambda e: e["cpu_pct_avg"] + e["io_read_bps_avg"] / 1e6, reverse=True)

    background_names = {"onedrive.exe", "teams.exe", "ms-teams.exe", "skype.exe",
                        "chrome.exe", "msedge.exe", "firefox.exe",
                        "searchindexer.exe", "searchhost.exe", "startmenuexperiencehost.exe",
                        "runtimebroker.exe", "yourphone.exe", "phoneexperiencehost.exe",
                        "dropbox.exe", "slack.exe", "adobe.exe", "creativecloud.exe"}
    bg_items = [e for e in items if (e["name"] or "").lower() in background_names]
    bg_sorted = sorted(bg_items, key=lambda e: e["cpu_pct_avg"] + e["rss_mb_max"] / 100, reverse=True)

    return {
        "top_cpu": [_trim(e) for e in cpu_sorted[:top_n]],
        "top_rss": [_trim(e) for e in rss_sorted[:top_n]],
        "top_handles": [_trim(e) for e in handles_sorted[:top_n]],
        "top_handle_growth": [_trim(e) for e in hgrow_sorted[:top_n] if e["handle_growth"] > 0],
        "top_threads": [_trim(e) for e in threads_sorted[:top_n]],
        "top_thread_growth": [_trim(e) for e in tgrow_sorted[:top_n] if e["thread_growth"] > 0],
        "top_io": [_trim(e) for e in io_sorted[:top_n]],
        "security": [_trim(e) for e in sec_sorted[:top_n]],
        "background_noise": [_trim(e) for e in bg_sorted[:top_n]],
    }


def process_churn_stats(process_events: list[dict[str, Any]]) -> dict[str, Any]:
    starts = sum(1 for e in process_events if e.get("event") == "process_started")
    ends = sum(1 for e in process_events if e.get("event") == "process_ended")
    counts: dict[str, int] = defaultdict(int)
    for e in process_events:
        if e.get("event") == "process_started":
            counts[e.get("name") or "?"] += 1
    top_starters = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    return {
        "total_process_starts": starts,
        "total_process_ends": ends,
        "top_spawners": [{"name": n, "starts": c} for n, c in top_starters],
    }
