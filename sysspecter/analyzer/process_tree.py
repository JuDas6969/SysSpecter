"""Process-tree reconstruction (Field-review A4).

Reconstructs the parent → child relationships visible in the run so
the report can answer the operator's first question — "what spawned
what" — with a glance instead of cross-referencing
`process_events.json` by hand.

The motivating example from the field review: an operator looking
at a Tableau workload had to read raw JSON to figure out

    Tableau Auto Report (PID X)
        → 15 child hyperd.exe instances
            → each spawning 4 MotoDB workers

Now this is one row per parent-child pair in the report:

    parent          child            instances  peak RSS (MB total)
    Tableau …       hyperd.exe       15         18 432
    hyperd.exe      MotoDB.exe       60         122 880

The data inputs are the H3 schema additions (`ppid`, `parent_name`
in `timeline_processes.csv`) and H4 (`process_events.json` always
written). For non-candidate parents — i.e. processes that exist on
the system but never made it into our top-N candidate set —
parent_name reads "(unknown)" and the row is still useful as
"these PIDs share an unknown ancestor".
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any


def build_process_tree(
    process_rows: list[dict[str, Any]],
    process_events: list[dict[str, Any]] | None = None,
    *,
    top_n_pairs: int = 50,
    pids_per_pair_cap: int = 25,
) -> dict[str, Any]:
    """Reconstruct the parent → child structure from per-sample
    process rows. Returns:

        {
            "by_parent": [
                {parent_name, child_name, pid_count, pids,
                 peak_rss_total_mb, total_samples}
                …  (sorted by peak_rss_total_mb desc, capped at top_n_pairs)
            ],
            "spawn_counts": {name: n_spawned_during_run},
            "exit_counts":  {name: n_exited_during_run},
            "total_pids_seen": int,
        }
    """
    process_events = process_events or []

    # 1. Per-PID summary. We pick the most-frequent (name, parent_name)
    # to handle PID recycling and the rare cases where the parent_name
    # cache resolved differently across samples.
    per_pid: dict[int, dict[str, Any]] = {}
    for r in process_rows:
        pid = r.get("pid")
        if pid is None:
            continue
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            continue
        name = r.get("name") or "?"
        parent_name = r.get("parent_name") or ""
        try:
            ppid = int(r.get("ppid") or 0)
        except (TypeError, ValueError):
            ppid = 0
        try:
            rss = int(r.get("rss_bytes") or 0)
        except (TypeError, ValueError):
            rss = 0

        entry = per_pid.setdefault(pid, {
            "pid": pid,
            "ppid": ppid,
            "_name_counts": defaultdict(int),
            "_parent_name_counts": defaultdict(int),
            "sample_count": 0,
            "peak_rss_bytes": 0,
        })
        entry["_name_counts"][name] += 1
        if parent_name:
            entry["_parent_name_counts"][parent_name] += 1
        entry["sample_count"] += 1
        if rss > entry["peak_rss_bytes"]:
            entry["peak_rss_bytes"] = rss

    # Resolve canonical name + parent_name per PID.
    for entry in per_pid.values():
        if entry["_name_counts"]:
            entry["name"] = max(
                entry["_name_counts"].items(), key=lambda kv: kv[1]
            )[0]
        else:
            entry["name"] = "?"
        if entry["_parent_name_counts"]:
            entry["parent_name"] = max(
                entry["_parent_name_counts"].items(), key=lambda kv: kv[1]
            )[0]
        else:
            entry["parent_name"] = ""
        del entry["_name_counts"]
        del entry["_parent_name_counts"]

    # 2. Aggregate by (parent_name, child_name).
    aggregates: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in per_pid.values():
        parent = entry["parent_name"] or "(unknown)"
        child = entry["name"]
        key = (parent, child)
        agg = aggregates.setdefault(key, {
            "parent_name": parent,
            "child_name": child,
            "pids": [],
            "peak_rss_total_bytes": 0,
            "total_samples": 0,
        })
        agg["pids"].append(entry["pid"])
        agg["peak_rss_total_bytes"] += entry["peak_rss_bytes"]
        agg["total_samples"] += entry["sample_count"]

    pairs: list[dict[str, Any]] = []
    for v in aggregates.values():
        pairs.append({
            "parent_name": v["parent_name"],
            "child_name": v["child_name"],
            "pid_count": len(v["pids"]),
            # Cap the PID list so the JSON stays readable on workloads
            # with hundreds of workers (top of the field review's
            # MotoDB case had 114 workers under one supervisor).
            "pids": sorted(v["pids"])[:pids_per_pair_cap],
            "peak_rss_total_mb": round(
                v["peak_rss_total_bytes"] / (1024 * 1024), 1
            ),
            "total_samples": v["total_samples"],
        })
    pairs.sort(key=lambda p: p["peak_rss_total_mb"], reverse=True)

    # 3. process_events spawn/exit counts during the run (one row per
    # process_started / process_exited). Useful for spotting churn —
    # e.g. "MotoDB.exe spawned 600 times" is its own diagnostic.
    spawn_counts: dict[str, int] = defaultdict(int)
    exit_counts: dict[str, int] = defaultdict(int)
    for e in process_events:
        kind = e.get("event")
        name = e.get("name") or "?"
        if kind in ("process_started", "process_create"):
            spawn_counts[name] += 1
        elif kind in ("process_exited", "process_exit"):
            exit_counts[name] += 1

    return {
        "by_parent": pairs[:top_n_pairs],
        "spawn_counts": dict(spawn_counts),
        "exit_counts": dict(exit_counts),
        "total_pids_seen": len(per_pid),
        "total_pairs_seen": len(aggregates),
    }
