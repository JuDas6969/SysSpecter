"""Field-review A4: process-tree reconstruction.

Pins the contract that the report can answer "what spawned what"
without the operator parsing raw process_events.json. Motivating
case from the field review:

    Tableau Auto Report (PID X) → 15 child hyperd.exe → 4 child MotoDB

The detector consumes:
- per-sample process rows (with H3's `parent_name` + `ppid`)
- process_events.json (H4 always-on)

and emits a parent → child aggregation that groups the 15 hyperd.exe
PIDs into a single row "Tableau Auto Report → 15 hyperd.exe".
"""

from __future__ import annotations

from sysspecter.analyzer.process_tree import build_process_tree


def _row(pid: int, name: str, ppid: int, parent_name: str,
         rel: float, rss_mb: float = 100.0) -> dict:
    return {
        "pid": pid, "name": name, "ppid": ppid, "parent_name": parent_name,
        "rel_seconds": rel, "rss_bytes": rss_mb * 1024 * 1024,
    }


# ----------------------------------------------------- happy path


def test_supervisor_with_n_children_collapses_to_one_row() -> None:
    """The whole point of A4: one supervisor + many workers should
    show up as a single 'parent → N × child' row, not N rows."""
    rows = []
    # Supervisor (1 PID, 60 samples)
    for t in range(60):
        rows.append(_row(1000, "supervisor.exe", 4, "services.exe",
                         rel=t, rss_mb=200))
    # 15 workers, each present for 30 samples
    for w_pid in range(2000, 2015):
        for t in range(30):
            rows.append(_row(w_pid, "worker.exe", 1000, "supervisor.exe",
                             rel=30 + t, rss_mb=80))

    tree = build_process_tree(rows)
    pairs = {(p["parent_name"], p["child_name"]): p
             for p in tree["by_parent"]}

    # services.exe → supervisor.exe (1 instance)
    assert ("services.exe", "supervisor.exe") in pairs
    assert pairs[("services.exe", "supervisor.exe")]["pid_count"] == 1

    # supervisor.exe → worker.exe (15 instances, collapsed)
    assert ("supervisor.exe", "worker.exe") in pairs
    workers_pair = pairs[("supervisor.exe", "worker.exe")]
    assert workers_pair["pid_count"] == 15
    # peak_rss_total = 15 × 80 MB
    assert 1100 < workers_pair["peak_rss_total_mb"] < 1300
    assert workers_pair["total_samples"] == 15 * 30


def test_three_level_hierarchy_emits_two_pair_rows() -> None:
    """X → 5 hyperd → 4 motodb each. Should produce two
    parent-child pair rows, NOT one nested tree."""
    rows = []
    # 1 X
    for t in range(60):
        rows.append(_row(1, "X.exe", 0, "(unknown)", rel=t, rss_mb=300))
    # 5 hyperd, each parented by X
    for h_pid in range(100, 105):
        for t in range(60):
            rows.append(_row(h_pid, "hyperd.exe", 1, "X.exe",
                             rel=t, rss_mb=200))
    # 4 motodb under each hyperd (= 20 total)
    pid = 1000
    for h_pid in range(100, 105):
        for _ in range(4):
            for t in range(60):
                rows.append(_row(pid, "motodb.exe", h_pid, "hyperd.exe",
                                 rel=t, rss_mb=400))
            pid += 1

    tree = build_process_tree(rows)
    pairs = {(p["parent_name"], p["child_name"]): p
             for p in tree["by_parent"]}
    assert pairs[("X.exe", "hyperd.exe")]["pid_count"] == 5
    assert pairs[("hyperd.exe", "motodb.exe")]["pid_count"] == 20


def test_unknown_parent_collapses_under_unknown_label() -> None:
    """Non-candidate parents (parent_name resolved to '') get
    grouped under '(unknown)' so the row is still useful for the
    operator to spot orphaned PIDs."""
    rows = [
        _row(101, "weird.exe", ppid=12345, parent_name="", rel=0),
        _row(101, "weird.exe", ppid=12345, parent_name="", rel=1),
    ]
    tree = build_process_tree(rows)
    pairs = [(p["parent_name"], p["child_name"]) for p in tree["by_parent"]]
    assert ("(unknown)", "weird.exe") in pairs


# ----------------------------------------------------- counts + ordering


def test_pairs_sorted_by_total_peak_rss_desc() -> None:
    rows = []
    # 'small' parent → 1 small child (10 MB)
    for t in range(60):
        rows.append(_row(1, "small.exe", 0, "(unknown)", rel=t, rss_mb=10))
        rows.append(_row(2, "small_child.exe", 1, "small.exe",
                         rel=t, rss_mb=5))
    # 'big' parent → 3 big children (each 500 MB)
    for t in range(60):
        rows.append(_row(10, "big.exe", 0, "(unknown)", rel=t, rss_mb=50))
    for cp in (11, 12, 13):
        for t in range(60):
            rows.append(_row(cp, "big_child.exe", 10, "big.exe",
                             rel=t, rss_mb=500))

    tree = build_process_tree(rows)
    # First entry must be the big_child row (3 × 500 MB = 1500 MB)
    assert tree["by_parent"][0]["child_name"] == "big_child.exe"
    assert tree["by_parent"][0]["peak_rss_total_mb"] >= 1400


def test_pids_capped_for_giant_worker_pools() -> None:
    """The MotoDB case had 114 workers under one supervisor — the
    JSON output must not blow up the report. Cap at the configured
    pids_per_pair_cap."""
    rows = []
    for w_pid in range(0, 200):
        rows.append(_row(w_pid, "worker.exe", 1, "supervisor.exe",
                         rel=0, rss_mb=10))
    tree = build_process_tree(rows, pids_per_pair_cap=25)
    pair = next(p for p in tree["by_parent"]
                if p["child_name"] == "worker.exe")
    assert pair["pid_count"] == 200, "count must reflect ALL pids"
    assert len(pair["pids"]) == 25, "pid LIST must be capped for size"


def test_process_recycling_uses_most_frequent_name() -> None:
    """Same PID, two different names across samples — the canonical
    name is the one that appeared most often, not the last one."""
    rows = []
    # PID 5 starts as cmd.exe (5 samples), then becomes notepad.exe (50 samples)
    for t in range(5):
        rows.append(_row(5, "cmd.exe", 1, "explorer.exe", rel=t))
    for t in range(50):
        rows.append(_row(5, "notepad.exe", 1, "explorer.exe", rel=5 + t))
    tree = build_process_tree(rows)
    pairs = [(p["parent_name"], p["child_name"]) for p in tree["by_parent"]]
    # The "winning" name is notepad.exe, NOT cmd.exe.
    assert ("explorer.exe", "notepad.exe") in pairs
    assert ("explorer.exe", "cmd.exe") not in pairs


# ----------------------------------------------------- process_events


def test_spawn_and_exit_counts_extracted_from_events() -> None:
    rows = [_row(1, "X.exe", 0, "(unknown)", rel=0)]
    events = [
        {"event": "process_started", "name": "MotoDB.exe", "pid": 100,
         "rel_seconds": 5},
        {"event": "process_started", "name": "MotoDB.exe", "pid": 101,
         "rel_seconds": 6},
        {"event": "process_exited", "name": "MotoDB.exe", "pid": 100,
         "rel_seconds": 30},
        {"event": "process_started", "name": "other.exe", "pid": 200,
         "rel_seconds": 10},
    ]
    tree = build_process_tree(rows, events)
    assert tree["spawn_counts"]["MotoDB.exe"] == 2
    assert tree["exit_counts"]["MotoDB.exe"] == 1
    assert tree["spawn_counts"]["other.exe"] == 1


def test_empty_input_returns_empty_tree() -> None:
    tree = build_process_tree([], [])
    assert tree["by_parent"] == []
    assert tree["total_pids_seen"] == 0
    assert tree["spawn_counts"] == {}
    assert tree["exit_counts"] == {}
