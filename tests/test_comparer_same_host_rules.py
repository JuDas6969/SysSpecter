"""v3-priority-7: same-host comparison rules.

The v2 production review's most damning finding: the engine fired
NOTHING on the GPLT3923 7-run same-host corpus despite every run
reproducing the same MotoDB bug. These tests pin the seven rule
families that close that gap.

Each test uses a hand-built `loaded` cohort that mimics one of the
GPLT3923 patterns the engine missed:
- 4 of 6 runs sharing a tight memory-leak signature (run-cluster)
- MotoDB.exe spawning 1 / 68 / 114 PIDs across runs (regime change)
- RSS plateau + handles plateau + CPU → 0 across multiple runs
  (deterministic deadlock)
- network = 0 everywhere (ICMP-block invariant)
- a process appearing in top-5 across 5 of 7 runs (consistency)
- empty / sampler-died-early runs (exclusion gates)

A non-`before_after` (e.g. fleet) cohort is also pinned to confirm
the same-host-only rules do NOT fire there.
"""

from __future__ import annotations

from sysspecter.comparer.same_host_rules import (
    build_same_host_findings,
    detect_cross_run_invariants,
    detect_deterministic_deadlocks,
    detect_excluded_runs,
    detect_regime_changes,
    detect_run_clusters,
    detect_top_n_consistency,
)

# --- factories -----------------------------------------------------

class _RD:
    def __init__(self, *, system_rows=None, process_rows=None) -> None:
        self.system_rows = system_rows or []
        self.process_rows = process_rows or []


def _run(
    run_id: str, *,
    process_rows=None,
    system_rows=None,
    leaks_memory=None,
    network_score=None,
    gpu_analysis=None,
    offenders=None,
    duration_s: float = 1800.0,
    cadence_health: str = "good",
    median_gap: float = 1.0,
    hostname: str = "GPLT3923",
) -> dict:
    """Build a minimal `loaded` entry."""
    findings: dict = {
        "leaks": {"memory": leaks_memory or []},
        "offenders": offenders or {},
    }
    if gpu_analysis is not None:
        findings["gpu_analysis"] = gpu_analysis
    scores: dict = {}
    if network_score is not None:
        scores["network_impact"] = {"score": network_score}
    return {
        "manifest": {
            "run_id": run_id,
            "hostname": hostname,
            "duration_actual_seconds": duration_s,
            "cadence_quality": {
                "cadence_health": cadence_health,
                "median_gap_seconds": median_gap,
                "nominal_interval_seconds": 1.0,
            },
        },
        "scores": scores,
        "findings": findings,
        "rd": _RD(system_rows=system_rows, process_rows=process_rows),
    }


def _proc_samples_with_plateau(
    pid: int, name: str, *,
    n: int = 60,
    interval_s: float = 1.0,
    rss_max: int = 15 * 1024 ** 3,  # 15 GB
    handles_max: int = 29_000,
    tail_cpu: float = 0.5,
    growing_cpu: float = 80.0,
) -> list[dict]:
    """Generate process samples that grow then plateau (deadlock signature)."""
    out = []
    half = n // 2
    for i in range(n):
        rel = i * interval_s
        # First half: growing; second half: plateau at max.
        if i < half:
            rss = int(rss_max * (i + 1) / half)
            handles = int(handles_max * (i + 1) / half)
            cpu = growing_cpu
        else:
            rss = rss_max
            handles = handles_max
            cpu = tail_cpu
        out.append({
            "rel_seconds": rel,
            "pid": pid,
            "name": name,
            "rss_bytes": rss,
            "num_handles": handles,
            "cpu_pct": cpu,
        })
    return out


# --- Rule 1: run-cluster detection --------------------------------

def test_run_cluster_fires_when_4_of_6_runs_share_signature() -> None:
    """The GPLT3923 case: MotoDB leaks at 1716 / 1764 / 1781 / 1761
    KB/s on 4 of 6 runs (CV ~1.5%) — should fire a high-severity
    cluster finding."""
    runs = [
        _run("munderfing_1", leaks_memory=[{
            "name": "MotoDB.exe", "slope_bytes_per_second": 1716 * 1024,
            "end_rss_bytes": 15_400_000_000,
        }]),
        _run("munderfing", leaks_memory=[{
            "name": "MotoDB.exe", "slope_bytes_per_second": 1764 * 1024,
            "end_rss_bytes": 15_400_000_000,
        }]),
        _run("jerez_4", leaks_memory=[{
            "name": "MotoDB.exe", "slope_bytes_per_second": 1781 * 1024,
            "end_rss_bytes": 15_400_000_000,
        }]),
        _run("zuhause", leaks_memory=[{
            "name": "MotoDB.exe", "slope_bytes_per_second": 1761 * 1024,
            "end_rss_bytes": 15_400_000_000,
        }]),
        _run("worker_pool_1", leaks_memory=[]),
        _run("worker_pool_2", leaks_memory=[]),
    ]
    findings = detect_run_clusters(runs)
    cluster = [f for f in findings if f["kind"] == "run_cluster_leak_signature"]
    assert len(cluster) == 1
    f = cluster[0]
    assert f["severity"] == "high"  # 4/6 = 67% share = high
    assert f["confidence"] == "high"
    assert "MotoDB.exe" in f["hypothesis"]
    # CV must be quoted — 1.5% on these slopes
    assert "%" in f["hypothesis"]
    assert len(f["affected_runs"]) == 4


def test_run_cluster_does_not_fire_when_slopes_diverge() -> None:
    """Same process leaks in two runs but at very different slopes
    (200 KB/s vs 2000 KB/s). CV ~80% — no cluster."""
    runs = [
        _run("a", leaks_memory=[{"name": "x", "slope_bytes_per_second": 200_000}]),
        _run("b", leaks_memory=[{"name": "x", "slope_bytes_per_second": 2_000_000}]),
    ]
    assert detect_run_clusters(runs) == []


def test_run_cluster_needs_at_least_two_leaks() -> None:
    """Single leak doesn't form a cluster."""
    runs = [
        _run("a", leaks_memory=[{"name": "x", "slope_bytes_per_second": 1_000_000}]),
        _run("b", leaks_memory=[]),
    ]
    assert detect_run_clusters(runs) == []


# --- Rule 2: regime-change detection ------------------------------

def test_regime_change_fires_on_process_count_jump() -> None:
    """MotoDB.exe goes from 1 PID to 68 PIDs across runs. 68× ratio →
    well above the 10× threshold."""
    runs = [
        _run("single_worker", process_rows=[
            {"pid": 100, "name": "MotoDB.exe"},
        ]),
        _run("worker_pool", process_rows=[
            {"pid": 100 + i, "name": "MotoDB.exe"} for i in range(68)
        ]),
    ]
    findings = detect_regime_changes(runs)
    regime = [f for f in findings if f["kind"] == "process_regime_change"]
    assert len(regime) == 1
    assert "MotoDB.exe" in regime[0]["hypothesis"]
    # Ratio should be ~68
    assert "68" in regime[0]["hypothesis"] or "ratio" in regime[0]["hypothesis"]


def test_regime_change_does_not_fire_on_normal_jitter() -> None:
    """1 PID vs 2 PIDs is not a regime change — 2× ratio is normal."""
    runs = [
        _run("a", process_rows=[{"pid": 100, "name": "x"}]),
        _run("b", process_rows=[
            {"pid": 100, "name": "x"}, {"pid": 101, "name": "x"},
        ]),
    ]
    assert detect_regime_changes(runs) == []


# --- Rule 3: deterministic-deadlock signature ---------------------

def test_deterministic_deadlock_fires_when_two_runs_match() -> None:
    """RSS plateau + handles plateau + CPU → 0 in 2 of 3 runs on
    the same process name."""
    runs = [
        _run("run1", process_rows=_proc_samples_with_plateau(
            pid=4712, name="MotoDB.exe", n=60,
        )),
        _run("run2", process_rows=_proc_samples_with_plateau(
            pid=5230, name="MotoDB.exe", n=60,
        )),
        # Third run: same process but no deadlock (CPU stays high)
        _run("run3", process_rows=_proc_samples_with_plateau(
            pid=6001, name="MotoDB.exe", n=60,
            tail_cpu=80.0,  # still active — no deadlock
        )),
    ]
    findings = detect_deterministic_deadlocks(runs)
    dl = [f for f in findings if f["kind"] == "deterministic_deadlock"]
    assert len(dl) == 1
    assert dl[0]["severity"] == "high"
    assert "MotoDB.exe" in dl[0]["hypothesis"]
    assert len(dl[0]["affected_runs"]) == 2


def test_deterministic_deadlock_does_not_fire_for_single_run() -> None:
    """One run with the signature isn't a cross-run pattern."""
    runs = [
        _run("solo", process_rows=_proc_samples_with_plateau(
            pid=4712, name="MotoDB.exe",
        )),
    ]
    assert detect_deterministic_deadlocks(runs) == []


def test_deterministic_deadlock_skips_short_runs() -> None:
    """Tail-window analysis needs >= 30 samples per process."""
    runs = [
        _run("a", process_rows=_proc_samples_with_plateau(
            pid=1, name="x", n=10,
        )),
        _run("b", process_rows=_proc_samples_with_plateau(
            pid=1, name="x", n=10,
        )),
    ]
    assert detect_deterministic_deadlocks(runs) == []


# --- Rule 4: cross-run invariants --------------------------------

def test_cross_run_invariants_fires_when_network_zero_everywhere() -> None:
    """All runs show network_score = 0.0 → policy-block hypothesis."""
    runs = [
        _run("a", network_score=0.0),
        _run("b", network_score=0.0),
        _run("c", network_score=0.0),
    ]
    findings = detect_cross_run_invariants(runs)
    net = [f for f in findings if f["kind"] == "constant_network_zero"]
    assert len(net) == 1
    assert "policy-level block" in net[0]["hypothesis"]


def test_cross_run_invariants_does_not_fire_when_one_run_nonzero() -> None:
    """A single non-zero network score breaks the invariant."""
    runs = [
        _run("a", network_score=0.0),
        _run("b", network_score=80.0),
    ]
    findings = detect_cross_run_invariants(runs)
    assert [f for f in findings if f["kind"] == "constant_network_zero"] == []


def test_gpu_idle_drain_invariant_fires_when_all_runs_match() -> None:
    """Power > 5W and utilization < 1% across every run."""
    gpu = {
        "enabled": True,
        "adapters": [{"avg_power_w": 12.0, "avg_utilization_pct": 0.3}],
    }
    runs = [_run(f"r{i}", gpu_analysis=gpu) for i in range(3)]
    findings = detect_cross_run_invariants(runs)
    drain = [f for f in findings if f["kind"] == "constant_gpu_idle_drain"]
    assert len(drain) == 1


# --- Rule 5: top-N process consistency ---------------------------

def test_top_n_consistency_fires_when_process_in_top5_across_majority() -> None:
    """A process in top-5 in 5 of 7 runs is itself a finding."""
    in_top5 = {"cpu": [{"name": "MotoDB.exe", "cpu_pct": 80}]}
    out_top5 = {"cpu": [{"name": "explorer.exe", "cpu_pct": 5}]}
    runs = (
        [_run(f"r{i}", offenders=in_top5) for i in range(5)]
        + [_run(f"r{i}", offenders=out_top5) for i in range(5, 7)]
    )
    findings = detect_top_n_consistency(runs, metric="cpu")
    assert len(findings) >= 1
    motodb = [
        f for f in findings
        if "MotoDB.exe" in (f.get("hypothesis") or "")
    ]
    assert len(motodb) == 1


def test_top_n_consistency_threshold_is_50_percent() -> None:
    """A process appearing in top-5 in only 1 of 4 runs (25 %) should
    not fire — below the 50 % consistency threshold."""
    rare = {"cpu": [{"name": "rare.exe", "cpu_pct": 80}]}
    other_a = {"cpu": [{"name": "a.exe", "cpu_pct": 5}]}
    other_b = {"cpu": [{"name": "b.exe", "cpu_pct": 5}]}
    other_c = {"cpu": [{"name": "c.exe", "cpu_pct": 5}]}
    runs = [
        _run("r0", offenders=rare),
        _run("r1", offenders=other_a),
        _run("r2", offenders=other_b),
        _run("r3", offenders=other_c),
    ]
    findings = detect_top_n_consistency(runs, metric="cpu")
    # No process appears in >= 2 runs, so nothing fires.
    assert findings == []


# --- Rule 6: exclusion gates -------------------------------------

def test_exclusion_fires_for_zero_sample_run() -> None:
    """An empty run should be flagged not_comparable."""
    runs = [
        _run("empty", system_rows=[]),
        _run("normal", system_rows=[{"rel_seconds": i} for i in range(120)]),
    ]
    findings = detect_excluded_runs(runs)
    excl = [f for f in findings if f["kind"] == "not_comparable"]
    assert len(excl) >= 1
    assert any(f["run_id"] == "empty" for f in excl)


def test_exclusion_fires_for_short_run() -> None:
    """Runs shorter than the verdict floor are flagged."""
    runs = [
        _run("short",
             system_rows=[{"rel_seconds": i} for i in range(50)],
             duration_s=30.0),
    ]
    findings = detect_excluded_runs(runs)
    assert any(f["run_id"] == "short" for f in findings)


def test_exclusion_fires_for_broken_cadence() -> None:
    """Cadence broken (median gap >> nominal) → exclude."""
    runs = [
        _run("atlt",
             system_rows=[{"rel_seconds": i} for i in range(55)],
             cadence_health="broken", median_gap=18.1, duration_s=902.0),
    ]
    findings = detect_excluded_runs(runs)
    excl = [f for f in findings if f["run_id"] == "atlt"]
    assert len(excl) == 1
    # Evidence should mention cadence
    assert any("cadence" in e.lower() for e in excl[0]["evidence"])


def test_exclusion_does_not_fire_for_healthy_run() -> None:
    """A normal 5-min run with good cadence → no exclusion."""
    runs = [
        _run("ok",
             system_rows=[{"rel_seconds": i} for i in range(300)],
             duration_s=300.0, cadence_health="good", median_gap=1.0),
    ]
    assert detect_excluded_runs(runs) == []


# --- Top-level orchestrator gating -------------------------------

def test_same_host_rules_only_fire_in_before_after_mode() -> None:
    """In `fleet` mode, run-cluster / regime-change / deadlock /
    consistency rules must NOT fire — they only make sense same-host.
    Cross-run invariants + exclusions still fire (they're useful
    everywhere)."""
    runs = [
        _run("a", hostname="HostA",
             leaks_memory=[{"name": "x",
                            "slope_bytes_per_second": 1_000_000,
                            "end_rss_bytes": 1_000_000_000}]),
        _run("b", hostname="HostB",
             leaks_memory=[{"name": "x",
                            "slope_bytes_per_second": 1_010_000,
                            "end_rss_bytes": 1_000_000_000}]),
    ]
    findings = build_same_host_findings(runs, mode="fleet")
    same_host_only_kinds = {
        "run_cluster_leak_signature",
        "process_regime_change",
        "deterministic_deadlock",
        "top_cpu_consistency",
        "top_memory_consistency",
    }
    fired = {f["kind"] for f in findings}
    assert fired & same_host_only_kinds == set()


def test_same_host_rules_fire_in_before_after_mode() -> None:
    """In `before_after` mode, the same data fires rules."""
    runs = [
        _run("a",
             leaks_memory=[{"name": "x",
                            "slope_bytes_per_second": 1_000_000,
                            "end_rss_bytes": 1_000_000_000}]),
        _run("b",
             leaks_memory=[{"name": "x",
                            "slope_bytes_per_second": 1_010_000,
                            "end_rss_bytes": 1_000_000_000}]),
    ]
    findings = build_same_host_findings(runs, mode="before_after")
    fired_kinds = {f["kind"] for f in findings}
    assert "run_cluster_leak_signature" in fired_kinds


def test_same_host_orchestrator_runs_invariants_in_any_mode() -> None:
    """Cross-run invariants (rule 4) fire even in fleet mode — a
    constant network=0 across every host is still useful info."""
    runs = [
        _run("a", hostname="HostA", network_score=0.0),
        _run("b", hostname="HostB", network_score=0.0),
    ]
    findings = build_same_host_findings(runs, mode="fleet")
    assert any(f["kind"] == "constant_network_zero" for f in findings)


def test_same_host_orchestrator_handles_empty_loaded() -> None:
    """Defensive: empty `loaded` returns []."""
    assert build_same_host_findings([], mode="before_after") == []
