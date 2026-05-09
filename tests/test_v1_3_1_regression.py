"""v1.3.1 regression tests — locks in the four production-feedback fixes.

The user's score-card on v1.3.0 surfaced four bugs that v1.3.1
addresses:

  1. `window_aligned_view` returned `no_data` for every row when
     both runs were < 1 h — the fresh-compute path bailed before
     producing scores. v1.3.1 adds a dynamic-window fallback
     (`dynamic_<n>s`) so any cohort with runs ≥ 60 s gets a
     length-fair frame.
  2. `peer_classes` returned None for MORGANA (off-domain ASRock
     desktop, 64 GB / 32 threads). The personal-desktop fallback
     read `cpu.count` but the static snapshot uses `cpu.logical_cores`.
  3. Verdict suppression only checked the winner's `trusted` flag,
     not whether participants got excluded. With ATLT4407 marked
     broken-cadence and excluded from rankings, v1.3.0 still
     published `best_overall` etc. as if MORGANA had won fair-and-
     square. v1.3.1 also requires no-exclusions for `trusted=True`.
  4. Suspect-4 mitigations (`__slots__` on per-sample dataclasses +
     ctypes array-type caching in system_sampler) reduce per-sample
     allocation churn even if the dominant residual leak is
     elsewhere.
"""

from __future__ import annotations

from sysspecter.collector.handles_sampler import HandleCount
from sysspecter.collector.latency_sampler import LatencySample
from sysspecter.collector.managed_heap_sampler import ManagedHeapSample
from sysspecter.collector.network_sampler import NetworkSample
from sysspecter.collector.process_sampler import ProcessSample
from sysspecter.collector.system_sampler import SystemSample
from sysspecter.comparer.cadence_quality import (
    HEALTH_BROKEN,
    HEALTH_GOOD,
    annotate_rankings,
)
from sysspecter.comparer.peer_context import (
    classify_from_static_snapshot,
    extract_machine_classes,
)
from sysspecter.comparer.window_alignment import (
    aligned_rankings,
    build_aligned_view,
    detect_aligned_window,
)

# --- Fix #1: window_aligned_view dynamic min-duration window -------

def test_window_aligned_view_falls_back_to_dynamic_when_runs_under_1h() -> None:
    """v1.3.0 left `alignment_status: no_data` for ATLT4407 (902 s) +
    MORGANA (1469 s) because neither canonical window fit. v1.3.1
    falls back to a dynamic window of 900 s (min(902, 1469)) so the
    aligned view actually produces metrics."""
    class _RD:
        def __init__(self, system_rows, latency_rows=None):
            self.system_rows = system_rows
            self.latency_rows = latency_rows or []
            self.process_rows = []
    # Need real per-sample timeseries so calculate_scores has signal
    sysrows = [
        {"rel_seconds": float(i), "cpu_total_pct": 20.0,
         "mem_percent": 40.0, "disk_active_pct_est": 5.0,
         "ctx_switches_per_sec": 1000.0, "interrupts_per_sec": 500.0}
        for i in range(900)
    ]
    loaded = [
        {"manifest": {"run_id": "ATLT4407", "duration_actual_seconds": 902.0,
                      "mode": "support"},
         "scores": {}, "findings": {"bottlenecks": {}}, "rd": _RD(sysrows)},
        {"manifest": {"run_id": "MORGANA", "duration_actual_seconds": 1469.0,
                      "mode": "support"},
         "scores": {}, "findings": {"bottlenecks": {}}, "rd": _RD(sysrows)},
    ]
    label = detect_aligned_window(loaded)
    # min(902, 1469) → 900 s rounded down to 10 s.
    assert label == "dynamic_900s"
    view = build_aligned_view(loaded, label)
    # Both rows must now have computed metrics, not no_data.
    statuses = {r["run_id"]: r["alignment_status"] for r in view["rows"]}
    assert statuses == {"ATLT4407": "aligned", "MORGANA": "aligned"}
    # And the rankings should have entries for both.
    ranks = aligned_rankings(loaded, label)
    overall = ranks.get("best_overall") or []
    assert len(overall) == 2


def test_window_aligned_view_returns_none_for_too_short_cohort() -> None:
    """v1.3.1: shortest run < 60 s → return None (comparison
    meaningless) rather than emit a misleadingly tiny window."""
    loaded = [
        {"manifest": {"run_id": "a", "duration_actual_seconds": 30.0},
         "scores": {}, "findings": {}, "rd": None},
        {"manifest": {"run_id": "b", "duration_actual_seconds": 30.0},
         "scores": {}, "findings": {}, "rd": None},
    ]
    assert detect_aligned_window(loaded) is None


# --- Fix #2: peer_classes personal-desktop fallback ----------------

def test_classify_morgana_personal_desktop_via_logical_cores() -> None:
    """v1.3.0 returned None for MORGANA because the classifier read
    `cpu.count` (doesn't exist) instead of `cpu.logical_cores`
    (canonical key set by static._cpu_info). v1.3.1 fixes the key
    chain — MORGANA (64 GB, 32 threads, ASRock motherboard, off-domain)
    now classifies as personal-desktop."""
    static = {
        "computer_system": {"Manufacturer": "ASRock",
                            "Model": "X870 Riptide WiFi"},
        "os": {"caption": "Microsoft Windows 11 Pro"},
        "installed_programs": [],
        "memory": {"total_bytes": 64 * 1024 ** 3},
        # Canonical static.cpu shape from static._cpu_info:
        "cpu": {"logical_cores": 32, "physical_cores": 16, "cpus": []},
    }
    manifest = {"hostname": "MORGANA", "fqdn": "MORGANA"}
    assert classify_from_static_snapshot(static, manifest) == "personal-desktop"


def test_classify_personal_desktop_via_motherboard_oem() -> None:
    """v1.3.1: a desktop-board OEM (ASRock / MSI / Gigabyte / EVGA)
    on a non-laptop, off-domain host classifies as personal-desktop
    even when the RAM/threads floor isn't reached. This catches the
    "hobbyist desktop" segment that v1.3.0 missed."""
    static = {
        "computer_system": {"Manufacturer": "MSI",
                            "Model": "PRO Z790-A WIFI"},
        "os": {"caption": "Microsoft Windows 11"},
        "installed_programs": [],
        "memory": {"total_bytes": 16 * 1024 ** 3},  # below 32 GB floor
        "cpu": {"logical_cores": 12, "physical_cores": 6, "cpus": []},
    }
    manifest = {"hostname": "GAMING-PC", "fqdn": "GAMING-PC"}
    assert classify_from_static_snapshot(static, manifest) == "personal-desktop"


def test_classify_morgana_via_extract_machine_classes_pipeline() -> None:
    """End-to-end: feed MORGANA through extract_machine_classes (the
    function the comparer actually calls). Result must populate
    machine_class + peer_group, NOT return None."""
    class _RD:
        def __init__(self, static):
            self.static = static
    static = {
        "computer_system": {"Manufacturer": "ASRock",
                            "Model": "X870 Riptide WiFi"},
        "os": {"caption": "Microsoft Windows 11 Pro"},
        "installed_programs": [],
        "memory": {"total_bytes": 64 * 1024 ** 3},
        "cpu": {"logical_cores": 32, "physical_cores": 16, "cpus": []},
    }
    loaded = [{
        "manifest": {"run_id": "r1", "hostname": "MORGANA",
                     "fqdn": "MORGANA", "meta": {}},
        "rd": _RD(static),
        "scores": {}, "findings": {},
    }]
    out = extract_machine_classes(loaded)
    assert out[0]["machine_class"] == "personal-desktop"
    assert out[0]["machine_class_source"] == "derived"
    # Bucket → workstation; rich form encodes 64GB:>32 threads.
    assert out[0]["peer_group"] == "workstation"
    # 32 threads falls into the `<=32` bucket (the next bucket up is
    # `>32`). 64 GB falls into the `64GB` bucket.
    assert out[0]["peer_group_detailed"] == "personal-desktop:64GB:<=32"


# --- Fix #3: verdict suppression "any untrusted participant" ------

def test_verdict_suppression_when_broken_cadence_excluded() -> None:
    """v1.3.0: when ATLT4407 was excluded from a sample-density-
    sensitive ranking due to broken cadence, the surviving MORGANA-
    only ranking was marked `trusted=True` (worst kept = good) and
    comparison_scores.json published all 6 verdicts. v1.3.1: any
    exclusion taints the ranking — `trusted=False` so the verdict
    suppression layer omits the key."""
    per_run = [
        {"run_id": "MORGANA", "cadence_health": HEALTH_GOOD},
        {"run_id": "ATLT4407", "cadence_health": HEALTH_BROKEN},
    ]
    rankings = {
        "best_efficiency": [("MORGANA", 80.0), ("ATLT4407", 75.0)],
    }
    annotated = annotate_rankings(rankings, per_run)
    out = annotated["best_efficiency"]
    # ATLT4407 was excluded; MORGANA still ranks. v1.3.0 set
    # trusted=True here (worst kept = good). v1.3.1: trusted=False
    # because excluding any participant means the comparison no
    # longer represents the full cohort.
    assert ("ATLT4407", "cadence_health=broken") in out["excluded"]
    assert out["trusted"] is False
    # MORGANA still has a per-cell value but the headline verdict
    # gating (in compare_runs._top_cadence_trusted) reads `trusted`
    # and omits the key when False.


def test_verdict_published_when_all_runs_healthy() -> None:
    """Sanity: when every participant is healthy, the ranking is
    trusted and verdicts publish normally."""
    per_run = [
        {"run_id": "a", "cadence_health": HEALTH_GOOD},
        {"run_id": "b", "cadence_health": HEALTH_GOOD},
    ]
    rankings = {"best_efficiency": [("a", 80.0), ("b", 75.0)]}
    annotated = annotate_rankings(rankings, per_run)
    out = annotated["best_efficiency"]
    assert out["trusted"] is True
    assert out["excluded"] == []


# --- Fix #4: __slots__ on per-sample dataclasses -------------------

def test_system_sample_has_slots() -> None:
    """v1.3.1 Suspect-4 mitigation: SystemSample uses __slots__ so
    each per-second instance saves ~80 bytes (no __dict__). Confirm
    the dataclass declaration kept the slots=True flag."""
    assert hasattr(SystemSample, "__slots__")
    assert "cpu_total_pct" in SystemSample.__slots__
    # Without __dict__, you can't add arbitrary attributes.
    sample = SystemSample(
        timestamp=0.0, rel_seconds=0.0, cpu_total_pct=0.0,
        cpu_per_core_pct=[], cpu_freq_current_mhz=None,
        ctx_switches_per_sec=None, interrupts_per_sec=None,
        proc_queue_len=None,
        mem_total_bytes=0, mem_available_bytes=0, mem_used_bytes=0,
        mem_percent=0.0, swap_total_bytes=0, swap_used_bytes=0,
        swap_percent=0.0, commit_used_bytes=None, commit_total_bytes=None,
        disk_read_bytes_per_sec=0.0, disk_write_bytes_per_sec=0.0,
        disk_read_count_per_sec=0.0, disk_write_count_per_sec=0.0,
        disk_active_pct_est=0.0, net_sent_bytes_per_sec=0.0,
        net_recv_bytes_per_sec=0.0, net_packets_sent_per_sec=0.0,
        net_packets_recv_per_sec=0.0, net_errin_per_sec=0.0,
        net_errout_per_sec=0.0, net_dropin_per_sec=0.0,
        net_dropout_per_sec=0.0, sample_late_ms=0.0, gap_seconds=0.0,
    )
    try:
        sample.unknown_field = 42  # type: ignore[attr-defined]
    except AttributeError:
        pass
    else:
        raise AssertionError("expected AttributeError — slots not effective")


def test_per_sample_dataclasses_all_have_slots() -> None:
    """Every per-second / per-snapshot sample dataclass should use
    slots=True for the same reason as SystemSample. The leak audit
    matters at scale — saving 80 bytes per process row × 50 PIDs ×
    1 sample/sec × 8 hours = 1.4 MB just on the process side."""
    for cls in (ProcessSample, NetworkSample, LatencySample,
                HandleCount, ManagedHeapSample):
        assert hasattr(cls, "__slots__"), f"{cls.__name__} missing __slots__"


# --- Fix #4: ctypes array-type caching ------------------------------

def test_freq_buffer_reuses_ctypes_array_across_calls() -> None:
    """v1.3.1: the cached _FREQ_BUF + _FREQ_BUF_SIZE module-level
    pair means repeated calls to _cpu_freq_via_ntpower reuse the
    same ctypes array instance instead of re-allocating. Each fresh
    ctypes type / array creates several KB of metadata that Python
    doesn't dedupe by value; the cache eliminates that allocation
    churn at the per-second hot loop."""
    import sys
    if sys.platform != "win32":
        return  # ctypes path is Windows-only
    from sysspecter.collector import system_sampler as ss
    # Reset the cache so we observe a fresh allocation.
    ss._FREQ_BUF = None
    ss._FREQ_BUF_SIZE = 0
    # First call populates the buffer.
    ss._cpu_freq_via_ntpower()
    first_buffer = ss._FREQ_BUF
    first_size = ss._FREQ_BUF_SIZE
    assert first_buffer is not None
    assert first_size > 0
    # Second call MUST reuse the same buffer object.
    ss._cpu_freq_via_ntpower()
    assert ss._FREQ_BUF is first_buffer
    assert ss._FREQ_BUF_SIZE == first_size
