"""v3-priority-5 (H2): tests for the managed-heap leak analyzer.

The analyzer's two jobs:

1. Detect gen-2 heap growth — managed leaks (retained roots in .NET).
2. Diff RSS growth vs managed-heap growth — when RSS grows but the
   managed heap is flat, the leak is in unmanaged memory (the
   "native_only_leaks" finding category, the killer feature for
   COM / C++ leak diagnosis).

These tests pin both behaviours, plus the back-compat empty-input path.
"""

from __future__ import annotations

from sysspecter.analyzer.managed_heap import detect_managed_heap_leaks


def _heap_samples(
    pid: int,
    *,
    name: str = "leaky.exe",
    gen2_start_bytes: int = 1_000_000,
    gen2_growth_per_minute: float = 0.0,
    bytes_in_all_heaps_start: int | None = None,
    n: int = 10,
    interval_seconds: float = 30.0,
    gen2_collections_start: int = 0,
    gen2_collections_per_sample: int = 0,
) -> list[dict]:
    out = []
    bih_start = bytes_in_all_heaps_start or gen2_start_bytes * 2
    for i in range(n):
        rel = i * interval_seconds
        gen2 = gen2_start_bytes + int((gen2_growth_per_minute / 60.0) * rel)
        bih = bih_start + (gen2 - gen2_start_bytes)
        out.append({
            "rel_seconds": rel,
            "timestamp": 1000.0 + rel,
            "pid": pid,
            "name": name,
            "bytes_in_all_heaps": bih,
            "gen0_heap_size": 100_000,
            "gen1_heap_size": 200_000,
            "gen2_heap_size": gen2,
            "large_object_heap_size": 50_000,
            "gen0_collections": i * 5,
            "gen1_collections": i * 1,
            "gen2_collections": gen2_collections_start + i * gen2_collections_per_sample,
            "pct_time_in_gc": 1.0,
            "pinned_objects": 5,
            "allocated_bytes_per_sec": 0.0,
        })
    return out


def _process_samples(
    pid: int,
    *,
    name: str = "leaky.exe",
    rss_start_bytes: int = 50_000_000,
    rss_growth_per_minute: float = 0.0,
    n: int = 10,
    interval_seconds: float = 1.0,
) -> list[dict]:
    out = []
    for i in range(n):
        rel = i * interval_seconds
        rss = rss_start_bytes + int((rss_growth_per_minute / 60.0) * rel)
        out.append({
            "rel_seconds": rel,
            "pid": pid,
            "name": name,
            "rss_bytes": rss,
        })
    return out


# --- empty / back-compat ------------------------------------------

def test_empty_input_returns_empty_skeleton() -> None:
    out = detect_managed_heap_leaks([])
    assert out == {
        "samples_seen": 0,
        "managed_leaks": [],
        "native_only_leaks": [],
    }


def test_none_input_returns_empty_skeleton() -> None:
    """Defensive: legacy run loaders may pass None instead of []."""
    out = detect_managed_heap_leaks(None)
    assert out["managed_leaks"] == []


# --- gen-2 leak detection ----------------------------------------

def test_low_growth_below_threshold_does_not_fire() -> None:
    """10 KB/min is well below the 50 KB/min low threshold."""
    rows = _heap_samples(pid=100, gen2_growth_per_minute=10 * 1024)
    out = detect_managed_heap_leaks(rows)
    assert out["managed_leaks"] == []


def test_medium_growth_fires_medium_severity() -> None:
    """1 MB/min — squarely in the medium band."""
    rows = _heap_samples(pid=100, gen2_growth_per_minute=1024 * 1024)
    out = detect_managed_heap_leaks(rows)
    findings = out["managed_leaks"]
    assert len(findings) == 1
    f = findings[0]
    assert f["pid"] == 100
    assert f["severity"] == "medium"
    # The slope should round to roughly 1 MB/min ± numeric noise.
    assert 0.9 * 1024 * 1024 <= f["slope_bytes_per_minute"] <= 1.1 * 1024 * 1024
    assert f["delta_bytes"] > 0


def test_high_growth_fires_high_severity() -> None:
    """10 MB/min — definite leak."""
    rows = _heap_samples(pid=100, gen2_growth_per_minute=10 * 1024 * 1024)
    out = detect_managed_heap_leaks(rows)
    findings = out["managed_leaks"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["confidence"] == "high"


def test_too_few_samples_does_not_fire() -> None:
    """A run with only 2 snapshots can't support a slope claim."""
    rows = _heap_samples(pid=100, gen2_growth_per_minute=10 * 1024 * 1024, n=2)
    out = detect_managed_heap_leaks(rows)
    assert out["managed_leaks"] == []


def test_gen2_collections_observed_is_reported() -> None:
    """When gen-2 collections fire during the run AND gen-2 still
    grows, that's the textbook retained-roots scenario. Surface the
    collection count so the analyst can see GC ran but didn't help."""
    rows = _heap_samples(
        pid=100,
        gen2_growth_per_minute=2 * 1024 * 1024,
        gen2_collections_per_sample=1,  # 1 gen2 GC per sample
    )
    out = detect_managed_heap_leaks(rows)
    findings = out["managed_leaks"]
    assert len(findings) == 1
    # 10 samples × 1 = 9 collection deltas (last - first).
    assert findings[0]["gen2_collections_observed"] == 9


def test_findings_sorted_by_severity_then_slope() -> None:
    rows = (
        _heap_samples(pid=1, name="a", gen2_growth_per_minute=1024 * 1024)
        + _heap_samples(pid=2, name="b", gen2_growth_per_minute=10 * 1024 * 1024)
        + _heap_samples(pid=3, name="c", gen2_growth_per_minute=100 * 1024)
    )
    findings = detect_managed_heap_leaks(rows)["managed_leaks"]
    severities = [f["severity"] for f in findings]
    # high (PID 2) > medium (PID 1) > low (PID 3)
    assert severities == ["high", "medium", "low"]


# --- native-only diff (the killer feature) ----------------------

def test_native_only_leak_fires_when_rss_grows_but_managed_flat() -> None:
    """A C/C++/COM leak: RSS grows steadily, managed heap stays flat.
    This is what the analyzer should now be able to point at after
    v2 left it stuck at "consistent with COM RCW leak."
    """
    heap_rows = _heap_samples(
        pid=4242, name="motodb",
        gen2_growth_per_minute=0.0,  # managed heap flat
        bytes_in_all_heaps_start=20_000_000,
    )
    proc_rows = _process_samples(
        pid=4242, name="motodb",
        rss_growth_per_minute=10 * 1024 * 1024,  # 10 MB/min RSS growth
        n=300, interval_seconds=1.0,
    )
    out = detect_managed_heap_leaks(heap_rows, proc_rows)
    native = out["native_only_leaks"]
    assert len(native) == 1
    f = native[0]
    assert f["pid"] == 4242
    assert f["name"] == "motodb"
    # RSS growth rate matches what we set (~10 MB/min).
    assert 9 * 1024 * 1024 <= f["rss_slope_bytes_per_minute"] <= 11 * 1024 * 1024
    # Managed slope is essentially zero.
    assert abs(f["managed_slope_bytes_per_minute"]) < 100
    # Native-share is at or near 100%.
    assert f["ratio_native_share"] >= 0.99


def test_managed_only_leak_does_not_fire_native_only() -> None:
    """When RSS and managed grow together, the leak is managed —
    DON'T flag it as native_only (it'd be misleading)."""
    heap_rows = _heap_samples(
        pid=100, gen2_growth_per_minute=10 * 1024 * 1024,
    )
    # RSS grows the same amount the managed heap is growing.
    proc_rows = _process_samples(
        pid=100, rss_growth_per_minute=10 * 1024 * 1024,
        n=300, interval_seconds=1.0,
    )
    out = detect_managed_heap_leaks(heap_rows, proc_rows)
    assert out["native_only_leaks"] == []
    # But the gen2 leak finding still fires.
    assert len(out["managed_leaks"]) == 1


def test_no_rss_growth_does_not_fire_native_only() -> None:
    """If RSS isn't growing, there's no leak to attribute. Skip."""
    heap_rows = _heap_samples(pid=100, gen2_growth_per_minute=0.0)
    proc_rows = _process_samples(pid=100, rss_growth_per_minute=0.0)
    out = detect_managed_heap_leaks(heap_rows, proc_rows)
    assert out["native_only_leaks"] == []


def test_native_only_diff_skipped_when_no_process_rows() -> None:
    """Diff requires both heap_rows and process_rows. If process_rows
    is empty, the diff section is empty but managed_leaks still fires."""
    heap_rows = _heap_samples(pid=100, gen2_growth_per_minute=10 * 1024 * 1024)
    out = detect_managed_heap_leaks(heap_rows, [])
    assert out["managed_leaks"]  # gen-2 finding still fires
    assert out["native_only_leaks"] == []


def test_samples_seen_counts_unique_timestamps() -> None:
    """3 PIDs, each with 5 samples at the same 5 rel_seconds — 5 unique."""
    rows = (
        _heap_samples(pid=100, gen2_growth_per_minute=1024 * 1024, n=5)
        + _heap_samples(pid=200, gen2_growth_per_minute=1024 * 1024, n=5)
        + _heap_samples(pid=300, gen2_growth_per_minute=1024 * 1024, n=5)
    )
    out = detect_managed_heap_leaks(rows)
    assert out["samples_seen"] == 5
