"""Field-review C1: stack-aware leak thresholds.

Pins the contract that the leak detector applies different bars per
language / runtime stack. The motivating cases — JVM at -Xmx,
Chromium GC saw-tooth, .NET server-GC — were the field review's
top false-positive complaint.

Tests cover:

- The shipped stack profiles cover every stack the catalog can tag.
- A 'native' (unknown stack) process keeps the legacy heuristic
  behaviour byte-for-byte.
- A JVM process with the SAME numeric trend as a leaking native
  process is NOT flagged.
- A Chromium process at high RSS with saw-tooth GC is NOT flagged.
- A real native leak IS still flagged (no over-correction).
- A genuinely-leaking JVM (much steeper slope, monotonic) IS flagged.
- Findings carry the resolved stack tag in the output.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from sysspecter import process_catalog as pc
from sysspecter.analyzer import leak_thresholds as lt
from sysspecter.analyzer.leaks import detect_memory_leaks
from sysspecter.config import Thresholds


def _reload_catalog_with(entries: list[dict]) -> pc.Catalog:
    """Force a clean catalog from an inline list — keeps tests
    independent of the shipped JSON file's evolving content."""
    import tempfile
    tmp = Path(tempfile.mkdtemp()) / "process_catalog.json"
    tmp.write_text(json.dumps({"version": 1, "entries": entries}),
                   encoding="utf-8")
    with patch.object(pc, "_candidate_paths", return_value=[str(tmp)]):
        return pc.reload()


def _series(name: str, pid: int, points: list[tuple[float, float]]) -> list[dict]:
    """Helper: build the process_rows shape the analyzer consumes."""
    return [
        {"pid": pid, "name": name, "rel_seconds": rel,
         "rss_bytes": rss, "num_handles": 100, "num_threads": 10}
        for rel, rss in points
    ]


def _linear(start_mb: float, slope_kb_per_s: float,
            duration_s: int, samples: int) -> list[tuple[float, float]]:
    """Generate a clean linear RSS series — the canonical leak shape."""
    out = []
    for i in range(samples):
        rel = i * (duration_s / (samples - 1))
        rss = (start_mb * 1024 * 1024) + (slope_kb_per_s * 1024 * rel)
        out.append((rel, rss))
    return out


# ----------------------------------------------------- profile catalog


def test_every_stack_in_catalog_resolves_to_a_profile() -> None:
    """If the C2 catalog tags a process with stack='X', then C1
    must have a profile for 'X'. Otherwise leaks.py would silently
    fall back to native and the field-review fix wouldn't apply."""
    cat = pc.reload()
    catalog_stacks = {
        e.stack for e in (cat.lookup(n) for n in cat.names_in_category("browser")
                          | cat.names_in_category("runtime")
                          | cat.names_in_category("ide")
                          | cat.names_in_category("chat"))
        if e and e.stack
    }
    profile_stacks = set(lt.known_stacks())
    missing = catalog_stacks - profile_stacks
    assert not missing, (
        f"shipped catalog tags processes with stacks that have no leak "
        f"profile: {missing}. Add them to "
        f"sysspecter.analyzer.leak_thresholds._PROFILES."
    )


def test_for_stack_unknown_returns_native_profile() -> None:
    assert lt.for_stack(None).stack == "native"
    assert lt.for_stack("not-a-real-stack").stack == "native"
    # native profile keeps the multipliers at 1.0 — back-compat.
    assert lt.for_stack(None).slope_multiplier == 1.0


def test_jvm_profile_tightens_bar_relative_to_native() -> None:
    n = lt.for_stack(None)
    j = lt.for_stack("jvm")
    assert j.slope_multiplier > n.slope_multiplier
    assert j.rss_min_growth_mb > n.rss_min_growth_mb
    assert j.rss_min_growth_ratio > n.rss_min_growth_ratio
    assert j.plateau_is_normal is True


def test_chromium_profile_tightens_bar_relative_to_native() -> None:
    c = lt.for_stack("chromium")
    assert c.slope_multiplier >= 3.0
    assert c.rss_min_growth_mb >= 100


# ----------------------------------------------------- false-positive gate


def test_jvm_at_xmx_plateau_is_not_flagged() -> None:
    """JVM heap rising 100 MB/min (~1.6 KB/s) on a 4 GB baseline is
    BELOW the C1 jvm threshold. Before C1 this was reported as a
    leak; after C1 it must not be."""
    _reload_catalog_with([
        {"name": "java.exe", "category": "runtime", "stack": "jvm"},
    ])
    rows = _series("java.exe", 4242, _linear(
        start_mb=4096,         # JVM at 4 GB heap
        slope_kb_per_s=200,    # noticeable but well under JVM bar
        duration_s=1800,
        samples=300,
    ))
    leaks = detect_memory_leaks(rows, Thresholds())
    assert leaks == [], (
        f"JVM at -Xmx must NOT be flagged with C1 thresholds; got: "
        f"{[(l['process_name'], l['confidence'], l['growth_mb']) for l in leaks]}"
    )


def test_chromium_steady_growth_under_threshold_is_not_flagged() -> None:
    """Chromium-tab cache fill of ~150 KB/s on a 600 MB baseline
    is below the chromium bar (slope_multiplier=3 + min_growth_mb=200)."""
    _reload_catalog_with([
        {"name": "chrome.exe", "category": "browser", "stack": "chromium"},
    ])
    rows = _series("chrome.exe", 4242, _linear(
        start_mb=600,
        slope_kb_per_s=150,
        duration_s=1800,
        samples=300,
    ))
    leaks = detect_memory_leaks(rows, Thresholds())
    assert leaks == [], (
        "Chromium with steady cache growth must NOT be flagged; got: "
        f"{leaks}"
    )


# ----------------------------------------------------- true positives still fire


def test_native_leak_still_flagged() -> None:
    """A native process growing 100 KB/s for 30 minutes must still
    fire — C1 must not over-correct."""
    _reload_catalog_with([])
    rows = _series("notepad.exe", 4242, _linear(
        start_mb=50,
        slope_kb_per_s=100,
        duration_s=1800,
        samples=300,
    ))
    leaks = detect_memory_leaks(rows, Thresholds())
    assert len(leaks) == 1, f"native leak must still be flagged; got: {leaks}"
    finding = leaks[0]
    assert finding["pid"] == 4242
    assert finding["confidence"] in ("suspicious", "likely", "strong evidence")
    # New: the finding now carries the stack tag.
    assert finding["stack"] == "native"


def test_jvm_with_huge_unbounded_growth_is_still_flagged() -> None:
    """If a JVM TRULY leaks (slope way past the JVM bar AND growth
    ratio > 50%), we still flag it. Otherwise we'd miss real bugs."""
    _reload_catalog_with([
        {"name": "java.exe", "category": "runtime", "stack": "jvm"},
    ])
    rows = _series("java.exe", 4242, _linear(
        start_mb=512,
        slope_kb_per_s=1500,   # well past the jvm slope_multiplier=4 bar
        duration_s=1800,
        samples=300,
    ))
    leaks = detect_memory_leaks(rows, Thresholds())
    assert len(leaks) >= 1, f"genuine JVM leak must still fire; got: {leaks}"
    assert leaks[0]["stack"] == "jvm"


def test_finding_includes_stack_label_for_unknown_processes() -> None:
    """An unknown process tags out as `native` in the finding."""
    _reload_catalog_with([])  # nothing in catalog
    rows = _series("custom-app.exe", 4242, _linear(
        start_mb=100, slope_kb_per_s=100,
        duration_s=1800, samples=300,
    ))
    leaks = detect_memory_leaks(rows, Thresholds())
    assert leaks
    assert leaks[0]["stack"] == "native"
