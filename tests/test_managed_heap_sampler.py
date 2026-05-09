"""v3-priority-5 (H2): tests for the managed-heap PDH sampler.

PDH itself can only be exercised on Windows with .NET apps running, so
this file pins:

- import-failure soft-degrade (when pywin32 is missing)
- non-Windows soft-degrade (returns [])
- empty-instance handling (when no .NET apps are around)
- instance-name → process-name parsing (covers `_p<pid>` suffix and
  PDH's `#<n>` disambiguator)
- CSV row shape (must match MANAGED_HEAP_FIELDS in csv_export.py)

End-to-end PDH calls are gated on `sys.platform == "win32"` and a
runtime check for at least one .NET app being present — they don't
fail CI on a host without .NET apps.
"""

from __future__ import annotations

import sys
from unittest.mock import patch

from sysspecter.collector import managed_heap_sampler as mh
from sysspecter.reporter.csv_export import MANAGED_HEAP_FIELDS


def test_non_windows_returns_empty() -> None:
    """On non-Windows the sampler short-circuits to []."""
    if sys.platform == "win32":
        return
    assert mh.collect_managed_heap_snapshot() == []


def test_pywin32_missing_returns_empty() -> None:
    """Locked-down host without pywin32 must soft-degrade to []."""
    with patch.object(mh, "_import_win32pdh", return_value=None):
        assert mh.collect_managed_heap_snapshot() == []


def test_no_dotnet_processes_returns_empty() -> None:
    """When `.NET CLR Memory` exists but has no instances (no .NET
    apps are running), return []."""
    fake = type("Fake", (), {})()
    with patch.object(mh, "_import_win32pdh", return_value=fake), \
         patch.object(mh, "_enum_instances", return_value=[]):
        assert mh.collect_managed_heap_snapshot() == []


def test_instance_name_to_proc_name_strips_pid_suffix() -> None:
    """Modern .NET emits `<exe>_p<pid>` instances. Strip the PID
    suffix for the human-readable process name."""
    assert mh._instance_name_to_proc_name("claude_p1234") == "claude"
    assert mh._instance_name_to_proc_name("powershell_p4242") == "powershell"


def test_instance_name_to_proc_name_strips_pdh_disambiguator() -> None:
    """PDH appends `#1`, `#2`, ... when multiple instances share a name."""
    assert mh._instance_name_to_proc_name("powershell#1") == "powershell"
    assert mh._instance_name_to_proc_name("powershell#2") == "powershell"


def test_instance_name_to_proc_name_handles_plain_name() -> None:
    """Older .NET emits just the exe name. Pass through unchanged."""
    assert mh._instance_name_to_proc_name("powershell") == "powershell"


def test_instance_name_to_proc_name_does_not_strip_random_underscores() -> None:
    """`_p` only strips when followed by digits — protect against
    false positives on names like `firefox_private`."""
    assert mh._instance_name_to_proc_name("firefox_private") == "firefox_private"


def test_to_csv_rows_shape_matches_csv_header() -> None:
    """The CSV writer expects exactly MANAGED_HEAP_FIELDS keys; pin the
    contract so a refactor can't silently drop a field."""
    sample = mh.ManagedHeapSample(
        pid=1234, name="claude",
        bytes_in_all_heaps=10_000_000,
        gen0_heap_size=2_000_000,
        gen1_heap_size=2_000_000,
        gen2_heap_size=4_000_000,
        large_object_heap_size=2_000_000,
        gen0_collections=50,
        gen1_collections=10,
        gen2_collections=2,
        pct_time_in_gc=3.5,
        pinned_objects=42,
        allocated_bytes_per_sec=12345.6,
    )
    rows = mh.to_csv_rows([sample], timestamp=1000.0, rel_seconds=12.34567)
    assert len(rows) == 1
    row = rows[0]
    # Every field declared in csv_export.MANAGED_HEAP_FIELDS must be
    # present and exactly that key set.
    assert set(row.keys()) == set(MANAGED_HEAP_FIELDS)
    assert row["pid"] == 1234
    assert row["name"] == "claude"
    assert row["bytes_in_all_heaps"] == 10_000_000
    assert row["gen2_heap_size"] == 4_000_000
    assert row["pct_time_in_gc"] == 3.5
    assert row["rel_seconds"] == 12.346  # 3-decimal rounding


def test_to_csv_rows_handles_empty_input() -> None:
    assert mh.to_csv_rows([], timestamp=0.0, rel_seconds=0.0) == []


def test_native_call_smoke_runs_without_raising() -> None:
    """End-to-end smoke on a real Windows host: the call must return a
    list without raising. We don't assert content because a CI runner
    typically has zero .NET apps; the host the developer runs locally
    may have many."""
    if sys.platform != "win32":
        return
    result = mh.collect_managed_heap_snapshot()
    assert isinstance(result, list)
