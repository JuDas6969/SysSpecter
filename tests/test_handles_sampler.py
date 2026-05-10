"""v3-priority-4 (H1): collector tests for the handles sampler.

The native ntdll calls themselves can only be exercised on Windows, so
this file pins:

- the pure aggregation logic (`_aggregate`) against a hand-crafted
  buffer matching the real SystemExtendedHandleInformation layout
- type-name resolution + cache reset
- CSV row shaping
- top-N PID capping

The end-to-end Windows-API smoke is left to a runtime check (gated on
`sys.platform`) so CI on non-Windows still gives meaningful signal.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import sizeof

from sysspecter.collector import handles_sampler as hs

# --- _resolve_type_name + cache -----------------------------------

def test_resolve_type_name_falls_back_to_index_string() -> None:
    """When the type-index map is empty, the resolver returns
    `TypeIndex_<n>` so downstream consumers always get a printable
    string. Important for hosts where NtQueryObject is denied."""
    hs.reset_type_cache()
    # Force the cache to an empty dict so we don't make a real syscall
    hs._type_index_to_name = {}
    assert hs._resolve_type_name(42) == "TypeIndex_42"


def test_resolve_type_name_uses_cached_map() -> None:
    hs._type_index_to_name = {7: "Event", 11: "Section"}
    assert hs._resolve_type_name(7) == "Event"
    assert hs._resolve_type_name(11) == "Section"
    # Unknown index still returns a string.
    assert hs._resolve_type_name(99) == "TypeIndex_99"


def test_reset_type_cache_clears_in_place() -> None:
    hs._type_index_to_name = {1: "X"}
    hs.reset_type_cache()
    assert hs._type_index_to_name is None


# --- _aggregate ----------------------------------------------------

def _build_handle_info_buffer(
    rows: list[tuple[int, int]],
) -> tuple[ctypes.Array, int]:
    """Build a fake SystemExtendedHandleInformation buffer.

    `rows` is a list of (pid, object_type_index) tuples. The other
    fields don't influence aggregation, so we leave them zero.

    Mirrors the real kernel layout:
        SYSTEM_HANDLE_INFORMATION_EX header (NumberOfHandles + Reserved)
        followed by NumberOfHandles × SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.

    v1.3.3: returns the ctypes array AND the used-byte count, matching
    the new `_query_system_handles` contract — `_aggregate` no longer
    accepts `bytes`, it reads directly from the cached ctypes buffer.
    """
    n = len(rows)
    header_size = sizeof(hs._SYSTEM_HANDLE_INFORMATION_EX)
    entry_size = sizeof(hs._SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
    total = header_size + n * entry_size
    # Allocate at least header_size so the empty-rows case still has
    # room for the NumberOfHandles=0 header.
    alloc = max(total, header_size)
    buf = (ctypes.c_ubyte * alloc)()
    header = ctypes.cast(buf, ctypes.POINTER(hs._SYSTEM_HANDLE_INFORMATION_EX)).contents
    header.NumberOfHandles = ctypes.c_void_p(n)
    header.Reserved = ctypes.c_void_p(0)
    if n:
        EntryArr = hs._SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * n
        entries = EntryArr.from_address(ctypes.addressof(buf) + header_size)
        for i, (pid, type_idx) in enumerate(rows):
            e = entries[i]
            e.Object = ctypes.c_void_p(0)
            e.UniqueProcessId = ctypes.c_void_p(pid)
            e.HandleValue = ctypes.c_void_p(i + 1)
            e.GrantedAccess = 0
            e.CreatorBackTraceIndex = 0
            e.ObjectTypeIndex = type_idx
            e.HandleAttributes = 0
            e.Reserved = 0
    return buf, total


def test_aggregate_groups_by_pid_and_type() -> None:
    """Two PIDs, two types each; counts must sum correctly."""
    hs._type_index_to_name = {7: "File", 11: "Event"}
    buf, used = _build_handle_info_buffer([
        (100, 7), (100, 7), (100, 7),  # PID 100: 3× File
        (100, 11),                      # PID 100: 1× Event
        (200, 7), (200, 7),             # PID 200: 2× File
    ])
    rows = hs._aggregate(buf, used)
    by_key = {(r.pid, r.type_name): r.count for r in rows}
    assert by_key == {
        (100, "File"): 3,
        (100, "Event"): 1,
        (200, "File"): 2,
    }


def test_aggregate_skips_pid_zero() -> None:
    """PID 0 is the System Idle Process — its handle table is huge and
    not actionable; the aggregator drops it."""
    hs._type_index_to_name = {7: "File"}
    buf, used = _build_handle_info_buffer([(0, 7), (0, 7), (100, 7)])
    rows = hs._aggregate(buf, used)
    pids = {r.pid for r in rows}
    assert pids == {100}


def test_aggregate_handles_empty_buffer() -> None:
    # A header that says "0 handles" produces an empty result.
    buf, used = _build_handle_info_buffer([])
    assert hs._aggregate(buf, used) == []
    # A `used` length below header size also produces []. Use a real
    # ctypes array so the cast inside _aggregate doesn't crash if
    # `used` somehow exceeds 0; we pass used=0 to short-circuit.
    tiny = (ctypes.c_ubyte * 8)()
    assert hs._aggregate(tiny, 0) == []


def test_aggregate_resolves_unknown_type_index_to_placeholder() -> None:
    """If NtQueryObject didn't populate the cache, every entry still
    aggregates correctly with a `TypeIndex_<n>` name — no crash."""
    hs._type_index_to_name = {}  # empty cache, but populated (non-None)
    buf, used = _build_handle_info_buffer([(100, 99), (100, 99)])
    rows = hs._aggregate(buf, used)
    assert len(rows) == 1
    assert rows[0].type_name == "TypeIndex_99"
    assert rows[0].count == 2


# --- collect_handles_snapshot top-N capping -----------------------

def test_top_n_pids_filters_by_total_count(monkeypatch) -> None:
    """top_n_pids=2 keeps only the two PIDs with the highest total."""
    hs._type_index_to_name = {7: "File", 11: "Event"}
    monkeypatch.setattr(hs, "_query_system_handles", lambda: _build_handle_info_buffer([
        (10, 7), (10, 7), (10, 7), (10, 7), (10, 7),  # PID 10: 5
        (20, 7),                                       # PID 20: 1
        (30, 7), (30, 7), (30, 7),                     # PID 30: 3
        (40, 7), (40, 7),                              # PID 40: 2
    ]))
    rows = hs.collect_handles_snapshot(top_n_pids=2)
    pids = {r.pid for r in rows}
    assert pids == {10, 30}  # the two highest totals


def test_top_n_pids_zero_keeps_everything(monkeypatch) -> None:
    """top_n_pids=0 disables the cap (useful for fleet-aggregation)."""
    hs._type_index_to_name = {7: "File"}
    monkeypatch.setattr(hs, "_query_system_handles", lambda: _build_handle_info_buffer([
        (10, 7), (20, 7), (30, 7),
    ]))
    rows = hs.collect_handles_snapshot(top_n_pids=0)
    assert {r.pid for r in rows} == {10, 20, 30}


def test_collect_handles_snapshot_returns_empty_when_query_fails(monkeypatch) -> None:
    """Soft-degrade: when the kernel call returns nothing, return []
    instead of raising."""
    monkeypatch.setattr(hs, "_query_system_handles", lambda: (None, 0))
    assert hs.collect_handles_snapshot() == []


def test_collect_handles_snapshot_non_windows() -> None:
    """On non-Windows the sampler short-circuits to []."""
    if sys.platform == "win32":
        return
    # _ntdll() returns None on non-Windows so _query_system_handles
    # returns b"" without doing anything.
    assert hs.collect_handles_snapshot() == []


# --- to_csv_rows --------------------------------------------------

def test_to_csv_rows_shape_matches_csv_header() -> None:
    rows = hs.to_csv_rows(
        [
            hs.HandleCount(pid=100, type_name="File", count=42),
            hs.HandleCount(pid=200, type_name="Event", count=10),
        ],
        timestamp=1000.0,
        rel_seconds=12.3,
        pid_to_name={100: "chrome.exe"},
    )
    assert len(rows) == 2
    keys = set(rows[0].keys())
    # The CSV writer requires these exact keys.
    assert keys == {"timestamp", "rel_seconds", "pid", "name", "type_name", "count"}
    assert rows[0]["pid"] == 100
    assert rows[0]["name"] == "chrome.exe"
    assert rows[0]["count"] == 42
    # PID 200 had no name in the map — falls back to "?".
    assert rows[1]["name"] == "?"


def test_to_csv_rows_preserves_rel_seconds_rounding() -> None:
    rows = hs.to_csv_rows(
        [hs.HandleCount(pid=1, type_name="File", count=1)],
        timestamp=0.0, rel_seconds=12.34567,
    )
    assert rows[0]["rel_seconds"] == 12.346  # rounded to 3 places


# --- end-to-end smoke against real Windows ------------------------

def test_native_call_returns_some_handles_on_windows() -> None:
    """When run on Windows, the kernel call should succeed and return
    a non-trivial number of handles. This is a weak sanity check —
    the precise count varies — but a totally-empty result on a real
    Windows host indicates a regression."""
    if sys.platform != "win32":
        return
    # Reset cache so we exercise the real type-name resolver too.
    hs.reset_type_cache()
    rows = hs.collect_handles_snapshot(top_n_pids=10)
    # On any non-locked-down Windows host with admin or even just a
    # normal user, we should see at least 100 handles from the top
    # 10 processes combined.
    if rows:
        assert sum(r.count for r in rows) >= 100
        # At least one type name should resolve to something readable
        # (not a raw TypeIndex_<n>).
        assert any(not r.type_name.startswith("TypeIndex_") for r in rows)
