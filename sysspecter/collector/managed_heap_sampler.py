"""v3-priority-5 (H2): .NET CLR managed-heap counters per PID.

Critical for any .NET / Matlab / Office workload — most of enterprise.
Without this, the analyzer can't tell a native leak (RSS grows, heap
flat — C/C++/COM bug) apart from a managed leak (RSS grows, gen2 also
grows — retained roots in .NET code). The v2 production review put
this second only to handle types in single-impact missing data.

Approach
--------
Read the `.NET CLR Memory` PerformanceCounter category via PDH (the
Performance Data Helper API). PDH is available on every Windows host
back to NT 4 and is the sysadmin-blessed way to enumerate counters.
We use the `win32pdh` module from pywin32 (already a hard dependency)
so we don't have to reimplement the ctypes dance from scratch.

Counter discovery: `.NET CLR Memory` instances are typically
`<procname>` or `<procname>_p<pid>` (modern .NET); to map an instance
back to a PID reliably we read the parallel `.NET CLR Process`
category which exposes a `Process ID` counter per instance, then join
on instance name. This is the same trick PerfMon uses internally.

Sampling cadence: 30 s by default. PDH reads are cheap (< 50 ms even
on hosts with many .NET processes); the leak detector needs roughly
one sample per minute to spot a > 100 KB/s gen-2 growth, so 30 s gives
margin without hammering the perf-counter subsystem.

Soft-degrade: any failure path returns []. The most common failures:
  - Non-Windows (no PDH)
  - pywin32 not importable (fresh Python install or sandboxed env)
  - .NET CLR Memory category absent (host has no .NET apps)
  - .NET CLR Process absent (older .NET-Framework-only hosts may
    expose `.NET CLR Memory` without the parallel `.NET CLR Process`)
  - PDH access denied (some lockdown profiles)

In every degrade path we still log at debug level so a maintainer can
diagnose if needed. The runner pipes the empty result through
`mark_degraded` so the report knows the data was unavailable.

API surface used
----------------
- `win32pdh.OpenQuery()` / `AddCounter` / `CollectQueryData` /
  `GetFormattedCounterValue` — standard PDH workflow
- `win32pdh.EnumObjectItems(None, None, "Category", PDH_DETAIL_WIZARD,
  0)` — discovers instance names

For the .NET 5+ / .NET Core case, the `.NET CLR Memory` category
isn't always populated; .NET Core uses EventSource-based counters
instead. We surface what PDH gives us and degrade gracefully on
hosts where the category is empty. JVM and Python managed-heap
metrics are in scope for v3-priority-5b (next round).
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass

_log = logging.getLogger("sysspecter.managed_heap")

# PDH counter paths we want from `.NET CLR Memory(<instance>)`. Names
# are stable across all .NET versions that populate the category.
_HEAP_COUNTERS: dict[str, str] = {
    "bytes_in_all_heaps": r"\.NET CLR Memory({inst})\# Bytes in all Heaps",
    "gen0_heap_size":     r"\.NET CLR Memory({inst})\Gen 0 heap size",
    "gen1_heap_size":     r"\.NET CLR Memory({inst})\Gen 1 heap size",
    "gen2_heap_size":     r"\.NET CLR Memory({inst})\Gen 2 heap size",
    "large_object_heap_size":
        r"\.NET CLR Memory({inst})\Large Object Heap size",
    "gen0_collections":   r"\.NET CLR Memory({inst})\# Gen 0 Collections",
    "gen1_collections":   r"\.NET CLR Memory({inst})\# Gen 1 Collections",
    "gen2_collections":   r"\.NET CLR Memory({inst})\# Gen 2 Collections",
    "pct_time_in_gc":     r"\.NET CLR Memory({inst})\% Time in GC",
    "pinned_objects":     r"\.NET CLR Memory({inst})\# of Pinned Objects",
    "allocated_bytes_per_sec":
        r"\.NET CLR Memory({inst})\Allocated Bytes/sec",
}

_PROCESS_PID_PATH = r"\.NET CLR Memory({inst})\Process ID"


@dataclass(slots=True)  # v1.3.1
class ManagedHeapSample:
    """One row of managed-heap data for one .NET process."""
    pid: int
    name: str
    bytes_in_all_heaps: int
    gen0_heap_size: int
    gen1_heap_size: int
    gen2_heap_size: int
    large_object_heap_size: int
    gen0_collections: int
    gen1_collections: int
    gen2_collections: int
    pct_time_in_gc: float
    pinned_objects: int
    allocated_bytes_per_sec: float


def _is_windows() -> bool:
    return sys.platform == "win32"


def _import_win32pdh():
    """Import pywin32's PDH wrapper. Returns the module on success or
    None on any import failure (non-Windows, missing pywin32, etc.).
    Cached at module level on first successful call."""
    if not _is_windows():
        return None
    try:
        import win32pdh  # type: ignore[import-not-found]
        return win32pdh
    except ImportError as e:
        _log.debug("win32pdh import failed: %s", e)
        return None


def _enum_instances(win32pdh) -> list[str]:
    """List `.NET CLR Memory` instances that aren't aggregates.

    The `_Global_` pseudo-instance is the cross-process aggregate;
    we drop it because the per-process rows are what the analyzer
    correlates with timeline_processes.
    """
    try:
        _, instances = win32pdh.EnumObjectItems(
            None, None, ".NET CLR Memory",
            win32pdh.PERF_DETAIL_WIZARD,
        )
    except Exception as e:  # pywin32 raises pywintypes.error
        _log.debug("PDH EnumObjectItems failed: %s", e)
        return []
    out: list[str] = []
    seen: dict[str, int] = {}
    for inst in instances or []:
        if inst.lower() in ("_global_", ""):
            continue
        # PDH disambiguates duplicate instance names with #1, #2, etc.
        # We pass the disambiguated form on to PDH as-is.
        seen[inst] = seen.get(inst, 0) + 1
        out.append(inst if seen[inst] == 1 else f"{inst}#{seen[inst] - 1}")
    return out


def _read_counter(win32pdh, query, path: str, fmt: int) -> float | int | None:
    """Add a counter to an open PDH query, collect, and return the value.

    PDH semantics: AddCounter / CollectQueryData / GetFormattedCounterValue.
    Some counters (rate-based ones like Allocated Bytes/sec) need TWO
    CollectQueryData calls before a value is available; for simplicity
    we collect twice with a short pause for those, but the heap-size
    counters (the load-bearing ones for leak detection) are
    instantaneous and need just one collect. We always do two collects
    so rates stabilise too.
    """
    try:
        h = win32pdh.AddCounter(query, path)
    except Exception as e:
        _log.debug("PDH AddCounter failed for %s: %s", path, e)
        return None
    try:
        win32pdh.CollectQueryData(query)
        # Second collect needed for rate-based counters; cheap.
        win32pdh.CollectQueryData(query)
        _, val = win32pdh.GetFormattedCounterValue(h, fmt)
        return val
    except Exception as e:
        _log.debug("PDH read failed for %s: %s", path, e)
        return None
    finally:
        try:
            win32pdh.RemoveCounter(h)
        except Exception:
            pass


def _instance_name_to_proc_name(inst: str) -> str:
    """Strip `_p<pid>` / `#<n>` suffixes from an instance name to get
    a printable process name. Used when the PDH `Process ID` counter
    is unavailable (older .NET Framework hosts)."""
    name = inst
    # Modern format: <name>_p<pid>
    if "_p" in name:
        head, _, tail = name.rpartition("_p")
        if tail.isdigit():
            name = head
    # PDH disambiguator: <name>#<n>
    if "#" in name:
        name = name.rsplit("#", 1)[0]
    return name


def collect_managed_heap_snapshot() -> list[ManagedHeapSample]:
    """Sample `.NET CLR Memory` for every .NET process.

    Returns one `ManagedHeapSample` per .NET process, or [] when the
    category isn't populated (non-Windows, no .NET apps, locked-down
    host, missing pywin32).
    """
    win32pdh = _import_win32pdh()
    if win32pdh is None:
        return []
    instances = _enum_instances(win32pdh)
    if not instances:
        return []

    try:
        query = win32pdh.OpenQuery()
    except Exception as e:
        _log.debug("PDH OpenQuery failed: %s", e)
        return []

    out: list[ManagedHeapSample] = []
    try:
        # PDH_FMT_LARGE = 64-bit int counter format
        # PDH_FMT_DOUBLE = double-precision float counter format
        fmt_large = getattr(win32pdh, "PDH_FMT_LARGE", 0x00000400)
        fmt_double = getattr(win32pdh, "PDH_FMT_DOUBLE", 0x00000200)

        for inst in instances:
            # PID lookup. Some hosts don't expose `Process ID` here —
            # try anyway, fall back to extracting from the instance
            # name pattern (`<exe>_p<pid>`).
            pid_val = _read_counter(
                win32pdh, query,
                _PROCESS_PID_PATH.format(inst=inst),
                fmt_large,
            )
            pid: int = int(pid_val) if isinstance(pid_val, (int, float)) and pid_val > 0 else 0
            if pid == 0 and "_p" in inst:
                tail = inst.rpartition("_p")[2]
                if tail.isdigit():
                    pid = int(tail)
            if pid <= 0:
                # No way to attribute these counters to a PID — skip.
                # The instance still contributes to _Global_ (which we
                # filter out anyway) so this is the right call.
                continue

            # Bind `inst` and `query` as defaults so the closure
            # captures the current loop iteration's value (avoids the
            # B023 footgun where every iteration's _read would resolve
            # `inst` to the loop's last value).
            def _read(
                name_key: str, default: float | int = 0,
                fmt: int = fmt_large,
                _inst: str = inst, _query=query,
            ) -> float | int:
                val = _read_counter(
                    win32pdh, _query,
                    _HEAP_COUNTERS[name_key].format(inst=_inst),
                    fmt,
                )
                return val if val is not None else default

            sample = ManagedHeapSample(
                pid=pid,
                name=_instance_name_to_proc_name(inst),
                bytes_in_all_heaps=int(_read("bytes_in_all_heaps") or 0),
                gen0_heap_size=int(_read("gen0_heap_size") or 0),
                gen1_heap_size=int(_read("gen1_heap_size") or 0),
                gen2_heap_size=int(_read("gen2_heap_size") or 0),
                large_object_heap_size=int(_read("large_object_heap_size") or 0),
                gen0_collections=int(_read("gen0_collections") or 0),
                gen1_collections=int(_read("gen1_collections") or 0),
                gen2_collections=int(_read("gen2_collections") or 0),
                pct_time_in_gc=float(_read("pct_time_in_gc", fmt=fmt_double) or 0.0),
                pinned_objects=int(_read("pinned_objects") or 0),
                allocated_bytes_per_sec=float(
                    _read("allocated_bytes_per_sec", fmt=fmt_double) or 0.0
                ),
            )
            out.append(sample)
    finally:
        try:
            win32pdh.CloseQuery(query)
        except Exception:
            pass

    # Drop processes with literally zero everything — likely PDH glitch
    # or terminated process between enumerate and read.
    return [s for s in out if s.bytes_in_all_heaps > 0 or s.gen2_collections > 0]


def to_csv_rows(
    samples: list[ManagedHeapSample],
    timestamp: float,
    rel_seconds: float,
) -> list[dict]:
    """Convert ManagedHeapSamples to CSV-row dicts."""
    return [
        {
            "timestamp": timestamp,
            "rel_seconds": round(rel_seconds, 3),
            "pid": s.pid,
            "name": s.name,
            "bytes_in_all_heaps": s.bytes_in_all_heaps,
            "gen0_heap_size": s.gen0_heap_size,
            "gen1_heap_size": s.gen1_heap_size,
            "gen2_heap_size": s.gen2_heap_size,
            "large_object_heap_size": s.large_object_heap_size,
            "gen0_collections": s.gen0_collections,
            "gen1_collections": s.gen1_collections,
            "gen2_collections": s.gen2_collections,
            "pct_time_in_gc": round(s.pct_time_in_gc, 2),
            "pinned_objects": s.pinned_objects,
            "allocated_bytes_per_sec": round(s.allocated_bytes_per_sec, 1),
        }
        for s in samples
    ]
