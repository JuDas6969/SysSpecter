"""v3-priority-4 (H1): per-PID handle counts by object type.

The v2 production review's biggest single-impact missing-data item.
Without it, the prior MotoDB diagnosis was stuck at "consistent with
COM RCW leak" (slow growth in `num_handles`); with it, you can say
"15 000 Section + 12 000 Event handles vs a baseline of 200 — that's
a COM Runtime-Callable-Wrapper leak in N seconds."

This module samples the kernel's object-handle table once per
configured interval (default 60 s — too cheap to skip, too expensive
to run per second on machines with > 100 k handles), aggregates by
(PID, ObjectTypeIndex), maps the indices to human-readable type names
(`File`, `Event`, `Mutant`, `Section`, …), and returns a list of
`HandleCount` rows ready for the streaming CSV writer.

API surface used:

- `NtQuerySystemInformation(SystemExtendedHandleInformation = 64, ...)`
  returns the full system handle table. Available without admin since
  Vista. Cannot read protected processes' handles, but the count
  per-PID per-type is still surfaced in the system-wide table.

- `NtQueryObject(NULL, ObjectAllTypesInformation = 3, ...)` returns
  the kernel's full object-type table including each type's name and
  index. We call this once per process at first-sample time to build
  an index → name map. The map is stable for the run's lifetime;
  it does not change while the kernel is running.

Both routines are formally undocumented but have been stable for two
decades and are used by Sysinternals tools, ProcessHacker, etc. We
soft-degrade on every error path: a sample that fails to allocate the
buffer or refuses access returns an empty list rather than raising.
"""

from __future__ import annotations

import ctypes
import logging
import sys
from ctypes import (
    POINTER,
    Structure,
    addressof,
    byref,
    c_uint8,
    c_uint16,
    c_uint32,
    c_void_p,
    c_wchar,
    cast,
    sizeof,
)
from dataclasses import dataclass

# UCHAR / USHORT / ULONG aren't reliably exported from ctypes.wintypes
# across Python versions (missing on 3.12 / 3.14). Use the c_ aliases
# directly so we work on every supported runtime.
UCHAR = c_uint8
USHORT = c_uint16
ULONG = c_uint32

# NTSTATUS codes we care about.
_STATUS_SUCCESS = 0x00000000
_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
_STATUS_BUFFER_OVERFLOW = 0x80000005

# SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation
_SYSTEM_EXTENDED_HANDLE_INFORMATION = 64

# OBJECT_INFORMATION_CLASS.ObjectAllTypesInformation
_OBJECT_ALL_TYPES_INFORMATION = 3

# Maximum buffer growth: stop at 256 MB to avoid runaway on a
# pathological host. A typical desktop has 100–500 k handles
# (~12–60 MB); 256 MB is generous.
_MAX_BUFFER_BYTES = 256 * 1024 * 1024

_log = logging.getLogger("sysspecter.handles")


# ---- ctypes structures --------------------------------------------------

class _UNICODE_STRING(Structure):
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", c_void_p),  # PWSTR but we extract via ctypes
    ]


class _OBJECT_TYPE_INFORMATION(Structure):
    """Subset of the kernel's OBJECT_TYPE_INFORMATION struct.

    We only consume `TypeName` and `TypeIndex`. The rest of the fields
    are present in the buffer (we have to skip past them to reach the
    next entry) but we don't care about them.
    """
    _fields_ = [
        ("TypeName", _UNICODE_STRING),
        ("TotalNumberOfObjects", ULONG),
        ("TotalNumberOfHandles", ULONG),
        ("TotalPagedPoolUsage", ULONG),
        ("TotalNonPagedPoolUsage", ULONG),
        ("TotalNamePoolUsage", ULONG),
        ("TotalHandleTableUsage", ULONG),
        ("HighWaterNumberOfObjects", ULONG),
        ("HighWaterNumberOfHandles", ULONG),
        ("HighWaterPagedPoolUsage", ULONG),
        ("HighWaterNonPagedPoolUsage", ULONG),
        ("HighWaterNamePoolUsage", ULONG),
        ("HighWaterHandleTableUsage", ULONG),
        ("InvalidAttributes", ULONG),
        ("GenericMapping", ULONG * 4),  # opaque
        ("ValidAccessMask", ULONG),
        ("SecurityRequired", UCHAR),
        ("MaintainHandleCount", UCHAR),
        ("TypeIndex", UCHAR),
        ("ReservedByte", UCHAR),
        ("PoolType", ULONG),
        ("DefaultPagedPoolCharge", ULONG),
        ("DefaultNonPagedPoolCharge", ULONG),
    ]


class _OBJECT_TYPES_INFORMATION(Structure):
    _fields_ = [
        ("NumberOfTypes", ULONG),
        # entries follow: NumberOfTypes × _OBJECT_TYPE_INFORMATION
    ]


class _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(Structure):
    """One row of SystemExtendedHandleInformation."""
    _fields_ = [
        ("Object", c_void_p),
        ("UniqueProcessId", c_void_p),  # PID, padded to pointer width
        ("HandleValue", c_void_p),
        ("GrantedAccess", ULONG),
        ("CreatorBackTraceIndex", USHORT),
        ("ObjectTypeIndex", USHORT),
        ("HandleAttributes", ULONG),
        ("Reserved", ULONG),
    ]


class _SYSTEM_HANDLE_INFORMATION_EX(Structure):
    _fields_ = [
        ("NumberOfHandles", c_void_p),  # ULONG_PTR
        ("Reserved", c_void_p),
        # entries follow: NumberOfHandles × _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    ]


# ---- public dataclass ---------------------------------------------------

@dataclass(slots=True)  # v1.3.1
class HandleCount:
    """One row in `timeline_handles.csv`."""
    pid: int
    type_name: str
    count: int


# ---- internal cache -----------------------------------------------------

_type_index_to_name: dict[int, str] | None = None

# v1.3.2: module-level cache for the giant ctypes buffer used by
# `_query_system_handles`. The v1.3.0/v1.3.1 path allocated a fresh
# 16 MB ctypes array per call (every 60 s on a typical desktop), which
# fragments the Windows process heap and is the most likely residual
# self-leak source after the v1.3.0 streaming-events fix. Reuse a
# single buffer for the lifetime of the process; only re-allocate on
# the (very rare) STATUS_INFO_LENGTH_MISMATCH growth path.
_HANDLES_BUF: ctypes.Array | None = None
_HANDLES_BUF_SIZE: int = 0

# v1.3.2: same treatment for the smaller ObjectAllTypes buffer.
# Magnitude is modest (64 KB → 4 MB) but the call still happens once
# per process lifetime in steady state and once per buffer-grow on
# resolution failure. Cache it for cleanliness even if it's not the
# dominant leak.
_TYPES_BUF: ctypes.Array | None = None
_TYPES_BUF_SIZE: int = 0


def _is_windows() -> bool:
    return sys.platform == "win32"


def _ntdll() -> ctypes.WinDLL | None:
    if not _is_windows():
        return None
    try:
        return ctypes.WinDLL("ntdll", use_last_error=True)  # type: ignore[attr-defined]
    except (OSError, AttributeError):
        return None


def _query_all_types() -> dict[int, str]:
    """Resolve the kernel's ObjectTypeIndex → type-name map.

    Soft-degrade: empty dict on any failure. The collector will
    surface numeric indices instead of names if this fails — still
    useful, just less readable.
    """
    global _TYPES_BUF, _TYPES_BUF_SIZE
    nt = _ntdll()
    if nt is None:
        return {}

    # Try expanding buffer sizes — start at 64 KB which fits all known
    # Windows builds, double until 4 MB. v1.3.2: reuse a module-level
    # cached array so steady-state callers don't fragment the heap.
    buf_size = _TYPES_BUF_SIZE if _TYPES_BUF is not None else 64 * 1024
    while buf_size <= 4 * 1024 * 1024:
        if _TYPES_BUF is None or _TYPES_BUF_SIZE != buf_size:
            _TYPES_BUF = (ctypes.c_ubyte * buf_size)()
            _TYPES_BUF_SIZE = buf_size
        buf = _TYPES_BUF
        ret_len = ULONG(0)
        try:
            status = nt.NtQueryObject(
                None,
                _OBJECT_ALL_TYPES_INFORMATION,
                buf, buf_size,
                byref(ret_len),
            )
        except OSError as e:
            _log.debug("NtQueryObject(ObjectAllTypes) failed: %s", e)
            return {}
        if status == _STATUS_INFO_LENGTH_MISMATCH:
            buf_size *= 2
            # Force a re-allocation for the next loop iteration.
            _TYPES_BUF = None
            _TYPES_BUF_SIZE = 0
            continue
        if status != _STATUS_SUCCESS:
            _log.debug("NtQueryObject(ObjectAllTypes) status=0x%08x", status & 0xFFFFFFFF)
            return {}
        return _parse_all_types_buffer(buf, ret_len.value or buf_size)
    _log.debug("NtQueryObject(ObjectAllTypes) buffer kept growing past 4 MB; aborting")
    return {}


def _parse_all_types_buffer(buf: ctypes.Array, total_len: int) -> dict[int, str]:
    """Walk the OBJECT_TYPES_INFORMATION buffer and pull (TypeIndex, TypeName)."""
    out: dict[int, str] = {}
    base_addr = addressof(buf)
    header = cast(buf, POINTER(_OBJECT_TYPES_INFORMATION)).contents
    n = header.NumberOfTypes
    # First entry sits AFTER the header, aligned up to pointer size.
    ptr_size = sizeof(c_void_p)
    offset = sizeof(_OBJECT_TYPES_INFORMATION)
    offset = (offset + ptr_size - 1) & ~(ptr_size - 1)
    for _ in range(n):
        if offset + sizeof(_OBJECT_TYPE_INFORMATION) > total_len:
            break
        entry = cast(
            base_addr + offset,
            POINTER(_OBJECT_TYPE_INFORMATION),
        ).contents
        # Extract the TypeName WCHAR buffer.
        name_len_chars = (entry.TypeName.Length // sizeof(c_wchar)) if entry.TypeName.Buffer else 0
        if entry.TypeName.Buffer and name_len_chars > 0:
            name_arr = (c_wchar * name_len_chars).from_address(entry.TypeName.Buffer)
            name = name_arr[:]
        else:
            name = ""
        out[int(entry.TypeIndex)] = name
        # Advance: name buffer follows the struct, then alignment to ptr_size.
        offset += sizeof(_OBJECT_TYPE_INFORMATION)
        # The TypeName.Buffer + MaximumLength bytes are inline AFTER the struct.
        # Skip them (rounded up to pointer alignment) to reach the next entry.
        offset += entry.TypeName.MaximumLength
        offset = (offset + ptr_size - 1) & ~(ptr_size - 1)
    return out


def _resolve_type_name(idx: int) -> str:
    """Return type name for an ObjectTypeIndex, falling back to the
    raw index string when the map isn't populated."""
    global _type_index_to_name
    if _type_index_to_name is None:
        _type_index_to_name = _query_all_types()
    return _type_index_to_name.get(idx) or f"TypeIndex_{idx}"


def reset_type_cache() -> None:
    """For tests — discard the cached index→name map so a fresh
    NtQueryObject call happens on next access. Also drops the module-
    level ctypes buffer caches added in v1.3.2 so tests can verify
    re-allocation on size growth."""
    global _type_index_to_name, _HANDLES_BUF, _HANDLES_BUF_SIZE
    global _TYPES_BUF, _TYPES_BUF_SIZE
    _type_index_to_name = None
    _HANDLES_BUF = None
    _HANDLES_BUF_SIZE = 0
    _TYPES_BUF = None
    _TYPES_BUF_SIZE = 0


# ---- collection --------------------------------------------------------

def _query_system_handles() -> bytes:
    """Return the raw SystemExtendedHandleInformation buffer.

    Empty bytes on any failure path. Caller must handle that.

    v1.3.2: reuse a module-level cached 16 MB ctypes array. The v1.3.0
    / v1.3.1 path allocated a fresh array per call (every 60 s on a
    typical desktop), which is the most likely residual self-leak
    source — large repeated allocations fragment the Windows process
    heap so HeapFree never returns memory to the OS.
    """
    global _HANDLES_BUF, _HANDLES_BUF_SIZE
    nt = _ntdll()
    if nt is None:
        return b""

    # Start at 16 MB which fits a desktop with up to ~700 k handles.
    # Double up to 256 MB ceiling.
    buf_size = _HANDLES_BUF_SIZE if _HANDLES_BUF is not None else 16 * 1024 * 1024
    while buf_size <= _MAX_BUFFER_BYTES:
        if _HANDLES_BUF is None or _HANDLES_BUF_SIZE != buf_size:
            _HANDLES_BUF = (ctypes.c_ubyte * buf_size)()
            _HANDLES_BUF_SIZE = buf_size
        buf = _HANDLES_BUF
        ret_len = ULONG(0)
        try:
            status = nt.NtQuerySystemInformation(
                _SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buf, buf_size,
                byref(ret_len),
            )
        except OSError as e:
            _log.debug("NtQuerySystemInformation failed: %s", e)
            return b""
        if status in (_STATUS_INFO_LENGTH_MISMATCH, _STATUS_BUFFER_OVERFLOW):
            buf_size *= 2
            # Force a re-allocation for the next loop iteration.
            _HANDLES_BUF = None
            _HANDLES_BUF_SIZE = 0
            continue
        if status != _STATUS_SUCCESS:
            _log.debug("NtQuerySystemInformation status=0x%08x", status & 0xFFFFFFFF)
            return b""
        # Snapshot the relevant prefix into immutable bytes so the
        # caller can release the cached ctypes buffer reference cleanly
        # (the cached buffer itself stays alive at module scope).
        used = ret_len.value or buf_size
        return bytes(buf[:used])
    _log.debug("NtQuerySystemInformation buffer kept growing past %d bytes; aborting",
               _MAX_BUFFER_BYTES)
    return b""


def _aggregate(buf: bytes) -> list[HandleCount]:
    """Walk the buffer and aggregate (pid, type_index) → count.

    Returns one HandleCount per (pid, type_name) pair. Resolves the
    type index to a human-readable name. Caller filters / caps further.
    """
    if len(buf) < sizeof(_SYSTEM_HANDLE_INFORMATION_EX):
        return []
    header_size = sizeof(_SYSTEM_HANDLE_INFORMATION_EX)
    entry_size = sizeof(_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)

    # The first ULONG_PTR is NumberOfHandles. On 64-bit Windows that
    # is 8 bytes; on 32-bit Python on 32-bit Windows it's 4. We use
    # `c_void_p` so ctypes picks the right width.
    array = (ctypes.c_ubyte * len(buf)).from_buffer_copy(buf)
    base = addressof(array)
    header = cast(array, POINTER(_SYSTEM_HANDLE_INFORMATION_EX)).contents
    n = int(header.NumberOfHandles or 0)
    if n <= 0:
        return []
    counts: dict[tuple[int, int], int] = {}
    EntryArr = _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * n
    if header_size + n * entry_size > len(buf):
        # Truncated buffer — bail rather than read past the end.
        _log.debug("handle buffer shorter than declared (got %d, need %d)",
                   len(buf), header_size + n * entry_size)
        return []
    entries = EntryArr.from_address(base + header_size)
    for i in range(n):
        e = entries[i]
        pid = int(e.UniqueProcessId or 0)
        if pid <= 0:
            continue
        idx = int(e.ObjectTypeIndex)
        key = (pid, idx)
        counts[key] = counts.get(key, 0) + 1
    out: list[HandleCount] = []
    for (pid, idx), count in counts.items():
        out.append(HandleCount(
            pid=pid,
            type_name=_resolve_type_name(idx),
            count=count,
        ))
    return out


def collect_handles_snapshot(
    *,
    top_n_pids: int = 50,
) -> list[HandleCount]:
    """Sample the kernel handle table and aggregate per-PID per-type.

    `top_n_pids` caps output to the PIDs with the largest total handle
    count. A typical desktop has 100–300 PIDs but only ~30 of them are
    interesting; capping keeps the CSV manageable on long runs.

    Returns an empty list (with a debug log) when:
      - we're not on Windows
      - ntdll can't be loaded
      - NtQuerySystemInformation fails (locked-down host, sandbox)
      - the call succeeds but reports zero handles
    """
    raw = _query_system_handles()
    if not raw:
        return []
    rows = _aggregate(raw)
    if not rows:
        return []
    # Cap to top-N by total handles per PID.
    by_pid: dict[int, int] = {}
    for r in rows:
        by_pid[r.pid] = by_pid.get(r.pid, 0) + r.count
    if 0 < top_n_pids < len(by_pid):
        keep = {pid for pid, _ in sorted(
            by_pid.items(), key=lambda kv: kv[1], reverse=True,
        )[:top_n_pids]}
        rows = [r for r in rows if r.pid in keep]
    return rows


def to_csv_rows(
    rows: list[HandleCount],
    timestamp: float,
    rel_seconds: float,
    pid_to_name: dict[int, str] | None = None,
) -> list[dict]:
    """Convert HandleCount rows to dicts for the streaming CSV writer.

    `pid_to_name` is optional — when provided we lift the process name
    so the CSV is readable without joining against timeline_processes.
    """
    pid_to_name = pid_to_name or {}
    return [
        {
            "timestamp": timestamp,
            "rel_seconds": round(rel_seconds, 3),
            "pid": r.pid,
            "name": pid_to_name.get(r.pid) or "?",
            "type_name": r.type_name,
            "count": r.count,
        }
        for r in rows
    ]
