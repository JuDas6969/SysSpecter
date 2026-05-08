"""Stable machine identifier (Field-review M5).

A single machine should be identifiable as the SAME machine across
runs, even if its hostname or FQDN changes. The legacy report keyed
the longitudinal view on `manifest.hostname` — which means a laptop
that gets renamed (after a department transfer, a re-image, or a
fleet-wide rename) loses its history.

This module emits `MACHINE-xxxxxxxx` — a deterministic 8-hex-char
token derived from durable hardware / OS identifiers. Same hardware
→ same token, regardless of hostname. The token is non-reversible
(blake2b 4-byte digest) so shipping the redacted manifest still
preserves cross-run correlation without leaking the underlying
serial number.

Resolution priority (most-stable first):

    1. SMBIOS UUID (Win32_ComputerSystemProduct.UUID) — survives OS
       reinstalls; tied to the hardware itself.
    2. Windows Machine SID (S-1-5-21-X-Y-Z prefix of any local
       account SID) — survives hostname renames + NIC swaps; only
       changes on full OS reinstall. Field-review M5 explicitly
       names this as a fallback signal alongside MAC.
    3. Physical NIC MACs, sorted + joined — survives a Windows
       reinstall on the same hardware. Lost when the NIC card is
       swapped or the network stack changes drivers.
    4. Hostname (last-resort fallback) — explicitly noted as weak
       so consumers can warn or refuse cross-machine joins on it.

The `source` field on the result tells consumers which tier they
got. A run with `machine_id_source="hostname_fallback"` shouldn't
be trusted for cross-machine deduplication.
"""

from __future__ import annotations

import hashlib
import socket
from dataclasses import dataclass

from .logging_setup import get_logger
from .winutil import run_ps_json

_log = get_logger(__name__)


@dataclass(frozen=True)
class MachineId:
    """Result of `compute_machine_id`. The `source` field flags how
    durable the id is — fleet-aggregation consumers should warn or
    refuse on `hostname_fallback` results."""
    machine_id: str        # "MACHINE-xxxxxxxx"
    source: str            # "smbios_uuid" | "machine_sid" | "mac" | "hostname_fallback"


_NULL_UUIDS = frozenset({
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "",
})


def _smbios_uuid_via_powershell() -> str | None:
    """Read the SMBIOS UUID via PowerShell. Returns None on failure
    or when the BIOS reports a placeholder UUID."""
    try:
        result = run_ps_json(
            "Get-CimInstance Win32_ComputerSystemProduct | "
            "Select-Object UUID"
        )
    except Exception:
        _log.debug("Win32_ComputerSystemProduct query failed", exc_info=True)
        return None
    if isinstance(result, dict):
        uuid = result.get("UUID")
        if isinstance(uuid, str):
            normalised = uuid.strip().lower()
            if normalised and normalised not in _NULL_UUIDS:
                return normalised
    return None


_SID_PREFIX_RE = __import__("re").compile(
    r"^(S-1-5-21-\d+-\d+-\d+)(?:-\d+)?$", flags=__import__("re").IGNORECASE
)


def _machine_sid_via_powershell() -> str | None:
    """Return the Windows Machine SID (the ``S-1-5-21-X-Y-Z`` prefix
    shared by every local account on the system). Survives hostname
    renames and NIC swaps; only changes on full OS reinstall.

    Strategy: query a single local user account; the first four SID
    components ARE the machine SID. Built-in accounts are always
    present, so the query never returns empty on a working Windows
    install."""
    try:
        result = run_ps_json(
            "Get-CimInstance Win32_UserAccount "
            "-Filter \"LocalAccount = True\" "
            "| Select-Object -First 1 -ExpandProperty SID"
        )
    except Exception:
        _log.debug("Win32_UserAccount query failed", exc_info=True)
        return None
    # PowerShell -ExpandProperty returns the raw string for a single
    # value; ConvertTo-Json wraps it as a string.
    if isinstance(result, str):
        sid = result.strip()
    elif isinstance(result, list) and result and isinstance(result[0], str):
        sid = result[0].strip()
    else:
        return None
    m = _SID_PREFIX_RE.match(sid)
    if not m:
        return None
    return m.group(1).upper()


def _physical_mac_addresses() -> list[str]:
    """Return MAC addresses of physical (non-loopback, non-virtual)
    network interfaces. Used as the second-tier fallback when the
    SMBIOS UUID is unavailable."""
    try:
        import psutil
    except Exception:
        _log.debug("psutil unavailable for MAC enumeration", exc_info=True)
        return []
    out: list[str] = []
    try:
        for name, addrs in psutil.net_if_addrs().items():
            lname = name.lower()
            if "loopback" in lname or "virtualbox" in lname or "vmware" in lname:
                continue
            for addr in addrs:
                # AF_LINK on Windows is the MAC family; psutil exports it.
                if hasattr(psutil, "AF_LINK") and addr.family == psutil.AF_LINK:
                    mac = (addr.address or "").replace("-", ":").upper().strip()
                    if mac and mac != "00:00:00:00:00:00" and len(mac) == 17:
                        out.append(mac)
    except Exception:
        _log.debug("MAC enumeration failed", exc_info=True)
        return []
    return out


def _hash8(value: str) -> str:
    """Return blake2b-4-bytes → 8 hex chars. Same algorithm the
    sanitizer uses for stable identifiers (M1)."""
    return hashlib.blake2b(
        value.encode("utf-8"), digest_size=4
    ).hexdigest()


_UNSET: object = object()


def compute_machine_id(
    *,
    _smbios_uuid: object = _UNSET,
    _machine_sid: object = _UNSET,
    _macs: object = _UNSET,
    _hostname: object = _UNSET,
) -> MachineId:
    """Resolve a stable machine identifier.

    Test hooks: pass any of `_smbios_uuid` / `_machine_sid` / `_macs`
    / `_hostname` explicitly (including ``None`` / empty values) to
    bypass the corresponding system-query primitive. The default
    sentinel ``_UNSET`` triggers a real query.

    Field-review C5: the OS-specific primitives are reached through
    the Platform ABC so a future POSIX implementation lands without
    re-touching this resolver.
    """
    from .platforms import platform as _platform_factory
    plat = _platform_factory()

    # Priority 1: SMBIOS UUID.
    uuid = plat.machine_id_smbios_uuid() if _smbios_uuid is _UNSET else _smbios_uuid
    if isinstance(uuid, str) and uuid.strip() and uuid.strip().lower() not in _NULL_UUIDS:
        return MachineId(
            machine_id=f"MACHINE-{_hash8(uuid.strip().lower())}",
            source="smbios_uuid",
        )

    # Priority 2: Windows Machine SID. Field-review M5 explicitly
    # names this as a fallback alongside MAC; we put it ABOVE MAC
    # because NIC swaps rotate MACs but a Machine SID survives.
    sid = plat.machine_id_machine_sid() if _machine_sid is _UNSET else _machine_sid
    if isinstance(sid, str) and sid.strip() and sid.upper().startswith("S-1-5-21-"):
        return MachineId(
            machine_id=f"MACHINE-{_hash8(sid.upper())}",
            source="machine_sid",
        )

    # Priority 3: physical NIC MACs.
    macs = plat.machine_id_macs() if _macs is _UNSET else _macs
    if macs and isinstance(macs, list):
        # Sort so two NICs in different enumeration order produce
        # the same joined string.
        joined = "|".join(sorted(set(macs)))
        return MachineId(
            machine_id=f"MACHINE-{_hash8(joined)}",
            source="mac",
        )

    # Priority 3: hostname. Documented as weak — operators should
    # treat machine_id_source == "hostname_fallback" as advisory
    # only when correlating across runs.
    host_raw = socket.gethostname() if _hostname is _UNSET else _hostname
    host = host_raw if isinstance(host_raw, str) and host_raw else "unknown"
    return MachineId(
        machine_id=f"MACHINE-{_hash8(host.lower())}",
        source="hostname_fallback",
    )
