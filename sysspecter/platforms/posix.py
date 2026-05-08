"""POSIX (Linux / macOS) platform stub.

SysSpecter does not ship a POSIX collector tier yet. This stub
provides honest answers for the methods that have a stdlib
equivalent (`is_admin` via ``os.geteuid``, MACs via ``psutil``) and
returns ``None`` for the methods that genuinely need OS-specific
implementations.

When a real POSIX implementation lands, it will live in
`platforms/linux.py` and `platforms/macos.py`. This stub keeps
SysSpecter from crashing in unexpected ways if someone runs the
unit tests on a POSIX host (CI matrix, contributor on Linux).

ADR-0006 documents the architectural intent.
"""

from __future__ import annotations

import os

from ..logging_setup import get_logger
from .base import Platform

_log = get_logger(__name__)


class PosixPlatform(Platform):
    name = "posix"

    # ----- privilege ------------------------------------------------------

    def is_admin(self) -> bool:
        try:
            geteuid = getattr(os, "geteuid", None)
            return geteuid() == 0 if callable(geteuid) else False
        except Exception:
            _log.debug("geteuid probe failed", exc_info=True)
            return False

    # ----- machine_id inputs (M5) -----------------------------------------

    def machine_id_smbios_uuid(self) -> str | None:
        # Linux: /sys/class/dmi/id/product_uuid (root-only on most
        # distros). macOS: ioreg -d2 -c IOPlatformExpertDevice. Not
        # implemented yet; returning None falls through to the next
        # tier (machine_sid → mac → hostname) which works on POSIX
        # too via the MAC tier.
        return None

    def machine_id_machine_sid(self) -> str | None:
        # Windows-specific concept; POSIX has no direct equivalent.
        # /etc/machine-id is the closest analogue but conceptually
        # different (set on first boot, not domain-tied), so we
        # return None and let M5 fall through to the MAC tier.
        return None

    def machine_id_macs(self) -> list[str]:
        # psutil is cross-platform — re-using the existing Windows
        # helper would also work here, but we localise it to avoid
        # importing module-level constants that assume Windows.
        try:
            import psutil
        except Exception:
            _log.debug("psutil unavailable for MAC enumeration",
                       exc_info=True)
            return []
        out: list[str] = []
        try:
            for name, addrs in psutil.net_if_addrs().items():
                lname = name.lower()
                if "lo" == lname or "loopback" in lname:
                    continue
                # Linux loopback is "lo" or "lo0"; veth / docker /
                # virbr / vboxnet are typical virtual interfaces.
                if any(p in lname for p in ("docker", "virbr",
                                            "vboxnet", "vmnet")):
                    continue
                for addr in addrs:
                    if hasattr(psutil, "AF_LINK") \
                            and addr.family == psutil.AF_LINK:
                        mac = (addr.address or "").upper().strip()
                        if mac and mac != "00:00:00:00:00:00" \
                                and len(mac) == 17:
                            out.append(mac)
        except Exception:
            _log.debug("MAC enumeration failed", exc_info=True)
            return []
        return out
