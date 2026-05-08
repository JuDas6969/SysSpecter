"""Windows platform adapter.

Delegates to existing Win32 / PowerShell implementations:

    is_admin                        ctypes shell32.IsUserAnAdmin
    machine_id_smbios_uuid          PowerShell Win32_ComputerSystemProduct
    machine_id_machine_sid          PowerShell Win32_UserAccount
    machine_id_macs                 psutil.net_if_addrs

Most of these were already implemented as private helpers in the
collectors / `machine_id.py`. This module is a thin re-export so
the same functions are reachable through the abstraction.
"""

from __future__ import annotations

import ctypes

from ..logging_setup import get_logger
from .base import Platform

_log = get_logger(__name__)


class WindowsPlatform(Platform):
    name = "windows"

    # ----- privilege ------------------------------------------------------

    def is_admin(self) -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            _log.debug("IsUserAnAdmin probe failed", exc_info=True)
            return False

    # ----- machine_id inputs (M5) -----------------------------------------

    def machine_id_smbios_uuid(self) -> str | None:
        # Re-export the existing helper so tests + downstream code have
        # one canonical entry point.
        from ..machine_id import _smbios_uuid_via_powershell
        return _smbios_uuid_via_powershell()

    def machine_id_machine_sid(self) -> str | None:
        from ..machine_id import _machine_sid_via_powershell
        return _machine_sid_via_powershell()

    def machine_id_macs(self) -> list[str]:
        from ..machine_id import _physical_mac_addresses
        return _physical_mac_addresses()
