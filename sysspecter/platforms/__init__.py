"""Cross-platform abstraction (Field-review C5).

SysSpecter is Windows-only by design today — every collector reaches
into ``ctypes.windll`` or ``powershell.exe`` directly. The field
review noted that even if the first ship stays Windows-only, the
sampler should be FACTORED so OS-specific calls live behind a clean
abstraction. Otherwise, retrofitting Linux (eBPF / perf_events) or
macOS (dtrace / EndpointSecurity) means rewriting every collector.

This module is the abstraction. Today it has one concrete
implementation (Windows, in `windows.py`) plus a stub for POSIX
(`posix.py`) that raises clearly so a future Linux / macOS
implementation has an obvious place to land.

Public API:

    >>> from sysspecter.platforms import platform
    >>> p = platform()
    >>> p.is_admin()                       # True / False
    >>> p.machine_id_smbios_uuid()         # str | None
    >>> p.machine_id_machine_sid()         # str | None
    >>> p.machine_id_macs()                # list[str]
    >>> p.name                             # "windows" | "linux" | "macos"

The factory is cached — the same Platform instance is returned on
every call within a process. Tests can inject a custom Platform
via :func:`set_platform`.

Architecture decision recorded as ADR-0006.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base import Platform

from .base import Platform as Platform

# ----- factory ------------------------------------------------------------

_cached: Platform | None = None


def platform() -> Platform:
    """Return the active platform implementation, picking one from
    :data:`sys.platform` on first call.

    The result is cached for the rest of the process. Tests that need
    a different platform should call :func:`set_platform` to inject
    one and :func:`reset_platform` afterwards to restore the cache.
    """
    global _cached
    if _cached is not None:
        return _cached
    _cached = _detect_platform()
    return _cached


def set_platform(p: Platform) -> None:
    """Inject a platform — for tests and override scenarios. The
    next call to :func:`platform` returns *p* until reset."""
    global _cached
    _cached = p


def reset_platform() -> None:
    """Drop the cached platform; the next :func:`platform` call
    re-detects from ``sys.platform``."""
    global _cached
    _cached = None


def _detect_platform() -> Platform:
    if sys.platform.startswith("win"):
        from .windows import WindowsPlatform
        return WindowsPlatform()
    if sys.platform.startswith(("linux", "darwin")):
        from .posix import PosixPlatform
        return PosixPlatform()
    # Unknown OS — fall back to POSIX stub so the error message is
    # meaningful (vs an AttributeError on whatever ctypes call).
    from .posix import PosixPlatform
    return PosixPlatform()


__all__ = ["Platform", "platform", "set_platform", "reset_platform"]
