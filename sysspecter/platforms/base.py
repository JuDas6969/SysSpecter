"""Platform ABC.

Every method on this class is OS-specific by definition. Subclasses
implement the methods their OS supports; methods they can't support
should raise NotImplementedError with a `__doc__`-grade message.

Methods grouped by responsibility:

    Privilege check
        - is_admin

    Stable machine identity (M5 inputs)
        - machine_id_smbios_uuid
        - machine_id_machine_sid
        - machine_id_macs

The contract on each method is documented inline. Anything that
returns None / [] is "couldn't determine, fall through to next tier"
— never a hard failure unless the OS truly can't supply it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class Platform(ABC):
    """Abstract OS adapter. Concrete subclasses live in `windows.py`,
    `posix.py`, etc."""

    #: Lowercase tag for the OS family. Read-only attribute on
    #: instances. Used for logging and for skipping tests on
    #: mismatched platforms.
    name: str

    # ----- privilege ------------------------------------------------------

    @abstractmethod
    def is_admin(self) -> bool:
        """Return True if the current process has the elevated
        privilege the platform's collector tier needs (Administrator
        on Windows; root / sudo on POSIX). False — possibly with
        reduced functionality — otherwise.

        Must NEVER raise. A failure to determine the privilege state
        is treated as "not admin" so the analyzer downgrades
        gracefully instead of crashing the run."""

    # ----- machine_id inputs (Field-review M5) ----------------------------

    @abstractmethod
    def machine_id_smbios_uuid(self) -> str | None:
        """Return the hardware-tied UUID for this machine, or None
        if the platform doesn't expose one. Windows reads SMBIOS
        UUID via WMI; Linux reads /sys/class/dmi/id/product_uuid;
        macOS uses ioreg IOPlatformUUID."""

    @abstractmethod
    def machine_id_machine_sid(self) -> str | None:
        """Return the OS-installation-tied identifier (Windows
        Machine SID, ``S-1-5-21-X-Y-Z``). Linux / macOS return None;
        the equivalent OS-installation-id is a different concept and
        should be added with a different method name when it lands."""

    @abstractmethod
    def machine_id_macs(self) -> list[str]:
        """Return MAC addresses of physical (non-loopback,
        non-virtual) network interfaces. Empty list if none can be
        enumerated. Used as the third-tier fallback in the M5
        machine_id resolution chain."""
