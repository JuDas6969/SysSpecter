"""Field-review C5: cross-platform abstraction layer.

Pins the contract of `sysspecter.platforms`:

- The factory caches the detected platform.
- `set_platform()` injects an override for tests.
- `reset_platform()` clears the cache.
- `WindowsPlatform.is_admin()` delegates to ctypes (mockable).
- `WindowsPlatform.machine_id_*()` re-export the existing helpers.
- `PosixPlatform` returns `None` for Windows-only signals (SMBIOS
  UUID, Machine SID) but does its best for cross-platform ones
  (admin via geteuid, MACs via psutil).
- `compute_machine_id()` flows through the ABC — patching
  `set_platform()` is sufficient to redirect every primitive.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from sysspecter import platforms
from sysspecter.machine_id import compute_machine_id
from sysspecter.platforms.base import Platform
from sysspecter.platforms.posix import PosixPlatform
from sysspecter.platforms.windows import WindowsPlatform


@pytest.fixture(autouse=True)
def _reset_platform_cache():
    """Each test starts with a fresh factory cache so the order
    of tests doesn't leak state."""
    platforms.reset_platform()
    yield
    platforms.reset_platform()


# ----- factory ---------------------------------------------------------------


def test_factory_picks_windows_on_win32() -> None:
    """When sys.platform reports `win32`, the factory must return a
    `WindowsPlatform` instance."""
    with patch.object(sys, "platform", "win32"):
        platforms.reset_platform()
        p = platforms.platform()
    assert isinstance(p, WindowsPlatform)
    assert p.name == "windows"


def test_factory_picks_posix_on_linux() -> None:
    with patch.object(sys, "platform", "linux"):
        platforms.reset_platform()
        p = platforms.platform()
    assert isinstance(p, PosixPlatform)
    assert p.name == "posix"


def test_factory_picks_posix_on_darwin() -> None:
    with patch.object(sys, "platform", "darwin"):
        platforms.reset_platform()
        p = platforms.platform()
    assert isinstance(p, PosixPlatform)


def test_factory_caches_within_process() -> None:
    a = platforms.platform()
    b = platforms.platform()
    assert a is b


def test_set_platform_overrides_factory() -> None:
    fake = MagicMock(spec=Platform)
    fake.name = "test"
    platforms.set_platform(fake)
    assert platforms.platform() is fake


def test_reset_platform_clears_cache() -> None:
    fake = MagicMock(spec=Platform)
    platforms.set_platform(fake)
    platforms.reset_platform()
    p = platforms.platform()
    assert p is not fake


def test_unknown_platform_falls_back_to_posix() -> None:
    """If `sys.platform` reports something unfamiliar (e.g. 'aix4'),
    the factory must still return a usable Platform instance —
    falling back to POSIX gives a meaningful is_admin etc."""
    with patch.object(sys, "platform", "aix4"):
        platforms.reset_platform()
        p = platforms.platform()
    assert isinstance(p, PosixPlatform)


# ----- WindowsPlatform ------------------------------------------------------


def test_windows_is_admin_returns_bool() -> None:
    """The probe must return a bool, never raise. We can't reliably
    assert a specific value (depends on test-runner privileges) but
    we CAN assert the type."""
    p = WindowsPlatform()
    result = p.is_admin()
    assert isinstance(result, bool)


def test_windows_machine_id_helpers_match_module_helpers() -> None:
    """The `WindowsPlatform.machine_id_*` methods are thin wrappers
    around the module-level helpers in `sysspecter.machine_id`. If
    the wrapper drifts, the field-review M5 contract breaks."""
    from sysspecter import machine_id as mid_mod
    p = WindowsPlatform()

    with patch.object(mid_mod, "_smbios_uuid_via_powershell",
                      return_value="abc-uuid"):
        assert p.machine_id_smbios_uuid() == "abc-uuid"

    with patch.object(mid_mod, "_machine_sid_via_powershell",
                      return_value="S-1-5-21-1-2-3"):
        assert p.machine_id_machine_sid() == "S-1-5-21-1-2-3"

    with patch.object(mid_mod, "_physical_mac_addresses",
                      return_value=["AA:BB:CC:DD:EE:FF"]):
        assert p.machine_id_macs() == ["AA:BB:CC:DD:EE:FF"]


# ----- PosixPlatform --------------------------------------------------------


def test_posix_machine_id_smbios_uuid_returns_none() -> None:
    """POSIX has no shipped SMBIOS reader yet — must return None
    so M5 falls through to the next tier instead of crashing."""
    assert PosixPlatform().machine_id_smbios_uuid() is None


def test_posix_machine_id_machine_sid_returns_none() -> None:
    """Machine SID is a Windows-only concept; POSIX returns None."""
    assert PosixPlatform().machine_id_machine_sid() is None


def test_posix_is_admin_uses_geteuid() -> None:
    """On POSIX, admin = root = euid 0. The probe must consult
    `os.geteuid` if available."""
    p = PosixPlatform()
    with patch("os.geteuid", create=True, return_value=0):
        assert p.is_admin() is True
    with patch("os.geteuid", create=True, return_value=1000):
        assert p.is_admin() is False


def test_posix_is_admin_falls_back_when_geteuid_missing() -> None:
    """On Windows running these tests, `os.geteuid` doesn't exist —
    the probe must report False rather than raising."""
    import os as _os
    if hasattr(_os, "geteuid"):
        pytest.skip("test target has geteuid")
    assert PosixPlatform().is_admin() is False


# ----- compute_machine_id flow through the ABC -------------------------------


def test_compute_machine_id_uses_platform_abc() -> None:
    """The whole point of C5: replacing the platform sets ALL three
    machine_id primitives in one place."""
    fake = MagicMock(spec=Platform)
    fake.name = "test"
    fake.machine_id_smbios_uuid.return_value = "fake-uuid-1234"
    fake.machine_id_machine_sid.return_value = None
    fake.machine_id_macs.return_value = []
    platforms.set_platform(fake)

    result = compute_machine_id()
    assert result.source == "smbios_uuid"
    fake.machine_id_smbios_uuid.assert_called_once()


def test_compute_machine_id_uses_platform_for_sid_tier() -> None:
    fake = MagicMock(spec=Platform)
    fake.name = "test"
    fake.machine_id_smbios_uuid.return_value = None
    fake.machine_id_machine_sid.return_value = "S-1-5-21-9-9-9"
    fake.machine_id_macs.return_value = []
    platforms.set_platform(fake)

    result = compute_machine_id()
    assert result.source == "machine_sid"


def test_compute_machine_id_uses_platform_for_mac_tier() -> None:
    fake = MagicMock(spec=Platform)
    fake.name = "test"
    fake.machine_id_smbios_uuid.return_value = None
    fake.machine_id_machine_sid.return_value = None
    fake.machine_id_macs.return_value = ["AA:BB:CC:DD:EE:FF"]
    platforms.set_platform(fake)

    result = compute_machine_id()
    assert result.source == "mac"


def test_compute_machine_id_test_hooks_still_bypass_platform() -> None:
    """The existing M5 test hooks (_smbios_uuid=…, _machine_sid=…,
    _macs=…) MUST take precedence over whatever the platform would
    return — otherwise the 19 M5 tests would have to be rewritten."""
    real = MagicMock(spec=Platform)
    real.machine_id_smbios_uuid.return_value = "platform-says-this"
    real.machine_id_machine_sid.return_value = "S-1-5-21-X-Y-Z"
    real.machine_id_macs.return_value = ["FROM-PLATFORM"]
    platforms.set_platform(real)

    # Test hook overrides the platform.
    result = compute_machine_id(_smbios_uuid="hook-uuid")
    assert "MACHINE-" in result.machine_id
    real.machine_id_smbios_uuid.assert_not_called()
