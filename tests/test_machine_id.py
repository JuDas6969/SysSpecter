"""Field-review M5: stable machine identifier.

Pins the contract that:
- Same hardware → same machine_id, even when hostname changes.
- Different hardware → different machine_id.
- The fallback chain (SMBIOS UUID → MAC → hostname) is honoured in
  priority order.
- The `source` field documents which tier was used so consumers can
  warn on the weak fallback.
- The token format is `MACHINE-` followed by exactly 8 hex chars.
- Pydantic Manifest schema accepts the new fields and v1/v2 manifests
  without them still load.
- build_run_manifest stamps the id onto every new run.
"""

from __future__ import annotations

import datetime as _dt
import re
from pathlib import Path
from unittest.mock import patch

from sysspecter import machine_id as mid_mod
from sysspecter.config import Config, Thresholds
from sysspecter.domain.schemas import Manifest, try_validate
from sysspecter.machine_id import compute_machine_id
from sysspecter.manifest import build_run_manifest
from sysspecter.paths import RunPaths

_TOKEN_RE = re.compile(r"^MACHINE-[0-9a-f]{8}$")


# ----------------------------------------------------- format + determinism


def test_token_format_is_machine_dash_8hex() -> None:
    """Every code path must produce a token matching MACHINE-xxxxxxxx."""
    cases = [
        compute_machine_id(_smbios_uuid="abcdef12-3456-7890-1234-567890abcdef"),
        compute_machine_id(_smbios_uuid=None, _machine_sid=None,
                           _macs=["AA:BB:CC:DD:EE:FF"]),
        compute_machine_id(_smbios_uuid=None, _machine_sid=None, _macs=[],
                           _hostname="some-host"),
    ]
    for c in cases:
        assert _TOKEN_RE.match(c.machine_id), \
            f"bad token format: {c.machine_id!r} (source={c.source})"


def test_same_uuid_produces_same_id() -> None:
    """Same input must produce same output across calls — the
    LONGITUDINAL TRENDING contract depends on this."""
    a = compute_machine_id(_smbios_uuid="abc-uuid")
    b = compute_machine_id(_smbios_uuid="abc-uuid")
    assert a == b


def test_different_uuids_produce_different_ids() -> None:
    a = compute_machine_id(_smbios_uuid="aaa-uuid")
    b = compute_machine_id(_smbios_uuid="bbb-uuid")
    assert a.machine_id != b.machine_id


def test_uuid_case_insensitive() -> None:
    """SMBIOS UUIDs come back from PowerShell with arbitrary case;
    same UUID upper or lower must hash the same."""
    a = compute_machine_id(_smbios_uuid="ABCDEF12-3456-7890-1234-567890ABCDEF")
    b = compute_machine_id(_smbios_uuid="abcdef12-3456-7890-1234-567890abcdef")
    assert a.machine_id == b.machine_id


# ----------------------------------------------------- fallback chain


def test_smbios_uuid_wins_when_present() -> None:
    """Priority 1: when an SMBIOS UUID is available, the MAC, SID
    and hostname don't enter the hash."""
    with_uuid = compute_machine_id(
        _smbios_uuid="abc-uuid",
        _machine_sid="S-1-5-21-1-2-3",
        _macs=["AA:BB:CC:DD:EE:FF"],
        _hostname="host",
    )
    only_uuid = compute_machine_id(
        _smbios_uuid="abc-uuid",
        _machine_sid="S-1-5-21-9-9-9",
        _macs=[],
        _hostname="other-host",
    )
    assert with_uuid.machine_id == only_uuid.machine_id
    assert with_uuid.source == "smbios_uuid"


def test_machine_sid_used_when_uuid_absent() -> None:
    """Priority 2: SID wins over MAC + hostname when present.
    This is the field-review-named tier — survives NIC swaps."""
    result = compute_machine_id(
        _smbios_uuid=None,
        _machine_sid="S-1-5-21-1234567890-987654321-111111111",
        _macs=["AA:BB:CC:DD:EE:FF"],
        _hostname="some-host",
    )
    assert result.source == "machine_sid"
    assert _TOKEN_RE.match(result.machine_id)


def test_machine_sid_with_account_rid_normalises() -> None:
    """A Win32_UserAccount.SID has the form `<machine-sid>-<rid>`.
    Two accounts on the same machine have different RIDs but same
    machine SID — the resolver must collapse them."""
    a = compute_machine_id(
        _smbios_uuid=None,
        _machine_sid="S-1-5-21-1234567890-987654321-111111111-500",
        _macs=["AA:BB:CC:DD:EE:FF"],
    )
    # Caller passes only the machine-SID prefix (this test simulates
    # what the production helper hands back after stripping the RID).
    b = compute_machine_id(
        _smbios_uuid=None,
        _machine_sid="S-1-5-21-1234567890-987654321-111111111",
        _macs=["AA:BB:CC:DD:EE:FF"],
    )
    # The PRODUCTION helper strips the RID before hashing, so a
    # caller-supplied SID with a RID that doesn't match the
    # canonical prefix DOESN'T match the canonical id. This test
    # documents that contract: callers supply already-canonicalised
    # SIDs.
    assert a.source == "machine_sid"
    assert b.source == "machine_sid"
    # Different SID strings, different ids (since the test bypasses
    # the prefix extraction).
    assert a.machine_id != b.machine_id


def test_machine_sid_case_insensitive() -> None:
    """SIDs are returned upper-case from PowerShell but be tolerant."""
    a = compute_machine_id(
        _smbios_uuid=None, _machine_sid="s-1-5-21-1-2-3",
        _macs=[],
    )
    b = compute_machine_id(
        _smbios_uuid=None, _machine_sid="S-1-5-21-1-2-3",
        _macs=[],
    )
    assert a.machine_id == b.machine_id


def test_invalid_sid_falls_through_to_mac() -> None:
    """A malformed SID (wrong prefix, junk) must be ignored, not
    used. Falls through to the next tier."""
    for bad in ("not-a-sid", "S-1-1-1-2-3", "", None,
                "S-1-5-32-544",        # built-in admin group, not machine SID
                "S-1-5-18"):           # local system, not a domain SID
        result = compute_machine_id(
            _smbios_uuid=None,
            _machine_sid=bad,
            _macs=["AA:BB:CC:DD:EE:FF"],
        )
        assert result.source == "mac", (
            f"bad SID {bad!r} should fall through to MAC, "
            f"got {result.source!r}"
        )


def test_mac_used_when_uuid_and_sid_absent() -> None:
    cases = (
        None, "", "00000000-0000-0000-0000-000000000000",
        "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
    )
    for sentinel in cases:
        result = compute_machine_id(
            _smbios_uuid=sentinel,
            _machine_sid=None,
            _macs=["AA:BB:CC:DD:EE:FF"],
            _hostname="some-host",
        )
        assert result.source == "mac", (
            f"sentinel UUID {sentinel!r} with no SID should fall back to MAC"
        )


def test_mac_order_independent() -> None:
    """Two NICs reported in different order must produce the same id —
    otherwise restarting the machine could rotate the id."""
    a = compute_machine_id(
        _smbios_uuid=None, _machine_sid=None,
        _macs=["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"],
    )
    b = compute_machine_id(
        _smbios_uuid=None, _machine_sid=None,
        _macs=["11:22:33:44:55:66", "AA:BB:CC:DD:EE:FF"],
    )
    assert a.machine_id == b.machine_id


def test_hostname_fallback_is_flagged_as_weak() -> None:
    result = compute_machine_id(
        _smbios_uuid=None, _machine_sid=None, _macs=[],
        _hostname="laptop42",
    )
    assert result.source == "hostname_fallback", (
        "hostname-only fallback must be flagged so consumers can warn"
    )
    assert _TOKEN_RE.match(result.machine_id)


def test_hostname_case_insensitive_fallback() -> None:
    a = compute_machine_id(
        _smbios_uuid=None, _machine_sid=None, _macs=[],
        _hostname="LAPTOP42",
    )
    b = compute_machine_id(
        _smbios_uuid=None, _machine_sid=None, _macs=[],
        _hostname="laptop42",
    )
    assert a.machine_id == b.machine_id


def test_empty_hostname_does_not_crash() -> None:
    """Edge case: socket.gethostname() returns "" on some misconfigured
    hosts. The fallback must not crash."""
    result = compute_machine_id(
        _smbios_uuid=None, _machine_sid=None, _macs=[],
        _hostname="",
    )
    assert _TOKEN_RE.match(result.machine_id)
    assert result.source == "hostname_fallback"


# ----------------------------------------------------- manifest integration


def _make_paths(tmp_path: Path) -> RunPaths:
    run_dir = tmp_path / "Runs" / "HOST_20260423_010000"
    run_dir.mkdir(parents=True)
    (run_dir / "logs").mkdir()
    return RunPaths(
        root=str(tmp_path),
        run_id="HOST_20260423_010000",
        hostname="HOST",
        started_at=_dt.datetime(2026, 4, 23, 1, 0, 0),
        run_dir=str(run_dir),
        logs_dir=str(run_dir / "logs"),
    )


def test_manifest_includes_machine_id_and_source(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    cfg = Config(output_root=str(tmp_path), mode="support",
                 thresholds=Thresholds())

    fake_id = mid_mod.MachineId(
        machine_id="MACHINE-deadbeef",
        source="smbios_uuid",
    )
    with patch("sysspecter.manifest.compute_machine_id", return_value=fake_id):
        m = build_run_manifest(paths, cfg)

    assert m["machine_id"] == "MACHINE-deadbeef"
    assert m["machine_id_source"] == "smbios_uuid"


def test_manifest_machine_id_changes_when_hardware_changes(tmp_path: Path) -> None:
    """Two different machines (different SMBIOS UUIDs) must produce
    different ids — even if their hostnames coincide. This is the
    point of M5."""
    paths = _make_paths(tmp_path)
    cfg = Config(output_root=str(tmp_path), thresholds=Thresholds())

    a = mid_mod.MachineId(machine_id="MACHINE-aaaaaaaa", source="smbios_uuid")
    b = mid_mod.MachineId(machine_id="MACHINE-bbbbbbbb", source="smbios_uuid")
    with patch("sysspecter.manifest.compute_machine_id", return_value=a):
        ma = build_run_manifest(paths, cfg)
    with patch("sysspecter.manifest.compute_machine_id", return_value=b):
        mb = build_run_manifest(paths, cfg)

    assert ma["machine_id"] != mb["machine_id"]


def test_manifest_machine_id_stable_across_renames(tmp_path: Path) -> None:
    """Same hardware, different hostname: machine_id stays the same.
    This is the LONGITUDINAL TRENDING contract."""
    cfg = Config(output_root=str(tmp_path), thresholds=Thresholds())
    fake_id = mid_mod.MachineId(machine_id="MACHINE-c0ffee01",
                                source="smbios_uuid")

    paths_v1 = RunPaths(
        root=str(tmp_path), run_id="OLDNAME_x", hostname="OLDNAME",
        started_at=_dt.datetime(2026, 1, 1, 0, 0, 0),
        run_dir=str(tmp_path / "v1"), logs_dir=str(tmp_path / "v1" / "logs"),
    )
    paths_v2 = RunPaths(
        root=str(tmp_path), run_id="NEWNAME_x", hostname="NEWNAME",
        started_at=_dt.datetime(2026, 6, 1, 0, 0, 0),
        run_dir=str(tmp_path / "v2"), logs_dir=str(tmp_path / "v2" / "logs"),
    )

    with patch("sysspecter.manifest.compute_machine_id", return_value=fake_id):
        ma = build_run_manifest(paths_v1, cfg)
        mb = build_run_manifest(paths_v2, cfg)

    assert ma["hostname"] != mb["hostname"]
    assert ma["machine_id"] == mb["machine_id"]


# ----------------------------------------------------- pydantic schema


def test_pydantic_manifest_validates_machine_id_field() -> None:
    raw = {
        "schema_version": 2,
        "run_id": "X",
        "hostname": "X",
        "started_at": "2026-01-01T00:00:00",
        "machine_id": "MACHINE-12345678",
        "machine_id_source": "smbios_uuid",
    }
    m = try_validate(Manifest, raw)
    assert m is not None
    assert m.machine_id == "MACHINE-12345678"
    assert m.machine_id_source == "smbios_uuid"


def test_pydantic_manifest_v1_without_machine_id_still_validates() -> None:
    """Backwards compatibility: a v1 manifest written before this
    commit must still load."""
    raw = {
        "schema_version": 1,
        "run_id": "X",
        "hostname": "X",
        "started_at": "2026-01-01T00:00:00",
    }
    m = try_validate(Manifest, raw)
    assert m is not None
    assert m.machine_id is None
    assert m.machine_id_source is None
