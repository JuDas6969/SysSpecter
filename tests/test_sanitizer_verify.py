"""End-to-end sanitize → verify: no known identifier left in the copy."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from sysspecter.sanitizer import sanitize_run
from sysspecter.sanitizer_verify import verify


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f)


def _write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def _make_run(tmp: Path) -> Path:
    """Build a run that contains the identifiers the sanitizer must redact."""
    run = tmp / "run"
    manifest = {
        "schema_version": 2, "sysspecter_version": "1.1.0-dev",
        "run_id": "RUN",
        "hostname": "GPLT9999",
        "fqdn": "GPLT9999.corp.local",
        "mode": "support",
        "started_at": "2026-04-23T01:00:00",
    }
    static = {
        "bios": {"SerialNumber": "BIOSXYZ42",
                 "SMBIOSBIOSVersion": "1.0", "ReleaseDate": "2024"},
        "baseboard": {"SerialNumber": "BB8888"},
        "disks": [{"_physical_drive": {
            "Model": "Samsung 980", "Size": 1024,
            "SerialNumber": "DRIVESN4711",
        }}],
        "network": {"vpn_suspect_adapters": [], "ipconfig_all": "",
                    "route_print": ""},
        "installed_programs": [{"DisplayName": "Chrome"}],
        "autoruns": [],
        "security": {"defender_status": {}, "antivirus_products": []},
        "computer_system": {"Manufacturer": "Dell", "Model": "Latitude"},
        "os": {"caption": "Windows 10", "build": "19044"},
        "power": {"active_scheme_raw": "(Balanced)"},
        "hostname": "GPLT9999",
    }
    findings = {"summary": {"verdict": "observed on GPLT9999 via BIOSXYZ42"}}
    scores = {"overall": 60, "confidence": "medium"}
    _write_json(run / "manifest.json", manifest)
    _write_json(run / "static_snapshot.json", static)
    _write_json(run / "findings.json", findings)
    _write_json(run / "scores.json", scores)
    _write_csv(run / "timeline_system.csv",
               ["timestamp", "rel_seconds", "cpu_total_pct", "note"],
               [["1.0", "0.0", "15", "host GPLT9999 drive DRIVESN4711"]])
    return run


def test_sanitize_then_verify_is_clean(tmp_path: Path) -> None:
    run = _make_run(tmp_path)
    # Keep a copy of the originals so verify can check against them
    original_manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    original_static = json.loads((run / "static_snapshot.json").read_text(encoding="utf-8"))
    out = Path(sanitize_run(str(run)))
    hits = verify(str(out),
                  original_manifest=original_manifest,
                  original_static=original_static)
    assert hits == [], f"sanitizer leaked identifiers: {hits}"


def test_verify_detects_leak_when_sanitize_is_bypassed(tmp_path: Path) -> None:
    run = _make_run(tmp_path)
    original_manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    original_static = json.loads((run / "static_snapshot.json").read_text(encoding="utf-8"))
    # Do NOT sanitize -- verify must find the identifiers still there
    hits = verify(str(run),
                  original_manifest=original_manifest,
                  original_static=original_static)
    assert hits, "verify should have flagged the un-redacted run"
    files = {h.file for h in hits}
    # At least one of the three identifier-carrying files must appear
    assert ("manifest.json" in files or "static_snapshot.json" in files
            or "findings.json" in files
            or "timeline_system.csv" in files)


def test_verify_returns_empty_when_no_identifiers(tmp_path: Path) -> None:
    # Tiny run with no interesting identifiers -- verify must be happy.
    run = tmp_path / "empty_run"
    _write_json(run / "manifest.json", {"hostname": "", "fqdn": ""})
    _write_json(run / "static_snapshot.json", {"bios": {}})
    hits = verify(str(run))
    assert hits == []
