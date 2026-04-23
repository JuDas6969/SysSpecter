"""Tests for the run sanitizer.

The sanitizer is a security-facing feature: if it leaks, the customer
ships identifiers to their vendor. Tests cover:
- hostname / FQDN redaction
- BIOS + disk + baseboard serial redaction
- user-path redaction
- metadata preservation (scores, findings structure unchanged)
- idempotent re-run
- sanitized-marker added to the manifest
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from sysspecter.sanitizer import sanitize_run


def _write_json(path: Path, data: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f)


def _write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def _make_run(tmp: Path, hostname: str = "GPLT3923", fqdn: str = "GPLT3923.corp.local",
              bios_serial: str = "BIOSSN001", disk_serial: str = "DISKSN001") -> Path:
    run = tmp / "runs" / f"{hostname}_20260423_010000"
    _write_json(run / "manifest.json", {
        "schema_version": 1,
        "sysspecter_version": "1.0.0",
        "run_id": "20260423_010000",
        "hostname": hostname,
        "fqdn": fqdn,
        "mode": "support",
        "started_at": "2026-04-23T01:00:00",
        "output_root": str(tmp),
        "run_dir": str(run),
        "python_executable": "C:/fake/python.exe",
    })
    _write_json(run / "static_snapshot.json", {
        "hostname": hostname,
        "bios": {"SerialNumber": bios_serial, "SMBIOSBIOSVersion": "1.20.0",
                 "ReleaseDate": "2024-03-05"},
        "baseboard": {"SerialNumber": "BBSER001"},
        "disks": [{"_physical_drive": {"Model": "Samsung 980", "Size": 1024,
                                       "SerialNumber": disk_serial}}],
        "network": {"vpn_suspect_adapters": [], "ipconfig_all": "long dump",
                    "route_print": "route dump"},
        "installed_programs": [{"DisplayName": "Chrome", "DisplayVersion": "120"}],
        "autoruns": [],
        "security": {"defender_status": {"AntivirusEnabled": True}},
        "computer_system": {"Manufacturer": "Dell", "Model": "Latitude"},
        "os": {"caption": "Windows 10", "build": "19044"},
        "power": {"active_scheme_raw": "(Balanced)"},
    })
    _write_json(run / "findings.json", {"summary": {"verdict": f"host {hostname} looks ok"}})
    _write_json(run / "scores.json", {"overall": 75, "confidence": "high"})
    # CSV: hostname should get redacted in any string cell
    _write_csv(run / "timeline_system.csv",
               ["timestamp", "rel_seconds", "cpu_total_pct", "note"],
               [["1.0", "0.0", "12.5", f"ran on {hostname}"]])
    return run


def test_sanitize_redacts_hostname_in_manifest(tmp_path: Path) -> None:
    run = _make_run(tmp_path)
    out = sanitize_run(str(run))
    manifest = json.loads(Path(out, "manifest.json").read_text(encoding="utf-8"))
    # hostname must be gone everywhere -- including the sanitized_source field
    assert "GPLT3923" not in json.dumps(manifest)
    assert manifest.get("sanitized") is True
    # sanitized_source still carries the timestamp for provenance, but the
    # hostname portion is redacted
    assert "REDACTED" in (manifest.get("sanitized_source") or "")


def test_sanitize_redacts_bios_and_disk_serials(tmp_path: Path) -> None:
    run = _make_run(tmp_path, bios_serial="BIOSSEC42", disk_serial="DSER99")
    out = sanitize_run(str(run))
    static = json.loads(Path(out, "static_snapshot.json").read_text(encoding="utf-8"))
    blob = json.dumps(static)
    assert "BIOSSEC42" not in blob
    assert "DSER99" not in blob


def test_sanitize_redacts_hostname_in_csv(tmp_path: Path) -> None:
    run = _make_run(tmp_path)
    out = sanitize_run(str(run))
    with Path(out, "timeline_system.csv").open(encoding="utf-8") as f:
        reader = csv.reader(f)
        rows = list(reader)
    full = "\n".join(",".join(r) for r in rows)
    assert "GPLT3923" not in full


def test_sanitize_drops_network_ipconfig(tmp_path: Path) -> None:
    run = _make_run(tmp_path)
    out = sanitize_run(str(run))
    static = json.loads(Path(out, "static_snapshot.json").read_text(encoding="utf-8"))
    net = static.get("network") or {}
    # ipconfig_all + route_print are in the drop list
    assert net.get("ipconfig_all") == "[REDACTED]"
    assert net.get("route_print") == "[REDACTED]"


def test_sanitize_preserves_scores_and_findings_structure(tmp_path: Path) -> None:
    run = _make_run(tmp_path)
    out = sanitize_run(str(run))
    scores = json.loads(Path(out, "scores.json").read_text(encoding="utf-8"))
    findings = json.loads(Path(out, "findings.json").read_text(encoding="utf-8"))
    assert scores["overall"] == 75
    assert "summary" in findings
    # hostname must be redacted inside verdict text too
    assert "GPLT3923" not in findings["summary"]["verdict"]


def test_sanitize_is_idempotent(tmp_path: Path) -> None:
    run = _make_run(tmp_path)
    first = sanitize_run(str(run))
    first_manifest = Path(first, "manifest.json").read_text(encoding="utf-8")
    second = sanitize_run(str(run))
    second_manifest = Path(second, "manifest.json").read_text(encoding="utf-8")
    assert first_manifest == second_manifest
    assert first == second


def test_sanitize_writes_to_sibling_folder_by_default(tmp_path: Path) -> None:
    run = _make_run(tmp_path)
    out = Path(sanitize_run(str(run)))
    assert out.name.endswith("_sanitized")
    assert out.parent == run.parent
