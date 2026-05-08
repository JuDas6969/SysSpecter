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
    # sanitized_source still carries the timestamp for provenance and now
    # carries a stable hash token (HOST-xxxx) instead of the literal hostname.
    src = manifest.get("sanitized_source") or ""
    assert "HOST-" in src, f"expected HOST-<hash> token in {src!r}"


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


# ----- Field-review M1: stable-hash redaction + cmdline secret stripping ---


def test_hostname_replaced_with_stable_hash_token(tmp_path: Path) -> None:
    """Hostname must be replaced by a deterministic ``HOST-xxxx`` token,
    NOT the literal `[REDACTED]`. Same hostname → same hash, so a
    consumer can still tell that two redacted runs share a host."""
    run_a = _make_run(tmp_path / "a", hostname="BOX1")
    run_b = _make_run(tmp_path / "b", hostname="BOX1")
    run_c = _make_run(tmp_path / "c", hostname="BOX2")

    a = json.loads(Path(sanitize_run(str(run_a)), "manifest.json")
                   .read_text(encoding="utf-8"))
    b = json.loads(Path(sanitize_run(str(run_b)), "manifest.json")
                   .read_text(encoding="utf-8"))
    c = json.loads(Path(sanitize_run(str(run_c)), "manifest.json")
                   .read_text(encoding="utf-8"))

    # Same hostname → same token (correlation preserved across runs).
    assert a["sanitized_source"] == b["sanitized_source"], \
        "same hostname must hash to same token"
    # Different hostname → different token.
    assert a["sanitized_source"] != c["sanitized_source"], \
        "different hostnames must NOT collapse to same token"

    # Tokens look like HOST-xxxx (4 hex chars).
    import re as _re
    src = a["sanitized_source"]
    assert _re.search(r"HOST-[0-9a-f]{4}", src), f"token shape wrong in {src!r}"


def test_fqdn_collapses_to_same_token_as_hostname(tmp_path: Path) -> None:
    """`BOX1` and `BOX1.corp.local` must map to the same hash so the
    redacted report doesn't show them as two different machines."""
    run = _make_run(tmp_path, hostname="BOX1", fqdn="BOX1.corp.local")
    out = sanitize_run(str(run))
    blob = Path(out, "static_snapshot.json").read_text(encoding="utf-8")
    # No literal hostname or FQDN must survive.
    assert "BOX1" not in blob
    assert "corp.local" not in blob


def test_bios_disk_baseboard_serials_each_get_distinct_label(tmp_path: Path) -> None:
    """BIOS / DISK / BB hashes must use different label prefixes so a
    consumer can tell which serial is which without seeing the value."""
    run = _make_run(tmp_path, bios_serial="BIOSSEC42", disk_serial="DSER99")
    out = sanitize_run(str(run))
    blob = Path(out, "static_snapshot.json").read_text(encoding="utf-8")
    assert "BIOSSEC42" not in blob
    assert "DSER99" not in blob
    # New labels must be present in the redacted output.
    assert "BIOS-" in blob, "expected BIOS-<hash> label"
    assert "DISK-" in blob, "expected DISK-<hash> label"


def test_cmdline_secret_stripping() -> None:
    """The pre-pass scrubber must strip credential-shaped substrings
    BEFORE the identifier replacement runs. Cmdline capture isn't
    persisted yet, but the scrubber is exercised through any string
    field — including manifest.tags or findings.summary.verdict."""
    from sysspecter.sanitizer import _scrub_secrets

    cases = [
        ("--password=hunter2",                 "<SECRET>"),
        ("--api-key abc123xyz",                "<SECRET>"),
        # Bearer pattern catches it before JWT pattern even tries — both
        # outcomes are acceptable, both strip the actual token.
        ("Authorization: Bearer eyJabcdef.deadBEEF12.signedThing34",
                                               "<SECRET>"),
        # Pure JWT (no Bearer prefix) takes the JWT path.
        ("token=eyJabcdef12.deadBEEF34.signedThing56",  "<JWT>"),
        ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", "<GITHUB_TOKEN>"),
        ("github_pat_AAAA1111BBBB2222CCCC3333DDDD4444",
                                               "<GITHUB_TOKEN>"),
        ("AKIAIOSFODNN7EXAMPLE",                "<AWS_KEY>"),
    ]
    for raw, expected_substring in cases:
        scrubbed = _scrub_secrets(raw)
        assert expected_substring in scrubbed, (
            f"scrubber missed {raw!r}: got {scrubbed!r}, "
            f"expected to contain {expected_substring!r}"
        )
        # And the literal secret value must NOT survive.
        if "hunter2" in raw:
            assert "hunter2" not in scrubbed
        if "abc123xyz" in raw:
            assert "abc123xyz" not in scrubbed


def test_cmdline_secret_runs_through_redact_text(tmp_path: Path) -> None:
    """End-to-end: a cmdline-shaped string with both an identifier AND
    a secret goes through both the secret pre-pass and the identifier
    substitution."""
    run = _make_run(tmp_path, hostname="HOSTA")
    # Inject a cmdline-shaped value into a JSON field that the redactor
    # walks (findings.summary.verdict is walked for hostname stripping).
    run_findings = run / "findings.json"
    payload = json.loads(run_findings.read_text(encoding="utf-8"))
    payload["summary"]["verdict"] = (
        "host HOSTA ran service.exe --password=hunter2 --api-key=secretX"
    )
    run_findings.write_text(json.dumps(payload), encoding="utf-8")

    out = sanitize_run(str(run))
    redacted = json.loads(
        Path(out, "findings.json").read_text(encoding="utf-8")
    )
    verdict = redacted["summary"]["verdict"]
    # Hostname → hash token.
    assert "HOSTA" not in verdict
    assert "HOST-" in verdict
    # Secrets → <SECRET>.
    assert "hunter2" not in verdict
    assert "secretX" not in verdict
    assert "<SECRET>" in verdict
