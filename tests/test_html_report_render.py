"""Golden-ish smoke test: the HTML report renderer runs end-to-end on
a minimal synthetic run folder without raising and emits a file that
contains the expected banner text and tool version.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest


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


@pytest.fixture
def synth_run(tmp_path: Path) -> Path:
    run = tmp_path / "RUN1"
    _write_json(run / "manifest.json", {
        "schema_version": 1,
        "sysspecter_version": "1.0.0",
        "run_id": "RUN1",
        "hostname": "HOST1",
        "fqdn": "host1.example.com",
        "mode": "support",
        "started_at": "2026-04-23T01:00:00",
        "ended_at": "2026-04-23T01:05:00",
        "duration_actual_seconds": 300,
        "interval_seconds": 1.0,
        "stop_reason": "manual",
        "privilege_level": "user",
        "target": {"name": None, "pid": None, "path": None},
        "tags": [], "latency_targets": [],
        "output_root": str(tmp_path), "run_dir": str(run),
        "python_version": "3.12", "python_executable": "py",
        "thresholds": {}, "phase3": {}, "collector_degraded": {},
    })
    _write_json(run / "static_snapshot.json", {
        "os": {"caption": "Windows 10", "build": "19044",
               "version": "10.0.19044", "architecture": "64-bit"},
        "computer_system": {"Manufacturer": "Dell", "Model": "Latitude"},
        "cpu": {"cpus": [{"Name": "i5"}], "physical_cores": 4, "logical_cores": 8},
        "memory": {"total_bytes": 16 * 1024**3},
        "security": {"defender_status": {}, "antivirus_products": []},
        "power": {"active_scheme_raw": "(Balanced) *"},
        "network": {"vpn_suspect_adapters": []},
        "bios": {"SMBIOSBIOSVersion": "1.0", "ReleaseDate": "2024-01-01"},
        "installed_programs": [], "autoruns": [],
        "disks": [],
    })
    _write_json(run / "findings.json", {
        "anomalies": [], "slowdowns": [], "leaks": {"memory": [], "handles": [], "threads": []},
        "offenders": {}, "apps": {},
        "network_attribution": {"by_app": [], "by_pid": [], "samples": 0},
        "latency_analysis": {"targets": [], "samples": 0},
        "gpu_analysis": {"enabled": False},
        "event_correlation": {"enabled": False},
        "etw_disk": {"enabled": False},
        "process_churn": {"total_process_starts": 0},
        "bottlenecks": {"primary": None, "secondary_bottlenecks": [], "scores": {}, "reasons": {}},
        "summary": {"verdict": "looks fine", "total_anomalies": 0,
                    "total_slowdown_windows": 0, "total_leak_candidates": 0,
                    "primary_bottleneck": None},
    })
    _write_json(run / "scores.json", {
        "stability": {"score": 80, "details": {}},
        "efficiency": {"score": 75, "details": {}},
        "workload_suitability": {"score": 50, "details": {}},
        "security_overhead": {"score": 90, "details": {}},
        "network_impact": {"score": 85, "details": {}},
        "resource_hygiene": {"score": 95, "details": {}},
        "overall": 80, "weights": {"stability": 0.25},
        "primary_bottleneck": None, "secondary_bottlenecks": [],
        "confidence": "medium", "sample_count": 300,
    })
    _write_csv(run / "timeline_system.csv",
               ["timestamp", "rel_seconds", "cpu_total_pct", "mem_percent",
                "disk_active_pct_est", "cpu_per_core_pct"],
               [[f"{t}.0", f"{t}", "20", "40", "5", ""] for t in range(300)])
    # empty phase-3 + timeline files
    for name in ("timeline_processes.csv", "timeline_network.csv",
                 "timeline_latency.csv", "timeline_connections.csv",
                 "timeline_gpu_engine.csv", "timeline_gpu_process.csv",
                 "timeline_gpu_adapter.csv"):
        (run / name).write_text("", encoding="utf-8")
    for name in ("process_events.json", "service_events.json"):
        _write_json(run / name, [])
    (run / "logs").mkdir(exist_ok=True)
    return run


def test_build_report_writes_html_with_version_banner(synth_run: Path) -> None:
    from sysspecter.reporter.html_report import build_report
    out = build_report(str(synth_run))
    assert Path(out).exists()
    content = Path(out).read_text(encoding="utf-8")
    # brand header, admin banner, and tool version must all land
    assert "SysSpecter v1.0.0" in content
    assert "brand-bar" in content
    assert "Running as standard user" in content  # privilege_level=user
    assert "HOST1" in content
    # css is inlined
    assert ".score-grid" in content


def test_build_report_shows_low_confidence_for_short_run(synth_run: Path) -> None:
    from sysspecter.reporter.html_report import build_report
    # overwrite system timeline with only 10 rows
    _write_csv(synth_run / "timeline_system.csv",
               ["timestamp", "rel_seconds", "cpu_total_pct", "mem_percent",
                "disk_active_pct_est", "cpu_per_core_pct"],
               [[f"{t}.0", f"{t}", "20", "40", "5", ""] for t in range(10)])
    out = build_report(str(synth_run))
    content = Path(out).read_text(encoding="utf-8")
    assert "Low sample count" in content or "Not enough" in content
