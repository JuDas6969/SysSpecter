"""Build the synthetic reference run used by the golden-report regression.

Run this script once when you intentionally change the report template
or refresh the golden fixture:

    python tests/data/build_reference_run.py

It writes:
- tests/data/reference_run/         — the synthetic run folder
- tests/golden/final_report.html    — the rendered HTML (golden)

The test suite does NOT execute this script — it only checks that a
fresh render matches the committed golden HTML (with timestamps masked).
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO))

RUN_DIR = HERE / "reference_run"
GOLDEN = REPO / "tests" / "golden" / "final_report.html"


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def _write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def build() -> None:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    (RUN_DIR / "logs").mkdir(exist_ok=True)

    manifest = {
        "schema_version": 2,
        "sysspecter_version": "1.0.0",
        "run_id": "REF_20260101_120000",
        "hostname": "REFHOST",
        "fqdn": "refhost.example.com",
        "started_at": "2026-01-01T12:00:00",
        "ended_at": "2026-01-01T12:05:00",
        "stop_reason": "duration_reached",
        "mode": "support",
        "duration_requested_seconds": 300,
        "duration_actual_seconds": 300.0,
        "interval_seconds": 1.0,
        "manual_stop": False,
        "tags": ["reference", "golden"],
        "target": {"name": None, "pid": None, "path": None},
        "latency_targets": ["127.0.0.1", "8.8.8.8"],
        "output_root": "X:\\ref",
        "run_dir": str(RUN_DIR),
        "privilege_level": "admin",
        "thresholds": {}, "phase3": {},
        "collector_degraded": {},
    }
    _write_json(RUN_DIR / "manifest.json", manifest)
    _write_json(RUN_DIR / "static_snapshot.json", {
        "os": {"caption": "Windows 11 Pro", "build": "22631",
               "version": "10.0.22631", "architecture": "64-bit"},
        "computer_system": {"Manufacturer": "Reference, Inc.",
                            "Model": "RefBook"},
        "cpu": {"cpus": [{"Name": "Reference CPU @ 3.0 GHz"}],
                "physical_cores": 4, "logical_cores": 8},
        "memory": {"total_bytes": 16 * 1024**3},
        "security": {"defender_status": {
            "RealTimeProtectionEnabled": True,
            "AntivirusEnabled": True,
            "AntivirusSignatureVersion": "1.0",
        }, "antivirus_products": []},
        "power": {"active_scheme_raw": "High performance"},
        "network": {"vpn_suspect_adapters": []},
        "bios": {"SMBIOSBIOSVersion": "1.0", "ReleaseDate": "2024-01-01"},
        "installed_programs": [], "autoruns": [], "disks": [],
    })
    _write_json(RUN_DIR / "findings.json", {
        "anomalies": [],
        "slowdowns": [],
        "leaks": {"memory": [], "handles": [], "threads": []},
        "offenders": {},
        "apps": {},
        "network_attribution": {"by_app": [], "by_pid": [], "samples": 0},
        "latency_analysis": {"targets": [], "samples": 0},
        "gpu_analysis": {"enabled": False},
        "event_correlation": {"enabled": False},
        "etw_disk": {"enabled": False},
        "process_churn": {"total_process_starts": 0},
        "bottlenecks": {"primary": None, "secondary_bottlenecks": [],
                        "scores": {}, "reasons": {}},
        "summary": {"verdict": "System behaved normally during the reference run.",
                    "total_anomalies": 0, "total_slowdown_windows": 0,
                    "total_leak_candidates": 0, "primary_bottleneck": None},
    })
    _write_json(RUN_DIR / "scores.json", {
        "stability": {"score": 92, "details": {}},
        "efficiency": {"score": 78, "details": {}},
        "workload_suitability": {"score": 50, "details": {}},
        "security_overhead": {"score": 90, "details": {}},
        "network_impact": {"score": 88, "details": {}},
        "resource_hygiene": {"score": 100, "details": {}},
        "overall": 85,
        "weights": {"stability": 0.25, "efficiency": 0.15,
                    "workload": 0.15, "security": 0.10,
                    "network": 0.15, "hygiene": 0.20},
        "primary_bottleneck": None, "secondary_bottlenecks": [],
        "confidence": "high", "sample_count": 300,
    })
    # Deterministic timeline: light sawtooth so the chart has something
    # visible but values are stable.
    rows = []
    for t in range(300):
        cpu = 10 + (t % 10)           # 10..19 sawtooth
        mem = 40 + (t % 5)            # 40..44
        disk = 5 + (t % 4)            # 5..8
        rows.append([f"{t+1}.000000", f"{t}", f"{cpu}", f"{mem}", f"{disk}", ""])
    _write_csv(RUN_DIR / "timeline_system.csv",
               ["timestamp", "rel_seconds", "cpu_total_pct",
                "mem_percent", "disk_active_pct_est", "cpu_per_core_pct"],
               rows)
    # Empty optional streams
    for name in ("timeline_processes.csv", "timeline_network.csv",
                 "timeline_latency.csv", "timeline_connections.csv",
                 "timeline_gpu_engine.csv", "timeline_gpu_process.csv",
                 "timeline_gpu_adapter.csv"):
        (RUN_DIR / name).write_text("", encoding="utf-8")
    for name in ("process_events.json", "service_events.json"):
        _write_json(RUN_DIR / name, [])

    # Render via the current pipeline
    from sysspecter.reporter.html_report import build_report

    build_report(str(RUN_DIR))
    # Copy final_report.html into the golden slot
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    html = (RUN_DIR / "final_report.html").read_text(encoding="utf-8")
    GOLDEN.write_text(html, encoding="utf-8")
    print(f"Wrote {GOLDEN} ({len(html)} bytes)")


if __name__ == "__main__":
    build()
