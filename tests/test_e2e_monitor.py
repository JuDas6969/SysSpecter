"""End-to-end smoke test: real monitor run → real report.

Spawns the CLI as a subprocess (so the test exercises the exact entry
point the user invokes), runs a ~5 s monitor, then asserts the expected
artefacts exist and are structurally valid.

Marked slow so it does not run under the unit-test pass. Gate:

    pytest -q -m e2e tests/test_e2e_monitor.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _python() -> str:
    """Use the venv Python if present, else the test interpreter."""
    venv = REPO / ".venv" / "Scripts" / "python.exe"
    return str(venv) if venv.exists() else sys.executable


@pytest.mark.e2e
def test_monitor_5_seconds_produces_report(tmp_path: Path) -> None:
    """Full CLI → collector → analyzer → reporter chain in under 30 s."""
    out_root = tmp_path / "e2e"
    out_root.mkdir()

    proc = subprocess.run(
        [
            _python(), str(REPO / "sysspecter.py"),
            "monitor",
            "--mode", "baseline",
            "--duration", "5",
            "--interval", "1",
            "--output-root", str(out_root),
        ],
        capture_output=True, text=True, timeout=120,
        cwd=str(REPO),
    )

    assert proc.returncode == 0, (
        f"monitor returned {proc.returncode}\n"
        f"--- stdout ---\n{proc.stdout}\n"
        f"--- stderr ---\n{proc.stderr}"
    )

    runs_dir = out_root / "Runs"
    assert runs_dir.exists(), "Runs/ not created"

    run_dirs = list(runs_dir.iterdir())
    assert len(run_dirs) == 1, f"expected 1 run, got {len(run_dirs)}"
    run = run_dirs[0]

    # Must-have artefacts.
    for name in ("manifest.json", "final_report.html", "findings.json",
                 "scores.json", "timeline_system.csv", "static_snapshot.json",
                 "timeline_per_core.csv"):
        assert (run / name).exists(), f"missing artefact: {name}"

    # H5: per-core CSV is long-format (one row per (sample, core)).
    pc_lines = (run / "timeline_per_core.csv").read_text(encoding="utf-8").splitlines()
    assert pc_lines[0] == "timestamp,rel_seconds,core_idx,cpu_pct"
    assert len(pc_lines) > 1, "per-core CSV must contain at least one data row"

    # Manifest is structurally valid + clean-stop.
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] >= 2
    assert manifest["stop_reason"] in ("duration_reached", "duration_elapsed",
                                       "manual_stop")

    # D3: phase3_captured block reflects what actually got data.
    # (Phase 3 was not requested for this baseline-mode run, so all
    # captured flags must be False.)
    assert "phase3_captured" in manifest, "manifest must carry phase3_captured"
    assert manifest["phase3_captured"]["etw_disk"] is False
    assert manifest["phase3_captured"]["event_logs"] is False
    assert manifest["duration_actual_seconds"] >= 4.0
    assert not manifest.get("aborted", False), "run flagged as aborted"

    # HTML report has non-trivial size.
    html_size = (run / "final_report.html").stat().st_size
    assert html_size > 5000, f"final_report.html too small ({html_size} B)"
