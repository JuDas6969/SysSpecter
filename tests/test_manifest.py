"""Tests for manifest.py beyond repair_manifest_if_aborted (already covered
in test_manifest_repair.py). Focus: build, end-update, degradation records."""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from sysspecter.config import Config, Thresholds
from sysspecter.manifest import (
    build_run_manifest,
    mark_degraded,
    update_manifest_end,
    write_manifest,
)
from sysspecter.paths import RunPaths


def _make_paths(tmp_path: Path) -> RunPaths:
    run_dir = tmp_path / "HOST_20260423_010000"
    run_dir.mkdir()
    return RunPaths(
        root=str(tmp_path),
        run_id=run_dir.name,
        hostname="HOST",
        started_at=_dt.datetime(2026, 4, 23, 1, 0, 0),
        run_dir=str(run_dir),
        logs_dir=str(run_dir / "logs"),
    )


def test_build_manifest_has_required_v2_fields(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    cfg = Config(
        output_root=str(tmp_path), mode="baseline", duration=300,
        interval=1.0, manual_stop=False,
        tags=["autopilot"], latency_targets=["8.8.8.8"],
        thresholds=Thresholds(),
    )
    m = build_run_manifest(paths, cfg)

    # Schema contract the reporter relies on.
    assert m["schema_version"] == 2
    assert m["run_id"] == paths.run_id
    assert m["mode"] == "baseline"
    assert m["duration_requested_seconds"] == 300
    assert m["manual_stop"] is False
    assert m["tags"] == ["autopilot"]
    assert m["latency_targets"] == ["8.8.8.8"]
    assert m["ended_at"] is None
    assert m["stop_reason"] is None
    assert m["collector_degraded"] == {}
    assert isinstance(m["thresholds"], dict)
    assert m["privilege_level"] in ("admin", "user")


def test_update_manifest_end_sets_all_end_fields(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    cfg = Config(output_root=str(tmp_path), mode="support", duration=60,
                 thresholds=Thresholds())
    manifest_path = tmp_path / "manifest.json"
    write_manifest(str(manifest_path), build_run_manifest(paths, cfg))

    update_manifest_end(
        str(manifest_path),
        ended_at=_dt.datetime(2026, 4, 23, 1, 1, 0),
        stop_reason="duration_elapsed",
        actual_duration=60.5,
    )
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert data["ended_at"] == "2026-04-23T01:01:00"
    assert data["stop_reason"] == "duration_elapsed"
    assert data["duration_actual_seconds"] == 60.5


def test_mark_degraded_accumulates_entries(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    cfg = Config(output_root=str(tmp_path), mode="support", thresholds=Thresholds())
    manifest_path = tmp_path / "manifest.json"
    write_manifest(str(manifest_path), build_run_manifest(paths, cfg))

    mark_degraded(str(manifest_path), "gpu_sampler", "powershell timeout")
    mark_degraded(str(manifest_path), "eventlog", "permission denied")

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert data["collector_degraded"] == {
        "gpu_sampler": "powershell timeout",
        "eventlog": "permission denied",
    }


def test_mark_degraded_on_missing_file_does_not_raise(tmp_path: Path) -> None:
    # If the manifest has never been written (very early crash), the
    # degradation record must silently no-op instead of crashing.
    mark_degraded(str(tmp_path / "nonexistent.json"), "x", "y")
    assert not (tmp_path / "nonexistent.json").exists()
