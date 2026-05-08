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
    stamp_phase3_captured,
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


# ----- Field-review D3: phase3_captured reflects reality, not request --


def _write_run_with_artifacts(
    tmp_path: Path,
    *,
    process_events_n: int = 0,
    event_logs_n: int = 0,
    etw_disabled_only: bool = False,
    gpu_engine_rows: int = 0,
) -> Path:
    paths = _make_paths(tmp_path)
    cfg = Config(output_root=str(tmp_path), mode="support",
                 thresholds=Thresholds())
    write_manifest(paths.manifest, build_run_manifest(paths, cfg))
    run = Path(paths.run_dir)

    (run / "process_events.json").write_text(
        json.dumps([{"event": "x"}] * process_events_n), encoding="utf-8"
    )
    (run / "event_log.json").write_text(
        json.dumps({"events": [{}] * event_logs_n}) if event_logs_n
        else json.dumps([]),
        encoding="utf-8",
    )
    if etw_disabled_only:
        (run / "etw_disk_summary.json").write_text(
            json.dumps({"enabled": False}), encoding="utf-8"
        )
    if gpu_engine_rows > 0:
        rows = "rel_seconds,instance,pct\n" + "\n".join(
            f"{i},GPU/Engine{i},10" for i in range(gpu_engine_rows)
        )
        (run / "timeline_gpu_engine.csv").write_text(rows, encoding="utf-8")
    return run


def test_phase3_captured_records_real_data(tmp_path: Path) -> None:
    """When ETW + event-logs were requested but only events fired,
    captured must show event_logs True / etw_disk False — even though
    phase3.etw_disk in the request block is True."""
    run = _write_run_with_artifacts(
        tmp_path,
        process_events_n=12,
        event_logs_n=3,
        etw_disabled_only=True,
        gpu_engine_rows=0,
    )
    captured = stamp_phase3_captured(str(run))
    assert captured["process_events"] is True
    assert captured["event_logs"] is True
    assert captured["etw_disk"] is False  # placeholder file, no real data
    assert captured["gpu_engine"] is False

    # Round-trip: the manifest now carries the captured block.
    data = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    assert data["phase3_captured"]["event_logs"] is True
    assert data["phase3_captured"]["etw_disk"] is False
    # Original `phase3` (request) block is untouched.
    assert "phase3" in data


def test_phase3_captured_handles_missing_artifacts(tmp_path: Path) -> None:
    """A run aborted before phase 3 finalised: no phase3 files at all.
    Every captured flag must be False, no exception."""
    run = _write_run_with_artifacts(tmp_path)
    # Remove the artefacts the helper wrote.
    for name in ("process_events.json", "event_log.json"):
        (run / name).unlink()
    captured = stamp_phase3_captured(str(run))
    assert all(v is False for v in captured.values())


def test_phase3_captured_no_manifest_returns_empty(tmp_path: Path) -> None:
    # Pre-manifest crash: stamping must not raise, just return {}.
    captured = stamp_phase3_captured(str(tmp_path / "no-such-run"))
    assert captured == {}
