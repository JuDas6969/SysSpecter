"""Smoke test for the manifest-repair path used when a run is killed hard."""

from __future__ import annotations

import datetime as _dt
import json
import os

from sysspecter.manifest import mark_degraded, repair_manifest_if_aborted


def _write_manifest(run_dir: str, data: dict) -> str:
    path = os.path.join(run_dir, "manifest.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return path


def _write_timeline(run_dir: str, rel_seconds_last: float) -> None:
    path = os.path.join(run_dir, "timeline_system.csv")
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write("timestamp,rel_seconds,cpu_total_pct\n")
        f.write("1.0,0.5,5.0\n")
        f.write(f"2.0,{rel_seconds_last},10.0\n")


def test_repair_infers_end_from_csv(tmp_path) -> None:
    started = _dt.datetime(2026, 4, 23, 10, 0, 0)
    _write_manifest(str(tmp_path), {
        "started_at": started.isoformat(), "ended_at": None,
    })
    _write_timeline(str(tmp_path), 123.4)

    changed = repair_manifest_if_aborted(str(tmp_path))
    assert changed is True

    with open(tmp_path / "manifest.json") as f:
        data = json.load(f)
    assert data["stop_reason"] == "aborted"
    assert data["duration_actual_seconds"] == 123.4
    assert data["ended_at"] == "2026-04-23T10:02:03"


def test_repair_is_idempotent(tmp_path) -> None:
    started = _dt.datetime(2026, 4, 23, 10, 0, 0)
    _write_manifest(str(tmp_path), {
        "started_at": started.isoformat(), "ended_at": None,
    })
    _write_timeline(str(tmp_path), 60.0)

    assert repair_manifest_if_aborted(str(tmp_path)) is True
    assert repair_manifest_if_aborted(str(tmp_path)) is False


def test_mark_degraded_writes_entry(tmp_path) -> None:
    path = _write_manifest(str(tmp_path), {"hostname": "X"})
    mark_degraded(path, "gpu", "nvidia-smi: not found")
    with open(path) as f:
        data = json.load(f)
    assert data["collector_degraded"]["gpu"].startswith("nvidia-smi")


def test_mark_degraded_merges_multiple(tmp_path) -> None:
    path = _write_manifest(str(tmp_path), {"hostname": "X"})
    mark_degraded(path, "gpu", "a")
    mark_degraded(path, "etw_disk", "b")
    with open(path) as f:
        data = json.load(f)
    assert set(data["collector_degraded"].keys()) == {"gpu", "etw_disk"}
