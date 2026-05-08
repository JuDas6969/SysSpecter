"""Run manifest — session metadata written at start and updated at end."""

from __future__ import annotations

import csv as _csv
import ctypes
import datetime as _dt
import json
import os
import socket
import sys
from typing import Any

from . import __version__ as _SS_VERSION
from .config import Config
from .paths import RunPaths


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def build_run_manifest(paths: RunPaths, config: Config) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "sysspecter_version": _SS_VERSION,
        "run_id": paths.run_id,
        "hostname": paths.hostname,
        "fqdn": socket.getfqdn(),
        "started_at": paths.started_at.isoformat(timespec="seconds"),
        "ended_at": None,
        "stop_reason": None,
        "mode": config.mode,
        "duration_requested_seconds": config.duration,
        "duration_actual_seconds": None,
        "interval_seconds": config.interval,
        "manual_stop": config.manual_stop,
        "tags": list(config.tags),
        # Field-review M2: structured fleet metadata. Distinct from
        # free-form `tags` so downstream tools can filter without
        # parsing strings.
        "meta": dict(config.meta),
        "target": {
            "name": config.target_name,
            "pid": config.target_pid,
            "path": config.target_path,
        },
        "latency_targets": list(config.latency_targets),
        "output_root": paths.root,
        "run_dir": paths.run_dir,
        "privilege_level": "admin" if is_admin() else "user",
        "python_version": sys.version,
        "python_executable": sys.executable,
        "thresholds": config.thresholds.__dict__,
        "phase3": {
            "gpu": config.enable_gpu,
            "event_logs": config.enable_event_logs,
            "etw_disk": config.enable_etw_disk,
        },
        # populated by samplers if they fail / degrade; see runner.py
        "collector_degraded": {},
    }


def update_manifest_end(
    manifest_path: str,
    ended_at: _dt.datetime,
    stop_reason: str,
    actual_duration: float,
) -> None:
    with open(manifest_path, encoding="utf-8") as f:
        data = json.load(f)
    data["ended_at"] = ended_at.isoformat(timespec="seconds")
    data["stop_reason"] = stop_reason
    data["duration_actual_seconds"] = round(actual_duration, 2)
    tmp = manifest_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, manifest_path)


def write_manifest(manifest_path: str, manifest: dict[str, Any]) -> None:
    tmp = manifest_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    os.replace(tmp, manifest_path)


def mark_degraded(manifest_path: str, collector: str, reason: str) -> None:
    """Record a non-fatal collector failure in the manifest so the report
    can surface a 'measurement degraded' banner. Safe to call before or
    after the run ends."""
    try:
        with open(manifest_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return
    deg = data.setdefault("collector_degraded", {})
    if not isinstance(deg, dict):
        deg = {}
        data["collector_degraded"] = deg
    deg[collector] = reason
    tmp = manifest_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, manifest_path)


def load_manifest(manifest_path: str) -> dict[str, Any]:
    with open(manifest_path, encoding="utf-8") as f:
        return json.load(f)


def _last_rel_seconds_in_csv(csv_path: str) -> float | None:
    if not os.path.exists(csv_path):
        return None
    last: float | None = None
    try:
        with open(csv_path, encoding="utf-8", newline="") as f:
            reader = _csv.DictReader(f)
            for row in reader:
                v = row.get("rel_seconds")
                if not v:
                    continue
                try:
                    last = float(v)
                except (TypeError, ValueError):
                    continue
    except OSError:
        return None
    return last


def stamp_phase3_captured(run_dir: str) -> dict[str, bool]:
    """Walk the finished run folder and stamp a `phase3_captured` block
    onto the manifest reflecting what actually produced data — distinct
    from `phase3` which records what was *requested*. Field-review D3.

    Returns the captured map for callers that want to log it.
    """
    manifest_path = os.path.join(run_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        return {}
    try:
        with open(manifest_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}

    def _file_has_data(name: str) -> bool:
        p = os.path.join(run_dir, name)
        if not os.path.exists(p):
            return False
        try:
            if p.endswith(".json"):
                with open(p, encoding="utf-8") as f:
                    payload = json.load(f)
                if isinstance(payload, list):
                    return len(payload) > 0
                if isinstance(payload, dict):
                    if not payload:
                        return False
                    # Reject the "{enabled: false}" placeholder writers
                    # use to signal "feature was off".
                    if list(payload.keys()) == ["enabled"] and not payload["enabled"]:
                        return False
                    return True
                return True
            # CSVs: more than the header line counts as "has data".
            with open(p, encoding="utf-8", newline="") as f:
                lines = f.readlines()
            return len(lines) > 1
        except (OSError, json.JSONDecodeError):
            return False

    captured = {
        "process_events": _file_has_data("process_events.json"),
        "service_events": _file_has_data("service_events.json"),
        "event_logs": _file_has_data("event_log.json"),
        "etw_disk": _file_has_data("etw_disk_summary.json"),
        "gpu_engine": _file_has_data("timeline_gpu_engine.csv"),
        "gpu_process": _file_has_data("timeline_gpu_process.csv"),
        "gpu_adapter": _file_has_data("timeline_gpu_adapter.csv"),
    }

    data["phase3_captured"] = captured

    tmp = manifest_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, manifest_path)
    return captured


def repair_manifest_if_aborted(run_dir: str) -> bool:
    """If the manifest has no ended_at (run was killed hard), infer end from artifacts.

    Uses the last rel_seconds in timeline_system.csv for duration; falls back to
    the collector.log mtime. Sets stop_reason="aborted". Returns True if the
    manifest was modified.
    """
    manifest_path = os.path.join(run_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        return False
    with open(manifest_path, encoding="utf-8") as f:
        data = json.load(f)
    if data.get("ended_at"):
        return False

    started_at: _dt.datetime | None = None
    started_str = data.get("started_at")
    if isinstance(started_str, str):
        try:
            started_at = _dt.datetime.fromisoformat(started_str)
        except ValueError:
            started_at = None

    duration = _last_rel_seconds_in_csv(os.path.join(run_dir, "timeline_system.csv"))
    ended_at: _dt.datetime | None = None
    if started_at is not None and duration is not None:
        ended_at = started_at + _dt.timedelta(seconds=duration)
    else:
        log_path = os.path.join(run_dir, "logs", "collector.log")
        if os.path.exists(log_path):
            ended_at = _dt.datetime.fromtimestamp(os.path.getmtime(log_path))
            if started_at is not None and duration is None:
                duration = (ended_at - started_at).total_seconds()

    data["ended_at"] = ended_at.isoformat(timespec="seconds") if ended_at else None
    data["stop_reason"] = "aborted"
    data["duration_actual_seconds"] = round(duration, 2) if duration is not None else None

    tmp = manifest_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, manifest_path)
    return True
