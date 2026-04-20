"""Run manifest — session metadata written at start and updated at end."""

from __future__ import annotations

import ctypes
import datetime as _dt
import json
import os
import socket
import sys
from typing import Any

from .config import Config
from .paths import RunPaths


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def build_run_manifest(paths: RunPaths, config: Config) -> dict[str, Any]:
    return {
        "schema_version": 1,
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
    }


def update_manifest_end(
    manifest_path: str,
    ended_at: _dt.datetime,
    stop_reason: str,
    actual_duration: float,
) -> None:
    with open(manifest_path, "r", encoding="utf-8") as f:
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


def load_manifest(manifest_path: str) -> dict[str, Any]:
    with open(manifest_path, "r", encoding="utf-8") as f:
        return json.load(f)
