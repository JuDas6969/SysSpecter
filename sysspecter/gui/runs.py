"""Scan run folders and produce lightweight summaries for the GUI."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any


@dataclass
class RunInfo:
    path: str
    run_id: str
    hostname: str
    mode: str
    started_at: str | None
    duration_seconds: float | None
    overall_score: float | None
    primary_bottleneck: str | None
    stop_reason: str | None
    has_final_report: bool
    has_phases: bool
    modified_epoch: float
    # Field-review M2: structured fleet metadata. v1/v2 manifests
    # without a `meta` block read as an empty dict.
    meta: dict[str, str]
    tags: list[str]


def _safe_json(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _score_val(scores: dict[str, Any], key: str) -> float | None:
    v = scores.get(key)
    if isinstance(v, dict):
        v = v.get("score")
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def summarize_run(run_dir: str) -> RunInfo | None:
    manifest_path = os.path.join(run_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        return None
    manifest = _safe_json(manifest_path)
    scores = _safe_json(os.path.join(run_dir, "scores.json"))
    try:
        mtime = os.path.getmtime(manifest_path)
    except OSError:
        mtime = 0.0
    raw_meta = manifest.get("meta") or {}
    meta = {
        str(k): str(v) for k, v in raw_meta.items()
        if isinstance(k, str) and isinstance(v, (str, int, float, bool))
    } if isinstance(raw_meta, dict) else {}
    raw_tags = manifest.get("tags") or []
    tags = [str(t) for t in raw_tags if isinstance(t, str)] \
        if isinstance(raw_tags, list) else []
    return RunInfo(
        path=run_dir,
        run_id=str(manifest.get("run_id") or os.path.basename(run_dir)),
        hostname=str(manifest.get("hostname") or "?"),
        mode=str(manifest.get("mode") or "?"),
        started_at=manifest.get("started_at"),
        duration_seconds=manifest.get("duration_actual_seconds"),
        overall_score=_score_val(scores, "overall"),
        primary_bottleneck=scores.get("primary_bottleneck"),
        stop_reason=manifest.get("stop_reason"),
        has_final_report=os.path.exists(os.path.join(run_dir, "final_report.html")),
        has_phases=os.path.exists(os.path.join(run_dir, "phases_report.html")),
        modified_epoch=mtime,
        meta=meta,
        tags=tags,
    )


def scan_runs(output_root: str) -> list[RunInfo]:
    runs_root = os.path.join(output_root, "Runs")
    if not os.path.isdir(runs_root):
        return []
    out: list[RunInfo] = []
    for name in os.listdir(runs_root):
        folder = os.path.join(runs_root, name)
        if not os.path.isdir(folder):
            continue
        info = summarize_run(folder)
        if info is not None:
            out.append(info)
    out.sort(key=lambda r: r.modified_epoch, reverse=True)
    return out
