"""Per-run summary loader for fleet aggregation.

Walks a tree of run folders and emits one ``RunSummary`` per run.
Reads the absolute minimum needed for fleet aggregation — score
axes, machine identity, baseline deviations, leak / deadlock counts —
without loading the full timeline CSVs. Designed to scale to
hundreds or thousands of runs.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RunSummary:
    """Compact per-run extract suitable for fleet aggregation. The
    fields here are populated from manifest.json + scores.json +
    findings.json with everything else dropped."""

    run_id: str
    run_path: str
    hostname: str
    machine_id: str | None
    machine_id_source: str | None
    machine_class: str | None
    capture_profile: str | None
    started_at: str | None
    duration_seconds: float | None

    overall: float | None
    stability: float | None
    efficiency: float | None
    workload_suitability: float | None
    security_overhead: float | None
    network_impact: float | None
    resource_hygiene: float | None

    primary_bottleneck: str | None
    confidence: str | None

    leak_count: int
    deadlock_count: int
    anomaly_count: int
    slowdown_count: int

    baseline_deviations: list[dict[str, Any]] = field(default_factory=list)


def _safe_json(path: str) -> dict[str, Any] | None:
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _score_axis(scores: dict[str, Any], key: str) -> float | None:
    v = scores.get(key)
    if isinstance(v, dict):
        v = v.get("score")
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def load_run_summary(run_dir: str) -> RunSummary | None:
    """Build a RunSummary from a single run folder. Returns None
    if the manifest is missing or unreadable (e.g. an aborted run
    that never wrote one)."""
    manifest = _safe_json(os.path.join(run_dir, "manifest.json"))
    if manifest is None:
        return None
    scores = _safe_json(os.path.join(run_dir, "scores.json")) or {}
    findings = _safe_json(os.path.join(run_dir, "findings.json")) or {}
    meta = manifest.get("meta") or {}

    leak_count = 0
    leaks = findings.get("leaks") or {}
    if isinstance(leaks, dict):
        for category in ("memory", "handles", "threads"):
            entries = leaks.get(category) or []
            if isinstance(entries, list):
                leak_count += len(entries)
    deadlock_count = len(findings.get("deadlocks") or [])
    anomaly_count = len(findings.get("anomalies") or [])
    slowdown_count = len(findings.get("slowdowns") or [])

    return RunSummary(
        run_id=str(manifest.get("run_id") or os.path.basename(run_dir)),
        run_path=os.path.abspath(run_dir),
        hostname=str(manifest.get("hostname") or "?"),
        machine_id=manifest.get("machine_id"),
        machine_id_source=manifest.get("machine_id_source"),
        machine_class=meta.get("machine_class"),
        capture_profile=meta.get("capture_profile"),
        started_at=manifest.get("started_at"),
        duration_seconds=(
            float(manifest.get("duration_actual_seconds"))
            if manifest.get("duration_actual_seconds") is not None else None
        ),
        overall=_score_axis(scores, "overall"),
        stability=_score_axis(scores, "stability"),
        efficiency=_score_axis(scores, "efficiency"),
        workload_suitability=_score_axis(scores, "workload_suitability"),
        security_overhead=_score_axis(scores, "security_overhead"),
        network_impact=_score_axis(scores, "network_impact"),
        resource_hygiene=_score_axis(scores, "resource_hygiene"),
        primary_bottleneck=scores.get("primary_bottleneck"),
        confidence=scores.get("confidence"),
        leak_count=leak_count,
        deadlock_count=deadlock_count,
        anomaly_count=anomaly_count,
        slowdown_count=slowdown_count,
        baseline_deviations=list(findings.get("baseline_deviations") or []),
    )


def scan_runs_recursive(root: str) -> list[RunSummary]:
    """Walk the given directory tree, returning a `RunSummary` for
    every folder that contains a `manifest.json`. Tolerates broken
    runs (skips them with no error). Recursive so the same tool
    works against `<output-root>/Runs/` and against an arbitrary
    archive of runs collected from a fleet."""
    summaries: list[RunSummary] = []
    if not os.path.isdir(root):
        return summaries
    for cur_dir, _subdirs, files in os.walk(root):
        if "manifest.json" not in files:
            continue
        s = load_run_summary(cur_dir)
        if s is not None:
            summaries.append(s)
    summaries.sort(key=lambda s: (s.machine_id or "", s.started_at or ""))
    return summaries
