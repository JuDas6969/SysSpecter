"""Fleet aggregation orchestrator.

Builds the fleet-wide view from a list of `RunSummary` items:
  - per-axis fleet stats (mean / p50 / p95 / std)
  - outliers per machine vs fleet (z-score >= 2)
  - per-machine longitudinal grouping (sorted by started_at)
  - per-machine drift (first vs last on each axis)
  - common baseline-deviation signatures across the fleet
"""

from __future__ import annotations

import datetime as _dt
import json
import math
import os
from typing import Any

from ..analyzer.stats import mean, percentile
from ..logging_setup import get_logger
from ..reporter.json_export import atomic_write_json
from .loader import RunSummary, scan_runs_recursive

_log = get_logger(__name__)

_SCORE_AXES = (
    "overall", "stability", "efficiency", "workload_suitability",
    "security_overhead", "network_impact", "resource_hygiene",
)

_OUTLIER_Z_THRESHOLD = 2.0


def _stddev(values: list[float]) -> float | None:
    if len(values) < 2:
        return None
    m = mean(values) or 0.0
    var = sum((v - m) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(var)


def _fleet_stats_for_axis(
    summaries: list[RunSummary], axis: str,
) -> dict[str, Any]:
    values = [getattr(s, axis) for s in summaries
              if getattr(s, axis) is not None]
    if not values:
        return {"samples": 0, "mean": None, "p50": None,
                "p95": None, "std": None}
    return {
        "samples": len(values),
        "mean": round(mean(values) or 0.0, 2),
        "p50": round(percentile(values, 50) or 0.0, 2),
        "p95": round(percentile(values, 95) or 0.0, 2),
        "std": round(_stddev(values) or 0.0, 2),
    }


def _build_fleet_stats(
    summaries: list[RunSummary],
) -> dict[str, dict[str, Any]]:
    return {axis: _fleet_stats_for_axis(summaries, axis) for axis in _SCORE_AXES}


def _detect_outliers(
    summaries: list[RunSummary],
    fleet_stats: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """For each (machine_id, axis) compute z-score against the fleet
    mean. Emit a finding when |z| >= 2.0. Uses the machine's MOST
    RECENT run per axis so the outlier reflects current state, not
    a year-old data point."""
    by_machine: dict[str, RunSummary] = {}
    for s in summaries:
        if not s.machine_id:
            continue
        prev = by_machine.get(s.machine_id)
        if prev is None or (s.started_at or "") > (prev.started_at or ""):
            by_machine[s.machine_id] = s

    out: list[dict[str, Any]] = []
    for axis in _SCORE_AXES:
        stats = fleet_stats[axis]
        m = stats.get("mean")
        std = stats.get("std")
        if m is None or std is None or std <= 0:
            continue
        for machine_id, s in by_machine.items():
            v = getattr(s, axis)
            if v is None:
                continue
            z = (v - m) / std
            if abs(z) < _OUTLIER_Z_THRESHOLD:
                continue
            out.append({
                "machine_id": machine_id,
                "hostname_seen": s.hostname,
                "axis": axis,
                "value": round(v, 1),
                "fleet_mean": m,
                "fleet_std": std,
                "z_score": round(z, 2),
                "direction": "below" if z < 0 else "above",
                "latest_run_id": s.run_id,
                "latest_run_path": s.run_path,
            })
    out.sort(key=lambda o: abs(o["z_score"]), reverse=True)
    return out


def _group_by_machine(
    summaries: list[RunSummary],
) -> dict[str, list[RunSummary]]:
    groups: dict[str, list[RunSummary]] = {}
    for s in summaries:
        key = s.machine_id or f"NO-ID:{s.hostname}"
        groups.setdefault(key, []).append(s)
    for runs in groups.values():
        runs.sort(key=lambda r: r.started_at or "")
    return groups


def _machine_view(
    machine_id: str, runs: list[RunSummary],
) -> dict[str, Any]:
    """Per-machine longitudinal view + drift (first vs last)."""
    drift: dict[str, dict[str, Any]] = {}
    if len(runs) >= 2:
        first, last = runs[0], runs[-1]
        for axis in _SCORE_AXES:
            f = getattr(first, axis)
            ll = getattr(last, axis)
            if f is None or ll is None:
                continue
            delta = round(ll - f, 1)
            drift[axis] = {
                "first": round(f, 1),
                "last": round(ll, 1),
                "delta": delta,
                "direction": "up" if delta > 0 else (
                    "down" if delta < 0 else "flat"
                ),
            }

    score_trend: dict[str, list[dict[str, Any]]] = {}
    for axis in _SCORE_AXES:
        series = []
        for r in runs:
            v = getattr(r, axis)
            if v is None:
                continue
            series.append({
                "run_id": r.run_id,
                "started_at": r.started_at,
                "value": round(v, 1),
            })
        if series:
            score_trend[axis] = series

    classes_seen = sorted({r.machine_class for r in runs if r.machine_class})
    profiles_seen = sorted({r.capture_profile for r in runs if r.capture_profile})
    hostnames_seen = sorted({r.hostname for r in runs if r.hostname and r.hostname != "?"})

    return {
        "machine_id": machine_id,
        "runs": len(runs),
        "first_run_at": runs[0].started_at,
        "last_run_at": runs[-1].started_at,
        "hostnames_seen": hostnames_seen,
        "machine_classes_seen": classes_seen,
        "capture_profiles_seen": profiles_seen,
        "score_drift": drift,
        "score_trend": score_trend,
    }


def _common_baseline_deviations(
    summaries: list[RunSummary],
) -> list[dict[str, Any]]:
    """Roll up baseline deviations across the fleet by signature
    (machine_class, metric). Reports each signature with how many
    machines it affects."""
    machines_with_signature: dict[tuple[str, str], set[str]] = {}
    machines_in_class: dict[str, set[str]] = {}
    for s in summaries:
        machine = s.machine_id or s.hostname
        if s.machine_class:
            machines_in_class.setdefault(s.machine_class, set()).add(machine)
        for d in s.baseline_deviations:
            sig = (d.get("machine_class") or "?",
                   d.get("metric") or "?")
            machines_with_signature.setdefault(sig, set()).add(machine)
    rolled: list[dict[str, Any]] = []
    for (cls, metric), machines in machines_with_signature.items():
        rolled.append({
            "machine_class": cls,
            "metric": metric,
            "machines_affected": len(machines),
            "machines_in_class": len(machines_in_class.get(cls, set())) or None,
        })
    rolled.sort(key=lambda r: r["machines_affected"], reverse=True)
    return rolled


def aggregate(summaries: list[RunSummary]) -> dict[str, Any]:
    """Top-level aggregation. Pure function over the loaded
    summaries; safe to test directly."""
    fleet_stats = _build_fleet_stats(summaries)
    outliers = _detect_outliers(summaries, fleet_stats)
    machine_groups = _group_by_machine(summaries)
    per_machine = {
        mid: _machine_view(mid, runs) for mid, runs in machine_groups.items()
    }

    # Headline counts
    distinct_machine_ids = sum(
        1 for mid in machine_groups
        if mid and not mid.startswith("NO-ID:")
    )
    no_id_runs = sum(
        len(runs) for mid, runs in machine_groups.items()
        if mid.startswith("NO-ID:")
    )

    return {
        "runs_scanned": len(summaries),
        "distinct_machines": len(machine_groups),
        "machines_with_id": distinct_machine_ids,
        "runs_without_machine_id": no_id_runs,
        "fleet_stats": fleet_stats,
        "outliers": outliers,
        "per_machine": per_machine,
        "common_baseline_deviations": _common_baseline_deviations(summaries),
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def run_aggregate(input_root: str, output_root: str) -> str:
    """End-to-end: scan a runs/ tree, aggregate, write the JSON +
    HTML report into ``<output_root>/Aggregations/AGG_<ts>/``.
    Returns the aggregation folder path."""
    _log.info("aggregating runs under %s", input_root)
    summaries = scan_runs_recursive(input_root)
    _log.info("loaded %d run summaries", len(summaries))
    result = aggregate(summaries)

    ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(output_root, "Aggregations", f"AGG_{ts}")
    os.makedirs(out_dir, exist_ok=True)

    manifest = {
        "aggregation_id": f"AGG_{ts}",
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "input_root": os.path.abspath(input_root),
        "runs_scanned": result["runs_scanned"],
        "distinct_machines": result["distinct_machines"],
    }
    atomic_write_json(os.path.join(out_dir, "manifest.json"), manifest)
    atomic_write_json(
        os.path.join(out_dir, "aggregated_findings.json"),
        result,
    )

    # Per-machine CSV — handy for spreadsheet-driven follow-up.
    csv_path = os.path.join(out_dir, "per_machine.csv")
    _write_per_machine_csv(csv_path, result["per_machine"])

    # HTML report (lazy import so the json output works even if
    # jinja or the template is missing).
    try:
        from .report import build_aggregation_report
        build_aggregation_report(out_dir, manifest, result)
    except Exception as e:
        _log.warning("HTML report build failed: %s", e)

    _log.info("aggregation written to %s", out_dir)
    return out_dir


def _write_per_machine_csv(
    path: str, per_machine: dict[str, dict[str, Any]],
) -> None:
    import csv
    fields = [
        "machine_id", "runs", "first_run_at", "last_run_at",
        "hostnames_seen", "machine_classes_seen",
        "drift_overall", "drift_stability", "drift_efficiency",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(fields)
        for mid, m in per_machine.items():
            drift = m.get("score_drift") or {}
            w.writerow([
                mid,
                m.get("runs"),
                m.get("first_run_at") or "",
                m.get("last_run_at") or "",
                ", ".join(m.get("hostnames_seen") or []),
                ", ".join(m.get("machine_classes_seen") or []),
                json.dumps(drift.get("overall") or {}, ensure_ascii=False),
                json.dumps(drift.get("stability") or {}, ensure_ascii=False),
                json.dumps(drift.get("efficiency") or {}, ensure_ascii=False),
            ])
