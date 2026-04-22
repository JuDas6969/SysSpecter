"""Orchestrate the split flow: detect -> per-phase sub-report -> overview."""

from __future__ import annotations

import os
import shutil
from typing import Any

from ..analyzer.loader import load_run
from ..analyzer.pipeline import analyze_run
from ..logging_setup import get_logger
from ..manifest import repair_manifest_if_aborted
from ..reporter.json_export import atomic_write_json
from .detect import (
    ChangePoint,
    Phase,
    build_phases,
    change_point_to_dict,
    detect_change_points,
    phase_to_dict,
)
from .overview import build_overview_report


def _phase_dir_name(phase: Phase) -> str:
    return f"phase_{phase.phase_id:02d}_{int(phase.start_rel):05d}s-{int(phase.end_rel):05d}s"


def split_run(
    run_dir: str,
    *,
    min_phase_seconds: float = 60.0,
    window_seconds: float = 20.0,
    step_threshold: float = 12.0,
    slope_threshold: float = 0.8,
    proximity_seconds: float = 30.0,
    build_subreports: bool = True,
) -> dict[str, Any]:
    """Run the full split pipeline on a finished run folder.

    Returns a dict summarising the result (phases, change_points, sub-report paths).
    Writes:
      <run_dir>/phases.json
      <run_dir>/phases_report.html
      <run_dir>/phases/<phase_dir>/... (when build_subreports is True)
    """
    os.makedirs(os.path.join(run_dir, "logs"), exist_ok=True)
    logger = get_logger("splitter", os.path.join(run_dir, "logs", "splitter.log"))
    logger.info("splitting run: %s", run_dir)

    if repair_manifest_if_aborted(run_dir):
        logger.info("manifest was incomplete -- repaired with stop_reason=aborted")
        print("  Manifest unvollstaendig -- repariert (stop_reason=aborted).", flush=True)

    rd = load_run(run_dir)
    if not rd.system_rows:
        msg = "no system timeline samples found; nothing to split"
        logger.warning(msg)
        print(f"  {msg}", flush=True)
        return {"phases": [], "change_points": [], "reason": msg}

    total_duration = float(rd.system_rows[-1].get("rel_seconds") or 0.0)
    if total_duration < 2 * min_phase_seconds:
        msg = (f"run too short for splitting ({total_duration:.0f}s < 2*{min_phase_seconds:.0f}s) "
               f"-- treating as single phase")
        logger.info(msg)
        print(f"  {msg}", flush=True)
        phases = [Phase(phase_id=1, start_rel=0.0, end_rel=total_duration,
                        duration_seconds=total_duration,
                        reason_at_start=None, evidence_at_start=None)]
        change_points: list[ChangePoint] = []
    else:
        change_points = detect_change_points(
            rd.system_rows, rd.process_rows,
            window_seconds=window_seconds,
            step_threshold=step_threshold,
            slope_threshold=slope_threshold,
            proximity_seconds=proximity_seconds,
        )
        phases = build_phases(change_points, total_duration, min_phase_seconds)
        logger.info("detected %d change points -> %d phases",
                    len(change_points), len(phases))
        print(f"  {len(change_points)} Change-Points -> {len(phases)} Phasen", flush=True)

    phases_root = os.path.join(run_dir, "phases")
    if build_subreports:
        if os.path.isdir(phases_root):
            shutil.rmtree(phases_root, ignore_errors=True)
        os.makedirs(phases_root, exist_ok=True)

    build_report_fn = None
    if build_subreports:
        from ..reporter.html_report import build_report as _br
        build_report_fn = _br

    phase_reports: list[dict[str, Any]] = []
    for p in phases:
        entry: dict[str, Any] = {
            **phase_to_dict(p),
            "subreport_path": None,
        }
        if build_subreports:
            pdir = os.path.join(phases_root, _phase_dir_name(p))
            os.makedirs(os.path.join(pdir, "logs"), exist_ok=True)
            try:
                logger.info("building sub-report for phase %d (%.0fs-%.0fs)",
                            p.phase_id, p.start_rel, p.end_rel)
                print(f"  Phase {p.phase_id}: {int(p.start_rel):5d}s - "
                      f"{int(p.end_rel):5d}s ({int(p.duration_seconds):4d}s)...",
                      flush=True)
                analyze_run(run_dir,
                            min_rel_seconds=p.start_rel,
                            max_rel_seconds=p.end_rel,
                            output_dir=pdir)
                report_path = build_report_fn(run_dir,
                                              min_rel_seconds=p.start_rel,
                                              max_rel_seconds=p.end_rel,
                                              output_dir=pdir)
                entry["subreport_path"] = os.path.relpath(report_path, run_dir).replace("\\", "/")
            except Exception as e:
                logger.exception("sub-report failed for phase %d: %s", p.phase_id, e)
                entry["error"] = f"{type(e).__name__}: {e}"
        phase_reports.append(entry)

    phases_summary = {
        "run_dir": run_dir,
        "total_duration_seconds": round(total_duration, 2),
        "parameters": {
            "min_phase_seconds": min_phase_seconds,
            "window_seconds": window_seconds,
            "step_threshold": step_threshold,
            "slope_threshold": slope_threshold,
            "proximity_seconds": proximity_seconds,
        },
        "change_points": [change_point_to_dict(c) for c in change_points],
        "phases": phase_reports,
    }

    atomic_write_json(os.path.join(run_dir, "phases.json"), phases_summary)

    overview_path = build_overview_report(
        run_dir=run_dir,
        manifest=rd.manifest,
        system_rows=rd.system_rows,
        change_points=change_points,
        phases=phases,
        phase_reports=phase_reports,
    )
    phases_summary["overview_report"] = os.path.basename(overview_path)
    atomic_write_json(os.path.join(run_dir, "phases.json"), phases_summary)

    logger.info("split complete: %s", overview_path)
    print(f"  Uebersicht: {overview_path}", flush=True)
    return phases_summary
