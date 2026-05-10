"""End-to-end analyzer pipeline: load run -> detect -> write findings.json + scores.json."""

from __future__ import annotations

import json
import os
from typing import Any

from ..config import Thresholds
from ..logging_setup import get_logger
from ..reporter.json_export import atomic_write_json
from .anomalies import detect_anomalies
from .bottlenecks import classify_bottlenecks
from .event_correlation import correlate_events
from .gpu_analysis import analyze_gpu
from .grouping import rank_apps
from .latency_analysis import analyze_latency
from .leaks import detect_leak_patterns
from .loader import load_run
from .network_attribution import attribute_connections
from .offenders import process_churn_stats, rank_offenders
from .scores import calculate_scores
from .slowdowns import detect_slowdown_windows


def _compute_analysis_window(
    run_dir: str,
    rd_manifest: dict[str, Any],
    system_rows: list[dict[str, Any]],
    min_rel_seconds: float | None,
    max_rel_seconds: float | None,
) -> dict[str, Any]:
    """Resolve the three-way duration ambiguity (manifest vs CSV vs trim).

    Field-review B1: scores.json reported 39 samples / 800 s while the CSV
    held 344 / 7998 s and the manifest claimed 49309 s — three numbers,
    no single source of truth. This block makes the choice explicit.

    Returns a dict that is stamped into BOTH findings.json and scores.json
    so every downstream consumer (HTML report, comparison, splitter)
    reads the same window definition.
    """
    # Re-read the on-disk manifest separately, because load_run() rewrites
    # rd.manifest in-memory when --trim-seconds is in effect. We want the
    # original recorded run length here, not the post-trim view.
    on_disk_manifest: dict[str, Any] = {}
    manifest_path = os.path.join(run_dir, "manifest.json")
    try:
        with open(manifest_path, encoding="utf-8") as f:
            on_disk_manifest = json.load(f)
    except (OSError, json.JSONDecodeError):
        on_disk_manifest = {}

    full_run_seconds = on_disk_manifest.get("duration_actual_seconds")
    requested_duration = on_disk_manifest.get("duration_requested_seconds")

    # Actual data range = the smallest and largest rel_seconds we loaded.
    # This is the ONLY source of truth for "what was analyzed".
    if system_rows:
        try:
            actual_lo = min(float(r.get("rel_seconds") or 0.0) for r in system_rows)
            actual_hi = max(float(r.get("rel_seconds") or 0.0) for r in system_rows)
        except (TypeError, ValueError):
            actual_lo = 0.0
            actual_hi = 0.0
    else:
        actual_lo = 0.0
        actual_hi = 0.0

    trimmed = (min_rel_seconds is not None) or (max_rel_seconds is not None)
    requested_lo = float(min_rel_seconds) if min_rel_seconds is not None else 0.0
    requested_hi: float | None
    if max_rel_seconds is not None:
        requested_hi = float(max_rel_seconds)
    elif full_run_seconds is not None:
        requested_hi = float(full_run_seconds)
    else:
        requested_hi = None

    return {
        # The window the analyzer actually ran on (smallest source of truth).
        "window_start_seconds": round(actual_lo, 2),
        "window_end_seconds": round(actual_hi, 2),
        "window_duration_seconds": round(actual_hi - actual_lo, 2),
        "samples_analyzed": len(system_rows),
        # The window the caller asked for (e.g. via --trim-seconds).
        "requested_window_start_seconds": round(requested_lo, 2),
        "requested_window_end_seconds": (
            round(requested_hi, 2) if requested_hi is not None else None
        ),
        # The full original run, untouched by trim.
        "full_run_duration_seconds": (
            round(float(full_run_seconds), 2) if full_run_seconds is not None else None
        ),
        "full_run_requested_duration_seconds": (
            int(requested_duration) if requested_duration is not None else None
        ),
        "trimmed": trimmed,
        "stop_reason": on_disk_manifest.get("stop_reason"),
    }


def analyze_run(
    run_dir: str,
    max_rel_seconds: float | None = None,
    min_rel_seconds: float | None = None,
    output_dir: str | None = None,
) -> dict[str, Any]:
    out_dir = output_dir or run_dir
    logger = get_logger("analyzer", os.path.join(out_dir, "logs", "analyzer.log"))
    if min_rel_seconds is not None or max_rel_seconds is not None:
        lo = min_rel_seconds if min_rel_seconds is not None else 0.0
        hi = max_rel_seconds if max_rel_seconds is not None else float("inf")
        logger.info("loading run %s (window %.0fs-%.0fs)", run_dir, lo, hi)
    else:
        logger.info("loading run %s", run_dir)
    rd = load_run(run_dir, max_rel_seconds=max_rel_seconds, min_rel_seconds=min_rel_seconds)

    # Resolve the three-way duration ambiguity once, share with all
    # downstream artefacts. See _compute_analysis_window for details.
    analysis_window = _compute_analysis_window(
        run_dir, rd.manifest, rd.system_rows,
        min_rel_seconds=min_rel_seconds, max_rel_seconds=max_rel_seconds,
    )
    logger.info(
        "analysis window: %.0fs..%.0fs (%d samples; full run=%s)",
        analysis_window["window_start_seconds"],
        analysis_window["window_end_seconds"],
        analysis_window["samples_analyzed"],
        analysis_window["full_run_duration_seconds"],
    )

    # Sparse-data guard: very short runs have no statistical signal and can
    # trip the scoring functions. Emit a minimal findings/scores set and return.
    if len(rd.system_rows) < 30:
        logger.warning(
            "only %d system samples — skipping deep analysis (need >=30 for confidence)",
            len(rd.system_rows),
        )
        findings = {
            "anomalies": [],
            "slowdowns": [],
            "leaks": {"memory": [], "handles": [], "threads": []},
            "handle_leaks_by_type": {
                "samples_seen": 0,
                "per_type_findings": [],
                "rcw_signature_candidates": [],
            },
            "managed_heap_leaks": {
                "samples_seen": 0,
                "managed_leaks": [],
                "native_only_leaks": [],
            },
            "deadlocks": [],
            "process_tree": {
                "by_parent": [], "spawn_counts": {}, "exit_counts": {},
                "total_pids_seen": 0, "total_pairs_seen": 0,
            },
            "periodicities": {
                "system": [], "per_process": [],
                "method": "autocorrelation",
                "bin_seconds": 5.0,
                "min_period_seconds": 30.0,
                "max_period_seconds": 1800.0,
            },
            "baseline_deviations": [],
            "offenders": {},
            "apps": {},
            "network_attribution": {"by_app": [], "by_pid": [], "samples": 0},
            "latency_analysis": {"targets": [], "samples": 0},
            "gpu_analysis": {"enabled": False},
            "event_correlation": {"enabled": False},
            "etw_disk": {"enabled": False},
            "process_churn": {"total_process_starts": 0},
            "bottlenecks": {"primary": None, "secondary_bottlenecks": [], "scores": {}, "reasons": {}},
            "summary": {
                "verdict": (
                    f"Not enough samples for a confident verdict "
                    f"({len(rd.system_rows)} system rows; need at least 30)."
                ),
                "total_anomalies": 0,
                "total_slowdown_windows": 0,
                "total_leak_candidates": 0,
                "total_deadlocks": 0,
                "primary_bottleneck": None,
                "insufficient_data": True,
            },
        }
        scores = {
            "overall": None, "stability": None, "efficiency": None,
            "workload_suitability": None, "security_overhead": None,
            "network_impact": None, "resource_hygiene": None,
            "confidence": "low",
            "sample_count": len(rd.system_rows),
            "weights": {},
            "primary_bottleneck": None,
            "secondary_bottlenecks": [],
            "analysis_window": analysis_window,
        }
        findings["analysis_window"] = analysis_window
        os.makedirs(out_dir, exist_ok=True)
        atomic_write_json(os.path.join(out_dir, "findings.json"), findings)
        atomic_write_json(os.path.join(out_dir, "scores.json"), scores)
        return {"findings": findings, "scores": scores}

    thresholds_data = (rd.manifest or {}).get("thresholds") or {}
    valid_fields = set(Thresholds().__dict__.keys())
    filtered = {k: v for k, v in thresholds_data.items() if k in valid_fields}
    th = Thresholds(**filtered)

    logger.info("detecting anomalies across %d system rows, %d latency rows",
                len(rd.system_rows), len(rd.latency_rows))
    anomalies = detect_anomalies(rd.system_rows, rd.latency_rows, th)

    logger.info("detecting slowdown windows")
    slowdowns = detect_slowdown_windows(rd.system_rows, rd.process_rows, rd.latency_rows, th)

    logger.info("detecting leak patterns")
    # v1.3.3: pass cadence_health so the leak detector can run a
    # permissive fallback on broken-cadence runs (where the main
    # detector goes silent because too few samples per sliding window).
    cadence_health = None
    cq = rd.manifest.get("cadence_quality") if isinstance(rd.manifest, dict) else None
    if isinstance(cq, dict):
        cadence_health = cq.get("cadence_health")
    if cadence_health is None and isinstance(rd.manifest, dict):
        cadence_health = rd.manifest.get("cadence_health")
    leaks = detect_leak_patterns(
        rd.process_rows, th, cadence_health=cadence_health,
    )

    # Field-review A2: deadlock-after-leak signature.
    logger.info("detecting deadlock-suspected processes")
    from .deadlocks import detect_deadlocks
    deadlocks = detect_deadlocks(rd.process_rows, th)

    # Field-review A4: parent → child aggregation so the report can
    # show "X spawned 15 children of name Y" without the operator
    # cross-referencing process_events.json by hand.
    logger.info("building process tree")
    from .process_tree import build_process_tree
    process_tree = build_process_tree(rd.process_rows, rd.process_events)

    # Field-review A3: detect periodic patterns (Defender scans, EDR
    # heartbeats, scheduled tasks). Autocorrelation on 5-second bins.
    logger.info("detecting periodic patterns")
    from .periodicity import detect_periodicities
    periodicities = detect_periodicities(rd.system_rows, rd.process_rows)

    # v3-priority-4 (H1): per-(pid, type) handle-leak analyzer.
    # Empty when the run pre-dates v3-priority-4 (no handles_rows).
    logger.info("detecting per-type handle leaks")
    from .handle_types import detect_handle_type_leaks
    handle_type_leaks = detect_handle_type_leaks(
        getattr(rd, "handles_rows", None) or [],
    )

    # v3-priority-5 (H2): managed-heap leak detection + native/managed
    # diff. Distinguishes a .NET retained-roots bug ("gen2 grows") from
    # an unmanaged C/C++/COM leak ("RSS grows but managed heap flat").
    # Empty when the run pre-dates v3-priority-5 or no .NET app ran.
    logger.info("detecting managed-heap leaks")
    from .managed_heap import detect_managed_heap_leaks
    managed_heap_leaks = detect_managed_heap_leaks(
        getattr(rd, "managed_heap_rows", None) or [],
        rd.process_rows,
    )

    # Field-review C3: machine-class baseline deviations. Reads the
    # machine class from manifest.meta (set via --machine-class or a
    # capture profile's suggested_meta) and flags metrics that fall
    # outside their expected band for the class.
    machine_class = (rd.manifest or {}).get("meta", {}).get("machine_class")
    if machine_class:
        logger.info("checking baselines for machine class %r", machine_class)
        from .machine_class_baselines import detect_baseline_deviations
        baseline_deviations = detect_baseline_deviations(
            rd.system_rows, machine_class,
        )
    else:
        baseline_deviations = []

    logger.info("ranking offenders")
    offenders = rank_offenders(rd.process_rows, top_n=10)
    apps = rank_apps(rd.process_rows, top_n=10)
    churn = process_churn_stats(rd.process_events)

    logger.info("attributing network connections")
    network_attribution = attribute_connections(rd.connection_rows, top_n=10)

    logger.info("analyzing latency / DNS")
    latency_analysis = analyze_latency(rd.latency_rows)

    # Phase 3 optional analyses — keyed off manifest.phase3 + presence of data
    phase3_cfg = (rd.manifest or {}).get("phase3") or {}
    gpu_analysis: dict[str, Any] = {"enabled": False}
    if phase3_cfg.get("gpu") or rd.gpu_engine_rows or rd.gpu_process_rows:
        logger.info("analyzing GPU metrics")
        pid_name_map: dict[int, str] = {}
        for pr in rd.process_rows:
            try:
                pid = int(pr.get("pid") or 0)
            except (TypeError, ValueError):
                pid = 0
            if pid > 0:
                pid_name_map.setdefault(pid, pr.get("name") or "?")
        gpu_analysis = analyze_gpu(
            rd.gpu_engine_rows, rd.gpu_process_rows, rd.gpu_adapter_rows, pid_name_map,
        )

    event_correlation: dict[str, Any] = {"enabled": False}
    if phase3_cfg.get("event_logs") or rd.event_log:
        logger.info("correlating event logs to slowdowns")
        event_correlation = correlate_events(rd.event_log, slowdowns)

    etw_disk = rd.etw_disk or {"enabled": False}

    logger.info("classifying bottlenecks")
    bottlenecks = classify_bottlenecks(rd.system_rows, anomalies, rd.latency_rows, slowdowns)

    logger.info("calculating scores")
    mode = (rd.manifest or {}).get("mode") or "support"
    scores = calculate_scores(
        rd.system_rows, anomalies, slowdowns, offenders, leaks, rd.latency_rows, mode, bottlenecks
    )

    # Field-review A6: cap-window-aware scoring. Re-score over
    # canonical tail windows (last 1 h, last 8 h) so this run is
    # comparable to runs of any other length on the same fleet.
    from .scores import compute_tail_window_scores
    tail_scores = compute_tail_window_scores(
        rd.system_rows, anomalies, slowdowns, offenders, leaks,
        rd.latency_rows, mode, bottlenecks,
        full_window_start=analysis_window["window_start_seconds"],
        full_window_end=analysis_window["window_end_seconds"],
    )
    if tail_scores:
        scores["tail_windows"] = tail_scores
        logger.info(
            "tail-window scoring: produced %d additional view(s) (%s)",
            len(tail_scores),
            ", ".join(s["window_label"] for s in tail_scores),
        )

    # Stamp the resolved analysis window onto BOTH artefacts so any
    # consumer (HTML report, comparison, splitter, downstream tooling)
    # has a single source of truth. Field-review B1.
    scores["analysis_window"] = analysis_window

    findings = {
        "anomalies": anomalies,
        "slowdowns": slowdowns,
        "leaks": leaks,
        # v3-priority-4 (H1): per-(pid, type) handle leaks. Empty
        # containers when the run pre-dates the H1 sampler.
        "handle_leaks_by_type": handle_type_leaks,
        # v3-priority-5 (H2): managed-heap leaks + native/managed
        # attribution. Empty containers when no .NET data captured.
        "managed_heap_leaks": managed_heap_leaks,
        "deadlocks": deadlocks,
        "process_tree": process_tree,
        "periodicities": periodicities,
        "baseline_deviations": baseline_deviations,
        "offenders": offenders,
        "apps": apps,
        "network_attribution": network_attribution,
        "latency_analysis": latency_analysis,
        "gpu_analysis": gpu_analysis,
        "event_correlation": event_correlation,
        "etw_disk": etw_disk,
        "process_churn": churn,
        "bottlenecks": bottlenecks,
        "summary": _summarize(anomalies, slowdowns, leaks, bottlenecks, scores,
                              deadlocks=deadlocks),
        "analysis_window": analysis_window,
    }

    os.makedirs(out_dir, exist_ok=True)
    atomic_write_json(os.path.join(out_dir, "findings.json"), findings)
    atomic_write_json(os.path.join(out_dir, "scores.json"), scores)
    logger.info("wrote findings.json and scores.json")
    return {"findings": findings, "scores": scores}


def _summarize(
    anomalies: list[dict[str, Any]],
    slowdowns: list[dict[str, Any]],
    leaks: dict[str, list[dict[str, Any]]],
    bottlenecks: dict[str, Any],
    scores: dict[str, Any],
    deadlocks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    deadlocks = deadlocks or []
    verdict_parts: list[str] = []
    primary = bottlenecks.get("primary")
    if primary:
        verdict_parts.append(f"Primary bottleneck: {primary}.")
    else:
        verdict_parts.append("No dominant bottleneck detected.")
    if slowdowns:
        verdict_parts.append(f"{len(slowdowns)} slowdown window(s) identified.")
    severe_anom = [a for a in anomalies if a.get("severity") == "high"]
    if severe_anom:
        verdict_parts.append(f"{len(severe_anom)} high-severity anomaly/anomalies.")
    total_leaks = sum(len(v) for v in leaks.values())
    if total_leaks:
        verdict_parts.append(f"{total_leaks} resource-leak candidate(s).")
    if deadlocks:
        # Field-review A2: deadlock signature is the highest-priority
        # signal for a leaking-then-stuck workload — surface it loudly.
        verdict_parts.append(
            f"{len(deadlocks)} deadlock-suspected process(es) "
            "(growth followed by CPU drop)."
        )
    verdict_parts.append(f"Overall score {scores['overall']:.0f}/100 ({scores['confidence']} confidence).")

    return {
        "verdict": " ".join(verdict_parts),
        "total_anomalies": len(anomalies),
        "total_slowdown_windows": len(slowdowns),
        "total_leak_candidates": total_leaks,
        "total_deadlocks": len(deadlocks),
        "primary_bottleneck": primary,
    }
