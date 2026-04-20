"""End-to-end analyzer pipeline: load run -> detect -> write findings.json + scores.json."""

from __future__ import annotations

import os
from typing import Any

from ..config import Thresholds
from ..logging_setup import get_logger
from ..reporter.json_export import atomic_write_json
from .anomalies import detect_anomalies
from .bottlenecks import classify_bottlenecks
from .leaks import detect_leak_patterns
from .loader import load_run
from .offenders import rank_offenders, process_churn_stats
from .scores import calculate_scores
from .slowdowns import detect_slowdown_windows


def analyze_run(run_dir: str) -> dict[str, Any]:
    logger = get_logger("analyzer", os.path.join(run_dir, "logs", "analyzer.log"))
    logger.info("loading run %s", run_dir)
    rd = load_run(run_dir)

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
    leaks = detect_leak_patterns(rd.process_rows, th)

    logger.info("ranking offenders")
    offenders = rank_offenders(rd.process_rows, top_n=10)
    churn = process_churn_stats(rd.process_events)

    logger.info("classifying bottlenecks")
    bottlenecks = classify_bottlenecks(rd.system_rows, anomalies, rd.latency_rows, slowdowns)

    logger.info("calculating scores")
    mode = (rd.manifest or {}).get("mode") or "support"
    scores = calculate_scores(
        rd.system_rows, anomalies, slowdowns, offenders, leaks, rd.latency_rows, mode, bottlenecks
    )

    findings = {
        "anomalies": anomalies,
        "slowdowns": slowdowns,
        "leaks": leaks,
        "offenders": offenders,
        "process_churn": churn,
        "bottlenecks": bottlenecks,
        "summary": _summarize(anomalies, slowdowns, leaks, bottlenecks, scores),
    }

    atomic_write_json(os.path.join(run_dir, "findings.json"), findings)
    atomic_write_json(os.path.join(run_dir, "scores.json"), scores)
    logger.info("wrote findings.json and scores.json")
    return {"findings": findings, "scores": scores}


def _summarize(
    anomalies: list[dict[str, Any]],
    slowdowns: list[dict[str, Any]],
    leaks: dict[str, list[dict[str, Any]]],
    bottlenecks: dict[str, Any],
    scores: dict[str, Any],
) -> dict[str, Any]:
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
    verdict_parts.append(f"Overall score {scores['overall']:.0f}/100 ({scores['confidence']} confidence).")

    return {
        "verdict": " ".join(verdict_parts),
        "total_anomalies": len(anomalies),
        "total_slowdown_windows": len(slowdowns),
        "total_leak_candidates": total_leaks,
        "primary_bottleneck": primary,
    }
