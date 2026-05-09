"""Cross-run comparison orchestration."""

from __future__ import annotations

import datetime as _dt
import os
from typing import Any

from ..logging_setup import get_logger
from ..paths import build_comparison_paths
from ..reporter.json_export import atomic_write_json
from .cadence_quality import (
    annotate_rankings,
    build_asymmetry_findings,
    extract_per_run,
)
from .compare_report import build_comparison_report
from .cross_run_view import build_cross_run_view
from .diagnosis import bottleneck_comparison, generate_hypotheses, generate_recommendations
from .loader import load_run_full
from .matrix import build_matrix, write_matrix_csv
from .mode import detect_mode, mode_label
from .peer_context import build_peer_mismatch_findings, extract_machine_classes
from .static_diff import diff_autoruns, diff_config, diff_hardware, diff_software
from .window_alignment import (
    aligned_rankings,
    build_aligned_view,
    detect_aligned_window,
)


def _explain_differences(runs: list[dict[str, Any]], matrix: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    rows = matrix["rows"]
    if len(rows) < 2:
        return findings

    def _safe_delta(a: float | None, b: float | None) -> float | None:
        if a is None or b is None:
            return None
        return round(a - b, 1)

    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            a = rows[i]
            b = rows[j]
            delta_overall = _safe_delta(a["overall"], b["overall"])
            bits: list[str] = []
            if delta_overall is not None and abs(delta_overall) >= 5:
                better = a["run_id"] if delta_overall > 0 else b["run_id"]
                bits.append(f"{better} scored {abs(delta_overall):.0f} points higher overall")

            for metric, label in [
                ("cpu_avg", "average CPU"),
                ("mem_avg", "average memory"),
                ("disk_avg", "average disk active"),
                ("latency_p95_ms", "p95 latency"),
                ("anomalies", "anomaly count"),
                ("slowdowns", "slowdown windows"),
            ]:
                d = _safe_delta(a[metric], b[metric])
                if d is None:
                    continue
                if abs(d) < 3 and metric not in ("latency_p95_ms",):
                    continue
                if abs(d) < 20 and metric == "latency_p95_ms":
                    continue
                bits.append(
                    f"{label}: {a['run_id']}={a[metric]} vs {b['run_id']}={b[metric]} (Δ {d:+})"
                )
            if bits:
                findings.append({
                    "pair": [a["run_id"], b["run_id"]],
                    "observations": bits,
                })
    return findings


def _unique_and_common_problems(runs: list[dict[str, Any]]) -> dict[str, Any]:
    per_run: dict[str, set[str]] = {}
    for r in runs:
        rid = r["manifest"].get("run_id")
        tags: set[str] = set()
        for a in (r["findings"].get("anomalies") or []):
            tags.add(a.get("kind") or "?")
        for s in (r["findings"].get("slowdowns") or []):
            for t in s.get("reason_tags") or []:
                tags.add(f"slowdown_{t}")
        per_run[rid] = tags

    all_sets = list(per_run.values())
    common = set.intersection(*all_sets) if all_sets else set()
    unique: dict[str, list[str]] = {}
    for rid, tags in per_run.items():
        others = [s for r2, s in per_run.items() if r2 != rid]
        other_union = set.union(*others) if others else set()
        unique[rid] = sorted(tags - other_union)
    return {
        "common_problem_kinds": sorted(common),
        "unique_per_run": unique,
    }


def run_compare(run_dirs: list[str], output_root: str) -> str:
    logger = get_logger("comparer", None)
    logger.info("comparing %d runs", len(run_dirs))

    loaded: list[dict[str, Any]] = []
    for rd_path in run_dirs:
        rd, findings, scores = load_run_full(rd_path)
        loaded.append({
            "manifest": rd.manifest,
            "findings": findings,
            "scores": scores,
            "rd": rd,
        })

    paths = build_comparison_paths(output_root)
    logger = get_logger("comparer", os.path.join(paths.comparison_dir, "comparer.log"))

    mode = detect_mode(loaded)
    logger.info("detected comparison mode: %s", mode)

    matrix = build_matrix(loaded)
    write_matrix_csv(matrix, paths.matrix_csv)

    # v3-priority-2: cadence-quality awareness. Lift each run's
    # `manifest.cadence_quality` block (shipped in v3-priority-1) and
    # build cross-run asymmetry findings + ranking annotations. Without
    # this, an under-sampled run's mean is presented at the same visual
    # weight as a well-sampled one — exactly the v2 production-review
    # bug ("ATLT4407 vs MORGANA").
    cadence_per_run = extract_per_run(loaded)
    cadence_warnings = build_asymmetry_findings(cadence_per_run)
    cadence_rankings = annotate_rankings(matrix["rankings"], cadence_per_run)
    if cadence_warnings:
        worst = next((w for w in cadence_warnings if w.get("severity") == "high"),
                     cadence_warnings[0])
        logger.warning("cadence-quality finding: [%s] %s",
                       worst.get("kind"), worst.get("hypothesis"))

    # v3-priority-3: peer-context awareness. When two runs declare
    # different machine_class (e.g. enterprise-managed-laptop vs
    # personal-desktop), surface that as a top-of-report caveat so
    # the engine isn't comparing non-peers without acknowledgement.
    peer_classes = extract_machine_classes(loaded)
    peer_warnings = build_peer_mismatch_findings(loaded)
    if peer_warnings:
        first = peer_warnings[0]
        logger.warning("peer-context finding: [%s] %s",
                       first.get("kind"), first.get("hypothesis"))

    # v3-priority-6: cap-window alignment. ATLT4407 (902 s) vs
    # MORGANA (1469 s) gives MORGANA an intrinsic advantage on every
    # "average over time" metric. When all runs can produce a
    # canonical tail window (last_1h / last_8h via A6), prefer those
    # scores in the headline verdicts so length is no longer a free
    # variable. When no common window exists (some run too short),
    # fall back to raw rankings — the cadence-quality and
    # peer-context layers (priorities 1-3) still apply.
    aligned_window = detect_aligned_window(loaded)
    aligned_view = build_aligned_view(loaded, aligned_window)
    aligned_ranks = aligned_rankings(loaded, aligned_window)
    if aligned_window:
        logger.info(
            "cross-run aligned window: %s — using cap-window-aware scoring "
            "for headline verdicts",
            aligned_window,
        )
    else:
        # Build a finding so the report explains why headline verdicts
        # may be length-biased on this cohort.
        too_short = [
            r["run_id"] for r in aligned_view["rows"]
            if r.get("alignment_status") == "too_short"
        ]
        if len(loaded) >= 2 and too_short:
            logger.info(
                "cap-window alignment unavailable — runs too short: %s",
                ", ".join(too_short),
            )

    differences = _explain_differences(loaded, matrix)
    problems = _unique_and_common_problems(loaded)

    hw_diff = diff_hardware(loaded)
    sw_diff = diff_software(loaded)
    autoruns_diff = diff_autoruns(loaded)
    cfg_diff = diff_config(loaded)
    bottlenecks = bottleneck_comparison(matrix)
    hypotheses = generate_hypotheses(loaded, matrix, hw_diff, sw_diff, cfg_diff)
    # Cadence-quality findings + peer-context findings rank ahead of
    # everything else: if cadence is broken or peers don't match,
    # downstream hypotheses are built on shaky comparisons. Cadence is
    # listed FIRST because it gates whether the data itself is trustworthy;
    # peer-context comes second because it gates whether the comparison
    # is fair.
    hypotheses = list(cadence_warnings) + list(peer_warnings) + list(hypotheses)
    recommendations = generate_recommendations(hypotheses)

    # Field-review A5: lift the new schema fields (M5 machine_id,
    # M2 meta, A6 tail_windows, C3 baseline_deviations, C4
    # capture_profile) into the comparison output.
    cross_run_view = build_cross_run_view(loaded)
    if cross_run_view["same_machine"]:
        logger.info("cross-run: all %d runs share a machine_id (longitudinal trend)",
                    len(loaded))
    if cross_run_view["tail_window_view"]["common_window_label"]:
        logger.info(
            "cross-run: tail-window-aligned view available at %s",
            cross_run_view["tail_window_view"]["common_window_label"],
        )

    comparison_findings = {
        "mode": mode,
        "mode_label": mode_label(mode),
        "runs": [
            {
                "run_id": r["manifest"].get("run_id"),
                "hostname": r["manifest"].get("hostname"),
                "mode": r["manifest"].get("mode"),
                "tags": r["manifest"].get("tags"),
                "duration_s": r["manifest"].get("duration_actual_seconds"),
            }
            for r in loaded
        ],
        "matrix_rows": matrix["rows"],
        "rankings": matrix["rankings"],
        # v3-priority-2: cadence-quality blocks ride alongside the
        # rankings so consumers can refuse claims when the cadence is
        # heterogeneous. `cadence_quality_per_run` is the per-run
        # manifest data lifted; `cadence_quality_warnings` is the
        # cross-run asymmetry findings; `rankings_with_confidence` is
        # the rankings annotated with per-metric confidence + the list
        # of runs excluded from each ranking due to broken cadence.
        "cadence_quality_per_run": cadence_per_run,
        "cadence_quality_warnings": cadence_warnings,
        "rankings_with_confidence": cadence_rankings,
        # v3-priority-3: peer-context blocks. `peer_classes` is the
        # per-run machine_class lift; `peer_mismatch_warnings` are the
        # non-peer findings. Together they let consumers know when a
        # comparison is between machines with different workload
        # profiles (and thus when cross-run claims need a caveat).
        "peer_classes": peer_classes,
        "peer_mismatch_warnings": peer_warnings,
        # v3-priority-6: cap-window alignment. `window_aligned_view`
        # carries per-run scores at the canonical tail window so the
        # report can show length-fair comparison alongside the raw
        # full-window scores. `window_aligned_rankings` is what
        # the headline verdicts actually consume.
        "window_aligned_view": aligned_view,
        "window_aligned_rankings": aligned_ranks,
        "pairwise_observations": differences,
        "common_and_unique_problems": problems,
        "static_diff": {
            "hardware": hw_diff,
            "software": sw_diff,
            "autoruns": autoruns_diff,
            "config": cfg_diff,
        },
        "bottleneck_comparison": bottlenecks,
        "cross_run_view": cross_run_view,
        "root_causes": hypotheses,
        "recommendations": recommendations,
    }

    atomic_write_json(paths.findings, comparison_findings)

    # v3-priority-6 + priority-2: headline verdicts.
    # Order of preference for "best_*" / "most_stable" / "best_efficiency":
    #   1. Aligned-window ranking (priority 6) — length-fair.
    #   2. Cadence-annotated raw ranking (priority 2) — excludes
    #      broken-cadence runs from sample-density-sensitive metrics.
    # This is what stops ATLT4407 from winning "best efficiency"
    # purely because its 902 s run integrated over a shorter window
    # than MORGANA's 1469 s.
    def _top_aligned(name: str) -> str | None:
        ordered = aligned_ranks.get(name) or []
        return ordered[0][0] if ordered else None

    def _top_cadence(name: str) -> str | None:
        annotated = cadence_rankings.get(name) or {}
        ordered = annotated.get("ordered") or []
        return ordered[0][0] if ordered else None

    def _top(name: str) -> str | None:
        return _top_aligned(name) or _top_cadence(name)

    comparison_scores = {
        "best_overall": _top("best_overall"),
        "most_stable": _top("best_stability"),
        "best_efficiency": _top("best_efficiency"),
        "lowest_cpu_avg": _top_cadence("lowest_cpu_avg"),
        "lowest_latency_p95": _top_cadence("lowest_latency_p95"),
        "fewest_anomalies": _top_cadence("fewest_anomalies"),
        # Surface which window the score-based verdicts were chosen on
        # so consumers don't have to guess.
        "chosen_window": aligned_window or "full_run",
    }
    atomic_write_json(paths.scores, comparison_scores)

    atomic_write_json(paths.manifest, {
        "comparison_id": paths.comparison_id,
        "started_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "input_runs": run_dirs,
        "mode": mode,
    })

    build_comparison_report(
        paths, loaded, matrix, differences, problems, comparison_scores,
        mode=mode,
        hw_diff=hw_diff,
        sw_diff=sw_diff,
        autoruns_diff=autoruns_diff,
        cfg_diff=cfg_diff,
        bottlenecks=bottlenecks,
        hypotheses=hypotheses,
        recommendations=recommendations,
        cross_run_view=cross_run_view,
        cadence_per_run=cadence_per_run,
        cadence_warnings=cadence_warnings,
        rankings_with_confidence=cadence_rankings,
        peer_classes=peer_classes,
        peer_warnings=peer_warnings,
        aligned_view=aligned_view,
        aligned_window=aligned_window,
    )
    logger.info("comparison complete: %s", paths.comparison_dir)
    return paths.comparison_dir
