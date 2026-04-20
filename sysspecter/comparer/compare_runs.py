"""Cross-run comparison orchestration."""

from __future__ import annotations

import datetime as _dt
import os
from typing import Any

from ..logging_setup import get_logger
from ..paths import build_comparison_paths
from ..reporter.json_export import atomic_write_json
from .compare_report import build_comparison_report
from .loader import load_run_full
from .matrix import build_matrix, write_matrix_csv


def _explain_differences(runs: list[dict[str, Any]], matrix: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    rows = matrix["rows"]
    if len(rows) < 2:
        return findings

    rows_by_id = {r["run_id"]: r for r in rows}

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

    matrix = build_matrix(loaded)
    write_matrix_csv(matrix, paths.matrix_csv)

    differences = _explain_differences(loaded, matrix)
    problems = _unique_and_common_problems(loaded)

    comparison_findings = {
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
        "pairwise_observations": differences,
        "common_and_unique_problems": problems,
    }

    atomic_write_json(paths.findings, comparison_findings)

    comparison_scores = {
        "best_overall": (matrix["rankings"].get("best_overall") or [[None, None]])[0][0],
        "most_stable": (matrix["rankings"].get("best_stability") or [[None, None]])[0][0],
        "best_efficiency": (matrix["rankings"].get("best_efficiency") or [[None, None]])[0][0],
        "lowest_cpu_avg": (matrix["rankings"].get("lowest_cpu_avg") or [[None, None]])[0][0],
        "lowest_latency_p95": (matrix["rankings"].get("lowest_latency_p95") or [[None, None]])[0][0],
        "fewest_anomalies": (matrix["rankings"].get("fewest_anomalies") or [[None, None]])[0][0],
    }
    atomic_write_json(paths.scores, comparison_scores)

    atomic_write_json(paths.manifest, {
        "comparison_id": paths.comparison_id,
        "started_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "input_runs": run_dirs,
    })

    build_comparison_report(paths, loaded, matrix, differences, problems, comparison_scores)
    logger.info("comparison complete: %s", paths.comparison_dir)
    return paths.comparison_dir
