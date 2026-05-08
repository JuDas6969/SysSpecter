"""Cross-run cadence-quality awareness (v3-priority-2).

The v2 production-test review found the comparison engine's biggest
practical bug: ATLT4407 (median sample gap 18 s, manifest claimed 1 s)
was matched up against MORGANA (median 1.1 s) on `cpu_avg`, `mem_avg`,
`latency_p95_ms` etc. without any acknowledgement that one side's mean
was averaged over 55 samples and the other's over 504. Every
"ATLT4407 vs anything" comparison silently misled.

v3-priority-1 (S1+S3) shipped the per-run `manifest.cadence_quality`
block. This module is what consumes it on the comparison side:

1. `extract_per_run(loaded)` — pulls the cadence_quality block from
   each run's manifest, with a back-compat fallback for runs that
   pre-date the field.
2. `classify_metric(name)` — returns "sample_density_sensitive" /
   "event_count" / "static" so the engine knows which columns are
   apples-to-undersampled-apples when cadence asymmetry exists.
3. `build_asymmetry_findings(per_run)` — returns one or more findings
   describing cross-run cadence heterogeneity (and which metrics it
   contaminates).
4. `confidence_for_metric(metric, per_run)` — for a given metric and
   the worst-cadence run involved, returns "trusted" / "degraded" /
   "untrusted" so the report can render a per-cell confidence marker.

The point is conservatism: when in doubt, surface the doubt. Refuse
strong claims (a `best_*` ranking) when any of the participants has
broken cadence on a sample-density-sensitive metric.
"""

from __future__ import annotations

from typing import Any

# A run with median_gap > 1.5× nominal is "degraded"; > 3× is "broken".
# Mirrors the runner's _summarise_cadence thresholds so reasoning is
# consistent on both sides of the system.
HEALTH_GOOD = "good"
HEALTH_DEGRADED = "degraded"
HEALTH_BROKEN = "broken"
HEALTH_NO_DATA = "no_data"
HEALTH_UNKNOWN = "unknown"  # for runs predating cadence_quality

_HEALTH_ORDER: dict[str, int] = {
    HEALTH_GOOD: 0,
    HEALTH_DEGRADED: 1,
    HEALTH_BROKEN: 2,
    HEALTH_NO_DATA: 3,
    HEALTH_UNKNOWN: 1,  # treat "unknown" no worse than "degraded" for back-compat
}


# Metrics whose value depends on the sample distribution. If the
# sampler dropped 9 of every 10 ticks, the *mean* is computed over
# the surviving 1, biasing toward whatever was happening in those
# brief windows. Comparing such a mean to a well-sampled run's mean
# is a textbook apples-to-oranges. Event counts (anomalies, leaks)
# are not affected — they're triggered by qualitative patterns the
# detectors find regardless of cadence. Static facts (RAM, CPU model)
# are obviously immune.
_SAMPLE_DENSITY_SENSITIVE: frozenset[str] = frozenset({
    "cpu_avg", "cpu_p95",
    "mem_avg",
    "disk_avg",
    "latency_p95_ms",
    "stability",  # stability score is built from per-sample variance
    "efficiency",  # efficiency is mean-based
    "workload",   # workload-suitability is mean-based
})

_EVENT_COUNT: frozenset[str] = frozenset({
    "anomalies", "slowdowns",
    "memory_leaks", "handle_leaks",
    "process_starts",
    "security",  # score derived from event-class counts
    "network",
    "hygiene",
    "overall",  # composite — partly cadence-sensitive but downgrading it confuses readers
})

_STATIC: frozenset[str] = frozenset({
    "run_id", "hostname", "mode", "tags",
    "cpu_model", "ram_gb", "primary_disk_tier",
    "duration_s", "samples", "primary",
})


def classify_metric(name: str) -> str:
    """Return one of "sample_density_sensitive" / "event_count" / "static" / "unknown"."""
    if name in _SAMPLE_DENSITY_SENSITIVE:
        return "sample_density_sensitive"
    if name in _EVENT_COUNT:
        return "event_count"
    if name in _STATIC:
        return "static"
    return "unknown"


def extract_per_run(loaded: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Lift `manifest.cadence_quality` into a flat per-run summary.

    Each entry shape:
        {
            "run_id": str,
            "hostname": str | None,
            "nominal_interval_seconds": float | None,
            "median_gap_seconds": float | None,
            "p95_gap_seconds": float | None,
            "max_gap_seconds": float | None,
            "samples_total": int | None,
            "cadence_health": "good" / "degraded" / "broken" / "no_data" / "unknown",
            "ratio_median_to_nominal": float | None,
            "process_priority_class": str | None,
            "back_compat": bool,  # True when the manifest predates v3-priority-1
        }

    Runs that pre-date the v3-priority-1 cadence block are surfaced
    with `cadence_health="unknown"` and `back_compat=True`. Downstream
    code treats "unknown" conservatively — the same code path that
    handles "degraded" — so back-compat doesn't silently dilute trust.
    """
    out: list[dict[str, Any]] = []
    for r in loaded:
        m = (r.get("manifest") or {})
        cq = m.get("cadence_quality")
        run_id = m.get("run_id")
        hostname = m.get("hostname")
        if not isinstance(cq, dict):
            out.append({
                "run_id": run_id,
                "hostname": hostname,
                "nominal_interval_seconds": m.get("interval_seconds"),
                "median_gap_seconds": None,
                "p95_gap_seconds": None,
                "max_gap_seconds": None,
                "samples_total": None,
                "cadence_health": HEALTH_UNKNOWN,
                "ratio_median_to_nominal": None,
                "process_priority_class": m.get("process_priority_class"),
                "back_compat": True,
            })
            continue
        out.append({
            "run_id": run_id,
            "hostname": hostname,
            "nominal_interval_seconds": cq.get("nominal_interval_seconds"),
            "median_gap_seconds": cq.get("median_gap_seconds"),
            "p95_gap_seconds": cq.get("p95_gap_seconds"),
            "max_gap_seconds": cq.get("max_gap_seconds"),
            "samples_total": cq.get("samples_total"),
            "cadence_health": cq.get("cadence_health") or HEALTH_UNKNOWN,
            "ratio_median_to_nominal": cq.get("ratio_median_to_nominal"),
            "process_priority_class": m.get("process_priority_class"),
            "back_compat": False,
        })
    return out


def worst_health(per_run: list[dict[str, Any]]) -> str:
    """Return the worst cadence_health across all participating runs."""
    if not per_run:
        return HEALTH_UNKNOWN
    return max(
        (p.get("cadence_health") or HEALTH_UNKNOWN for p in per_run),
        key=lambda h: _HEALTH_ORDER.get(h, 0),
    )


def confidence_for_metric(metric: str, per_run: list[dict[str, Any]]) -> str:
    """Per-metric confidence verdict based on the worst participant.

    Returns "trusted" / "degraded" / "untrusted":
      - trusted: all participants are good (or the metric is event-count/static)
      - degraded: any participant is degraded/unknown on a sensitive metric
      - untrusted: any participant is broken/no_data on a sensitive metric
    """
    kind = classify_metric(metric)
    if kind != "sample_density_sensitive":
        # Event counts and static facts are unaffected by cadence.
        return "trusted"
    worst = worst_health(per_run)
    if worst == HEALTH_GOOD:
        return "trusted"
    if worst in (HEALTH_BROKEN, HEALTH_NO_DATA):
        return "untrusted"
    # degraded or unknown
    return "degraded"


def cadence_ratio(a: dict[str, Any], b: dict[str, Any]) -> float | None:
    """Return median-gap ratio worse/better between two runs (always >= 1.0)."""
    ma = a.get("median_gap_seconds")
    mb = b.get("median_gap_seconds")
    try:
        ma_f = float(ma) if ma is not None else None
        mb_f = float(mb) if mb is not None else None
    except (TypeError, ValueError):
        return None
    if not ma_f or not mb_f:
        return None
    if ma_f <= 0 or mb_f <= 0:
        return None
    if ma_f >= mb_f:
        return round(ma_f / mb_f, 2)
    return round(mb_f / ma_f, 2)


def build_asymmetry_findings(per_run: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build one or more findings describing cross-run cadence heterogeneity.

    Three patterns we surface:

    1. **Any broken-cadence run.** Top-priority warning: the per-run
       cadence is so degraded that any sample-density-sensitive metric
       on this run is misleading.
    2. **Mixed-health comparison.** When some participants are good
       and others are degraded/broken, every cadence-sensitive
       cross-run claim is suspect.
    3. **Pairwise gap-ratio > 2×.** Even if both sides are nominally
       "good," a 2.5× ratio means one had ~2.5× more samples to
       average over. The downstream verdict should reflect that.

    Returns an empty list when all runs are healthy (good) and gap
    ratios are within 2×. Each finding has the standard shape used
    elsewhere in comparison_findings.json so the report renderer
    doesn't need a bespoke template.
    """
    findings: list[dict[str, Any]] = []
    if len(per_run) < 1:
        return findings

    sensitive_list = sorted(_SAMPLE_DENSITY_SENSITIVE)

    # Pattern 1: any broken-cadence run.
    broken_runs = [p for p in per_run if p.get("cadence_health") == HEALTH_BROKEN]
    for p in broken_runs:
        median = p.get("median_gap_seconds")
        nominal = p.get("nominal_interval_seconds")
        ratio = p.get("ratio_median_to_nominal")
        evidence = [
            f"{p.get('run_id')} median sample gap: "
            f"{median:.1f}s vs nominal {nominal:.1f}s (ratio {ratio:.1f}×)"
            if median is not None and nominal is not None and ratio is not None
            else f"{p.get('run_id')} cadence_quality.cadence_health = broken",
            f"samples_total: {p.get('samples_total')}",
            f"gaps over 5× nominal: {p.get('p95_gap_seconds')} (p95)",
        ]
        findings.append({
            "severity": "high",
            "category": "cadence_quality",
            "kind": "broken_cadence_in_participant",
            "run_id": p.get("run_id"),
            "hypothesis": (
                f"{p.get('run_id')} sampled at <1/3 of its nominal cadence. "
                f"Means / percentiles on this run are biased; cross-run claims "
                f"involving this run on sample-density-sensitive metrics are "
                f"not reliable."
            ),
            "evidence": evidence,
            "recommendation": (
                "Re-capture on this host with a longer interval (e.g. "
                "--interval 5) so the sampler can keep up; or accept "
                "back-pressure markers and limit comparisons to "
                "event-count metrics (anomalies, leaks)."
            ),
            "affected_metrics": sensitive_list,
        })

    # Pattern 2: mixed-health comparison (only if 2+ runs).
    if len(per_run) >= 2:
        healths = {p.get("cadence_health") for p in per_run}
        # A "mixed" comparison is one with at least one good and at
        # least one not-good. The broken case is already covered above
        # with a separate, sharper finding; mixed is the in-between.
        not_good = healths - {HEALTH_GOOD}
        if HEALTH_GOOD in healths and not_good and not_good != {HEALTH_BROKEN}:
            ranked = sorted(per_run, key=lambda p: _HEALTH_ORDER.get(
                p.get("cadence_health") or HEALTH_UNKNOWN, 0))
            best = ranked[0]
            worst = ranked[-1]
            findings.append({
                "severity": "medium",
                "category": "cadence_quality",
                "kind": "mixed_cadence_health",
                "run_id": worst.get("run_id"),
                "peer_id": best.get("run_id"),
                "hypothesis": (
                    f"This comparison mixes runs of different cadence quality "
                    f"({sorted(healths)}). Sample-density-sensitive metrics "
                    f"may be biased toward the better-sampled side."
                ),
                "evidence": [
                    f"{p.get('run_id')}: health={p.get('cadence_health')}, "
                    f"median_gap={p.get('median_gap_seconds')}s, "
                    f"samples={p.get('samples_total')}"
                    for p in per_run
                ],
                "recommendation": (
                    "Restrict cross-run claims on cpu_avg / mem_avg / "
                    "latency_p95 to event-count framing (e.g. count of "
                    "anomalies) when cadence is heterogeneous, or down-weight "
                    "the lower-cadence side."
                ),
                "affected_metrics": sensitive_list,
            })

    # Pattern 3: pairwise gap-ratio > 2× even when both sides are "good".
    # Use the worst pair only — multiple findings of the same pattern
    # would be noise.
    worst_ratio = 1.0
    worst_pair: tuple[dict[str, Any], dict[str, Any]] | None = None
    for i, a in enumerate(per_run):
        for b in per_run[i + 1:]:
            if a.get("median_gap_seconds") is None or b.get("median_gap_seconds") is None:
                continue
            r = cadence_ratio(a, b)
            if r is not None and r > worst_ratio:
                worst_ratio = r
                worst_pair = (a, b)
    if worst_pair is not None and worst_ratio >= 2.0:
        a, b = worst_pair
        # Skip if pattern 1 or 2 already covered this asymmetry to
        # avoid double-warning. Pattern 1 fires per broken run;
        # pattern 2 fires on mixed-health. If both sides are "good"
        # we still want this finding because patterns 1 and 2 stay
        # silent.
        already_covered = (
            a.get("cadence_health") in (HEALTH_BROKEN, HEALTH_NO_DATA)
            or b.get("cadence_health") in (HEALTH_BROKEN, HEALTH_NO_DATA)
            or (a.get("cadence_health") != b.get("cadence_health")
                and HEALTH_GOOD in {a.get("cadence_health"), b.get("cadence_health")})
        )
        if not already_covered:
            findings.append({
                "severity": "medium",
                "category": "cadence_quality",
                "kind": "pairwise_gap_ratio",
                "run_id": (
                    a.get("run_id") if (a.get("median_gap_seconds") or 0)
                    >= (b.get("median_gap_seconds") or 0)
                    else b.get("run_id")
                ),
                "peer_id": (
                    b.get("run_id") if (a.get("median_gap_seconds") or 0)
                    >= (b.get("median_gap_seconds") or 0)
                    else a.get("run_id")
                ),
                "hypothesis": (
                    f"Sample-cadence ratio between the two runs is {worst_ratio}×. "
                    f"Even with both sides labelled 'good', the lower-cadence "
                    f"side averaged over fewer samples — interpret cross-run "
                    f"deltas with that in mind."
                ),
                "evidence": [
                    f"{a.get('run_id')}: median_gap={a.get('median_gap_seconds')}s, "
                    f"samples={a.get('samples_total')}",
                    f"{b.get('run_id')}: median_gap={b.get('median_gap_seconds')}s, "
                    f"samples={b.get('samples_total')}",
                    f"ratio: {worst_ratio}×",
                ],
                "recommendation": (
                    "When publishing the comparison, mention sample counts "
                    "alongside means."
                ),
                "affected_metrics": sensitive_list,
            })

    return findings


def annotate_rankings(
    rankings: dict[str, list[tuple[str, float]]],
    per_run: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Wrap each ranking with cadence-confidence metadata.

    Output shape per ranking:
        {
            "ordered": [(run_id, value, confidence), ...],
            "metric_class": "sample_density_sensitive" | "event_count" | ...,
            "trusted": bool,        # all participants healthy on this metric
            "excluded": [(run_id, reason), ...],
        }

    Sample-density-sensitive rankings exclude runs whose cadence_health
    is "broken" or "no_data" — these would otherwise dominate
    spuriously (e.g. a run with 0 samples winning "best efficiency"
    because its score field is None and the comparator skipped it...
    or worse, ranking it #1). Event-count rankings are unaffected.
    """
    by_id: dict[str, dict[str, Any]] = {p.get("run_id"): p for p in per_run if p.get("run_id")}
    out: dict[str, dict[str, Any]] = {}
    for name, ordered in rankings.items():
        # name is e.g. "best_overall", "lowest_cpu_avg", "fewest_anomalies"
        # Strip the "best_" / "lowest_" / "fewest_" prefix to find the metric.
        metric = name
        for prefix in ("best_", "lowest_", "fewest_", "most_"):
            if name.startswith(prefix):
                metric = name[len(prefix):]
                break
        kind = classify_metric(metric)
        excluded: list[tuple[str, str]] = []
        kept: list[tuple[str, float, str]] = []
        for run_id, value in ordered:
            cq = by_id.get(run_id) or {}
            health = cq.get("cadence_health") or HEALTH_UNKNOWN
            if kind == "sample_density_sensitive" and health in (
                HEALTH_BROKEN, HEALTH_NO_DATA,
            ):
                excluded.append((run_id, f"cadence_health={health}"))
                continue
            if kind == "sample_density_sensitive" and health in (
                HEALTH_DEGRADED, HEALTH_UNKNOWN,
            ):
                kept.append((run_id, value, "degraded"))
            else:
                kept.append((run_id, value, "trusted"))
        worst = worst_health([by_id[rid] for rid, _, _ in kept if rid in by_id]) \
            if kept else HEALTH_UNKNOWN
        all_trusted = (
            kind != "sample_density_sensitive"
            or worst == HEALTH_GOOD
        )
        out[name] = {
            "ordered": kept,
            "metric_class": kind,
            "trusted": all_trusted,
            "excluded": excluded,
        }
    return out
