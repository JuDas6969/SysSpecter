"""v3-priority-2: comparison-engine cadence-quality awareness.

The v2 production review surfaced the engine's biggest practical bug:
ATLT4407 (median sample gap 18 s) was matched against MORGANA
(median 1.1 s) on `cpu_avg`, `mem_avg`, `latency_p95_ms` etc. without
any acknowledgement that one side's mean was averaged over 55
samples and the other's over 504. These tests pin the new layer that
guards against that:

- per-run extraction with back-compat for runs that pre-date the
  v3-priority-1 cadence_quality manifest block
- metric classification (sample-density-sensitive vs event-count vs
  static)
- asymmetry findings: broken cadence in any participant; mixed
  health; pairwise gap-ratio > 2× even when both sides nominally good
- ranking annotation: sample-density-sensitive rankings exclude
  broken/no_data runs; event-count rankings are unaffected
"""

from __future__ import annotations

from sysspecter.comparer.cadence_quality import (
    HEALTH_BROKEN,
    HEALTH_DEGRADED,
    HEALTH_GOOD,
    HEALTH_NO_DATA,
    HEALTH_UNKNOWN,
    annotate_rankings,
    build_asymmetry_findings,
    cadence_ratio,
    classify_metric,
    confidence_for_metric,
    extract_per_run,
    worst_health,
)

# --- factories ------------------------------------------------------

def _run(run_id: str, *,
         interval: float = 1.0,
         cq: dict | None = None,
         priority: str = "HIGH",
         hostname: str | None = None) -> dict:
    """Build a minimal `loaded` entry shaped like comparer/loader output."""
    manifest: dict = {
        "run_id": run_id,
        "hostname": hostname or run_id,
        "interval_seconds": interval,
        "process_priority_class": priority,
    }
    if cq is not None:
        manifest["cadence_quality"] = cq
    return {"manifest": manifest, "scores": {}, "findings": {}, "rd": None}


def _good_cq(median: float = 1.0, samples: int = 500) -> dict:
    return {
        "nominal_interval_seconds": 1.0,
        "samples_total": samples,
        "median_gap_seconds": median,
        "p95_gap_seconds": median * 1.2,
        "max_gap_seconds": median * 2.0,
        "gaps_over_2x_nominal": 0,
        "gaps_over_5x_nominal": 0,
        "cadence_health": HEALTH_GOOD,
        "ratio_median_to_nominal": median,
    }


def _broken_cq_atlt4407() -> dict:
    """The exact pattern the v2 production review captured on ATLT4407."""
    return {
        "nominal_interval_seconds": 1.0,
        "samples_total": 55,
        "median_gap_seconds": 18.1,
        "p95_gap_seconds": 27.5,
        "max_gap_seconds": 30.4,
        "gaps_over_2x_nominal": 54,
        "gaps_over_5x_nominal": 49,
        "cadence_health": HEALTH_BROKEN,
        "ratio_median_to_nominal": 18.1,
    }


# --- classify_metric -----------------------------------------------

def test_classify_metric_categorises_sample_density_metrics() -> None:
    assert classify_metric("cpu_avg") == "sample_density_sensitive"
    assert classify_metric("mem_avg") == "sample_density_sensitive"
    assert classify_metric("latency_p95_ms") == "sample_density_sensitive"
    assert classify_metric("stability") == "sample_density_sensitive"


def test_classify_metric_categorises_event_counts_correctly() -> None:
    assert classify_metric("anomalies") == "event_count"
    assert classify_metric("memory_leaks") == "event_count"
    assert classify_metric("process_starts") == "event_count"
    # security/network/hygiene are score columns derived from event
    # counts, so they're cadence-immune.
    assert classify_metric("security") == "event_count"


def test_classify_metric_static_and_unknown() -> None:
    assert classify_metric("ram_gb") == "static"
    assert classify_metric("primary_disk_tier") == "static"
    assert classify_metric("not_a_real_column") == "unknown"


# --- extract_per_run -----------------------------------------------

def test_extract_per_run_lifts_cadence_quality_block() -> None:
    loaded = [
        _run("r1", cq=_good_cq(median=1.05, samples=300)),
    ]
    out = extract_per_run(loaded)
    assert len(out) == 1
    assert out[0]["run_id"] == "r1"
    assert out[0]["cadence_health"] == HEALTH_GOOD
    assert out[0]["median_gap_seconds"] == 1.05
    assert out[0]["samples_total"] == 300
    assert out[0]["back_compat"] is False


def test_extract_per_run_back_compat_for_pre_v3_runs() -> None:
    """Runs that pre-date v3-priority-1 don't have cadence_quality.
    Must surface as health=unknown / back_compat=True without raising."""
    loaded = [_run("r_old"), _run("r_new", cq=_good_cq())]
    out = extract_per_run(loaded)
    assert out[0]["cadence_health"] == HEALTH_UNKNOWN
    assert out[0]["back_compat"] is True
    assert out[0]["nominal_interval_seconds"] == 1.0  # falls back to manifest.interval_seconds
    assert out[1]["back_compat"] is False


# --- worst_health --------------------------------------------------

def test_worst_health_picks_the_worst_state() -> None:
    per_run = [
        {"cadence_health": HEALTH_GOOD},
        {"cadence_health": HEALTH_DEGRADED},
        {"cadence_health": HEALTH_GOOD},
    ]
    assert worst_health(per_run) == HEALTH_DEGRADED

    per_run.append({"cadence_health": HEALTH_BROKEN})
    assert worst_health(per_run) == HEALTH_BROKEN

    per_run.append({"cadence_health": HEALTH_NO_DATA})
    assert worst_health(per_run) == HEALTH_NO_DATA


def test_worst_health_empty_returns_unknown() -> None:
    assert worst_health([]) == HEALTH_UNKNOWN


# --- confidence_for_metric -----------------------------------------

def test_confidence_for_event_count_metric_is_always_trusted() -> None:
    """Event counts (anomalies, leaks) don't depend on cadence."""
    per_run = extract_per_run([_run("r1", cq=_broken_cq_atlt4407())])
    assert confidence_for_metric("anomalies", per_run) == "trusted"
    assert confidence_for_metric("memory_leaks", per_run) == "trusted"


def test_confidence_for_sample_density_metric_with_broken_run_is_untrusted() -> None:
    per_run = extract_per_run([
        _run("good", cq=_good_cq()),
        _run("ATLT4407", cq=_broken_cq_atlt4407()),
    ])
    assert confidence_for_metric("cpu_avg", per_run) == "untrusted"
    assert confidence_for_metric("mem_avg", per_run) == "untrusted"


def test_confidence_for_sample_density_metric_with_only_good_runs_is_trusted() -> None:
    per_run = extract_per_run([
        _run("good1", cq=_good_cq(median=1.0)),
        _run("good2", cq=_good_cq(median=1.1)),
    ])
    assert confidence_for_metric("cpu_avg", per_run) == "trusted"


def test_confidence_for_sample_density_metric_with_unknown_is_degraded() -> None:
    """Pre-v3 runs surface as unknown — treat conservatively (degraded)."""
    per_run = extract_per_run([_run("good", cq=_good_cq()), _run("legacy")])
    assert confidence_for_metric("cpu_avg", per_run) == "degraded"


# --- cadence_ratio -------------------------------------------------

def test_cadence_ratio_returns_worse_over_better() -> None:
    a = {"median_gap_seconds": 18.0}
    b = {"median_gap_seconds": 1.0}
    assert cadence_ratio(a, b) == 18.0
    assert cadence_ratio(b, a) == 18.0  # always >= 1


def test_cadence_ratio_handles_missing_data() -> None:
    assert cadence_ratio({}, {"median_gap_seconds": 1.0}) is None
    assert cadence_ratio({"median_gap_seconds": 0.0}, {"median_gap_seconds": 1.0}) is None


# --- build_asymmetry_findings --------------------------------------

def test_no_findings_when_all_runs_healthy_and_close() -> None:
    per_run = extract_per_run([
        _run("a", cq=_good_cq(median=1.0)),
        _run("b", cq=_good_cq(median=1.1)),
    ])
    assert build_asymmetry_findings(per_run) == []


def test_broken_run_fires_high_severity_finding() -> None:
    """The ATLT4407 case must produce a high-severity broken-cadence
    finding listing affected metrics."""
    per_run = extract_per_run([
        _run("MORGANA", cq=_good_cq(median=1.1, samples=504)),
        _run("ATLT4407", cq=_broken_cq_atlt4407()),
    ])
    findings = build_asymmetry_findings(per_run)
    broken = [f for f in findings if f["kind"] == "broken_cadence_in_participant"]
    assert len(broken) == 1
    f = broken[0]
    assert f["severity"] == "high"
    assert f["category"] == "cadence_quality"
    assert f["run_id"] == "ATLT4407"
    assert "cpu_avg" in f["affected_metrics"]
    assert "mem_avg" in f["affected_metrics"]
    # Evidence should cite the actual numbers.
    joined_evidence = " ".join(f["evidence"])
    assert "18" in joined_evidence  # median 18.1 s shown


def test_mixed_health_fires_medium_finding() -> None:
    """When some good + some degraded participants exist, surface a
    medium-severity warning so the report can mention the asymmetry."""
    per_run = extract_per_run([
        _run("good1", cq=_good_cq()),
        _run("degraded1", cq={
            "nominal_interval_seconds": 1.0,
            "samples_total": 100,
            "median_gap_seconds": 2.5,
            "p95_gap_seconds": 3.0,
            "max_gap_seconds": 5.0,
            "gaps_over_2x_nominal": 80,
            "gaps_over_5x_nominal": 5,
            "cadence_health": HEALTH_DEGRADED,
            "ratio_median_to_nominal": 2.5,
        }),
    ])
    findings = build_asymmetry_findings(per_run)
    mixed = [f for f in findings if f["kind"] == "mixed_cadence_health"]
    assert len(mixed) == 1
    assert mixed[0]["severity"] == "medium"
    assert mixed[0]["run_id"] == "degraded1"
    assert mixed[0]["peer_id"] == "good1"


def test_pairwise_gap_ratio_finding_for_two_good_runs_with_2x_difference() -> None:
    """Even when both sides are 'good', a 2.5× cadence gap means one
    side averaged over fewer samples. Surface as a medium finding."""
    per_run = extract_per_run([
        _run("fast", cq=_good_cq(median=0.5)),
        _run("slow", cq=_good_cq(median=1.4)),  # 2.8× ratio
    ])
    findings = build_asymmetry_findings(per_run)
    pairs = [f for f in findings if f["kind"] == "pairwise_gap_ratio"]
    assert len(pairs) == 1
    assert pairs[0]["severity"] == "medium"
    assert pairs[0]["run_id"] == "slow"


def test_pairwise_finding_skipped_when_already_covered_by_broken() -> None:
    """If a broken-cadence finding fires, the pairwise-ratio one should
    NOT also fire — it'd be noise. The broken finding is sharper."""
    per_run = extract_per_run([
        _run("good", cq=_good_cq()),
        _run("ATLT4407", cq=_broken_cq_atlt4407()),
    ])
    findings = build_asymmetry_findings(per_run)
    pairs = [f for f in findings if f["kind"] == "pairwise_gap_ratio"]
    assert pairs == []  # broken finding already covers it


# --- annotate_rankings ---------------------------------------------

def test_event_count_rankings_unaffected_by_cadence() -> None:
    """fewest_anomalies is a count — broken cadence doesn't change
    whether an anomaly was detected. So a broken-cadence run can win
    this ranking."""
    per_run = extract_per_run([
        _run("good", cq=_good_cq()),
        _run("ATLT4407", cq=_broken_cq_atlt4407()),
    ])
    rankings = {"fewest_anomalies": [("ATLT4407", 0), ("good", 5)]}
    out = annotate_rankings(rankings, per_run)
    assert out["fewest_anomalies"]["ordered"][0][0] == "ATLT4407"
    assert out["fewest_anomalies"]["excluded"] == []
    assert out["fewest_anomalies"]["metric_class"] == "event_count"


def test_sample_density_rankings_exclude_broken_runs() -> None:
    """`lowest_cpu_avg` MUST exclude the broken-cadence run — its
    average is biased by 18 s gaps. This is the headline guard."""
    per_run = extract_per_run([
        _run("MORGANA", cq=_good_cq(median=1.1, samples=504)),
        _run("ATLT4407", cq=_broken_cq_atlt4407()),
    ])
    rankings = {"lowest_cpu_avg": [("ATLT4407", 5.0), ("MORGANA", 6.9)]}
    out = annotate_rankings(rankings, per_run)
    # ATLT4407 had the lowest CPU on paper but cadence is broken.
    # MORGANA wins instead.
    assert out["lowest_cpu_avg"]["ordered"][0][0] == "MORGANA"
    excluded_ids = {rid for rid, _ in out["lowest_cpu_avg"]["excluded"]}
    assert "ATLT4407" in excluded_ids


def test_sample_density_rankings_keep_all_when_only_good_cadence() -> None:
    per_run = extract_per_run([
        _run("a", cq=_good_cq(median=1.0)),
        _run("b", cq=_good_cq(median=1.1)),
    ])
    rankings = {"lowest_cpu_avg": [("a", 5.0), ("b", 6.0)]}
    out = annotate_rankings(rankings, per_run)
    assert len(out["lowest_cpu_avg"]["ordered"]) == 2
    assert out["lowest_cpu_avg"]["excluded"] == []
    assert out["lowest_cpu_avg"]["trusted"] is True


def test_unknown_back_compat_run_kept_but_marked_degraded() -> None:
    """A pre-v3 run shouldn't be excluded outright (back-compat) but
    must be flagged degraded so the report can show a per-cell
    confidence marker. The well-sampled peer keeps its "trusted"
    per-cell marker (its own data is fine), but the overall ranking's
    `trusted` flag goes False so the report knows the comparison as a
    whole is suspect."""
    per_run = extract_per_run([_run("legacy"), _run("good", cq=_good_cq())])
    rankings = {"lowest_cpu_avg": [("legacy", 5.0), ("good", 6.0)]}
    out = annotate_rankings(rankings, per_run)
    assert len(out["lowest_cpu_avg"]["ordered"]) == 2
    confidences = {rid: conf for rid, _, conf in out["lowest_cpu_avg"]["ordered"]}
    assert confidences["legacy"] == "degraded"  # its own health is unknown
    assert confidences["good"] == "trusted"     # its own health is good
    # But the ranking as a whole isn't fully trusted — one participant
    # has unknown cadence, so the headline verdict needs a caveat.
    assert out["lowest_cpu_avg"]["trusted"] is False
