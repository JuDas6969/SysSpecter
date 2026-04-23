"""Tests for the scoring engine.

The scorer is the piece of output the customer actually reads. These
tests lock in:
- each score stays within [0, 100]
- extreme inputs produce the right extremes (all-idle = high, all-hot = low)
- the calculate_scores() orchestrator returns the expected keys
- confidence tiers kick in at documented sample counts
- mode="workload" drops workload score below 50 on heavy slowdown ratio
"""

from __future__ import annotations

import pytest

from sysspecter.analyzer.scores import (
    calculate_scores,
    efficiency_score,
    network_impact_score,
    resource_hygiene_score,
    security_overhead_score,
    stability_score,
    workload_suitability_score,
)


def _sys_rows(cpu: float = 20, mem: float = 40, n: int = 120) -> list[dict]:
    """Synthetic system-timeline rows, flat at (cpu, mem)."""
    return [
        {"cpu_total_pct": cpu, "mem_percent": mem, "disk_active_pct_est": 0}
        for _ in range(n)
    ]


# ------------------------------------------------------------------- individual


def test_stability_all_idle_returns_high() -> None:
    score, _ = stability_score(_sys_rows(cpu=5, mem=30), anomalies=[])
    assert score >= 95


def test_stability_penalises_high_anomalies() -> None:
    anomalies = [{"severity": "high"}] * 4
    score, details = stability_score(_sys_rows(), anomalies)
    assert score <= 90
    assert details["anomaly_count"] == 4


def test_stability_on_empty_returns_neutral() -> None:
    score, details = stability_score([], anomalies=[])
    assert score == 50
    assert "no samples" in details["note"]


def test_efficiency_high_idle_scores_well() -> None:
    rows = _sys_rows(cpu=5, mem=20)
    score, details = efficiency_score(rows, offenders={})
    assert score >= 80
    assert details["avg_idle_cpu_pct"] == 95
    assert details["avg_free_mem_pct"] == 80


def test_efficiency_penalises_background_noise() -> None:
    offenders = {"background_noise": [
        {"cpu_pct_avg": 25},
        {"cpu_pct_avg": 15},
        {"cpu_pct_avg": 10},
    ]}
    clean, _ = efficiency_score(_sys_rows(cpu=5, mem=20), offenders={})
    noisy, _ = efficiency_score(_sys_rows(cpu=5, mem=20), offenders=offenders)
    assert noisy < clean


def test_workload_neutral_outside_workload_mode() -> None:
    score, details = workload_suitability_score(_sys_rows(), slowdowns=[], mode="support")
    assert score == 50
    assert details.get("neutral_baseline") is True


def test_workload_drops_on_high_slowdown_ratio() -> None:
    slowdowns = [{"duration_s": 60}, {"duration_s": 30}]
    score, details = workload_suitability_score(
        _sys_rows(n=120), slowdowns, mode="workload",
    )
    # 90 seconds of slowdown over 120 samples ~= 75 % ratio -> ~25
    assert score < 40
    assert 0 < details["slowdown_ratio"] <= 1


def test_security_no_observed_security_processes_stays_high() -> None:
    score, _ = security_overhead_score(offenders={})
    assert score >= 85


def test_security_penalty_scales_with_cpu_and_ram() -> None:
    offenders = {"security": [
        {"cpu_pct_avg": 10, "rss_mb_max": 500},
        {"cpu_pct_avg": 8, "rss_mb_max": 300},
        {"cpu_pct_avg": 6, "rss_mb_max": 200},
    ]}
    # formula: 100 - sum(cpu)*1.5 - sum(rss_mb)*0.05
    #        = 100 - 24*1.5 - 1000*0.05 = 100 - 36 - 50 = 14
    score, _ = security_overhead_score(offenders)
    assert score < 30  # meaningfully penalised

    # And compare with a clean baseline
    clean, _ = security_overhead_score(offenders={})
    assert clean > score + 40


def test_network_no_latency_data_returns_mid_70s() -> None:
    score, _ = network_impact_score(latency_rows=[])
    assert score == 70


def test_network_penalises_high_latency_and_loss() -> None:
    rows = [
        {"avg_ms": 250, "loss_pct": 5},
        {"avg_ms": 300, "loss_pct": 5},
    ]
    score, _ = network_impact_score(rows)
    assert score < 50


def test_resource_hygiene_no_leaks_is_100() -> None:
    score, _ = resource_hygiene_score(
        leaks={"memory": [], "handles": [], "threads": []},
        offenders={},
    )
    assert score == 100


def test_resource_hygiene_strong_leak_penalty() -> None:
    leaks = {
        "memory": [{"confidence": "strong evidence"}, {"confidence": "likely"}],
        "handles": [],
        "threads": [],
    }
    score, _ = resource_hygiene_score(leaks, offenders={})
    # 20 (strong) + 10 (likely) = -30
    assert score == pytest.approx(70.0)


# ---------------------------------------------------------------- orchestrator


def test_calculate_scores_all_clean() -> None:
    out = calculate_scores(
        system_rows=_sys_rows(cpu=5, mem=30, n=700),
        anomalies=[], slowdowns=[],
        offenders={}, leaks={"memory": [], "handles": [], "threads": []},
        latency_rows=[{"avg_ms": 10, "loss_pct": 0} for _ in range(10)],
        mode="support",
        bottlenecks={"primary": None, "secondary": []},
    )
    for key in ("stability", "efficiency", "workload_suitability",
                "security_overhead", "network_impact", "resource_hygiene"):
        assert 0 <= out[key]["score"] <= 100
    assert 0 <= out["overall"] <= 100
    assert out["confidence"] == "high"
    assert out["sample_count"] == 700


def test_calculate_scores_low_confidence_on_short_run() -> None:
    out = calculate_scores(
        system_rows=_sys_rows(n=30),
        anomalies=[], slowdowns=[], offenders={},
        leaks={"memory": [], "handles": [], "threads": []},
        latency_rows=[], mode="support",
        bottlenecks={"primary": None, "secondary": []},
    )
    assert "low" in out["confidence"]
    assert out["sample_count"] == 30


def test_calculate_scores_weights_sum_to_one() -> None:
    out = calculate_scores(
        system_rows=_sys_rows(),
        anomalies=[], slowdowns=[], offenders={},
        leaks={"memory": [], "handles": [], "threads": []},
        latency_rows=[], mode="support",
        bottlenecks={"primary": None, "secondary": []},
    )
    assert sum(out["weights"].values()) == pytest.approx(1.0)
