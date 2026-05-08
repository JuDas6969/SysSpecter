"""Field-review M3: fleet aggregation.

End-to-end tests that build synthetic run folders, run the
aggregator over them, and verify:

- run summaries get loaded with the right fields
- fleet stats compute correct mean / p50 / p95 / std
- outliers are detected at z-score >= 2 against the LATEST run
  per machine
- machines with the same machine_id collapse into one
  longitudinal-trend group
- score drift = first vs last per axis
- common baseline deviations get rolled up across the fleet
- runs without a machine_id are still counted (and flagged)
- the run_aggregate CLI flow writes manifest.json,
  aggregated_findings.json, fleet_report.html, per_machine.csv
"""

from __future__ import annotations

import json
from pathlib import Path

from sysspecter.aggregator.aggregate import (
    _detect_outliers,
    _group_by_machine,
    _machine_view,
    aggregate,
    run_aggregate,
)
from sysspecter.aggregator.loader import (
    RunSummary,
    load_run_summary,
    scan_runs_recursive,
)


def _write_run(
    runs_root: Path,
    *,
    run_id: str,
    machine_id: str | None,
    hostname: str = "BOX1",
    machine_class: str | None = "developer-workstation",
    capture_profile: str | None = None,
    started_at: str = "2026-04-23T01:00:00",
    overall: float = 75.0,
    stability: float = 70.0,
    efficiency: float = 65.0,
    leak_count: int = 0,
    deadlock_count: int = 0,
    baseline_deviations: list[dict] | None = None,
) -> Path:
    """Create a minimal valid run folder under ``runs_root/<run_id>``
    so the loader has something to read."""
    run_dir = runs_root / run_id
    run_dir.mkdir(parents=True)

    manifest = {
        "schema_version": 2,
        "run_id": run_id,
        "hostname": hostname,
        "started_at": started_at,
        "duration_actual_seconds": 1800.0,
        "machine_id": machine_id,
        "machine_id_source": "smbios_uuid" if machine_id else None,
        "meta": {
            "machine_class": machine_class,
            "capture_profile": capture_profile,
        },
    }
    scores = {
        "overall": overall,
        "stability": {"score": stability},
        "efficiency": {"score": efficiency},
        "workload_suitability": {"score": 50},
        "security_overhead": {"score": 80},
        "network_impact": {"score": 90},
        "resource_hygiene": {"score": 75},
        "primary_bottleneck": "cpu",
        "confidence": "high",
    }
    findings = {
        "anomalies": [],
        "slowdowns": [],
        "leaks": {
            "memory": [{} for _ in range(leak_count)],
            "handles": [],
            "threads": [],
        },
        "deadlocks": [{} for _ in range(deadlock_count)],
        "baseline_deviations": list(baseline_deviations or []),
    }
    (run_dir / "manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8")
    (run_dir / "scores.json").write_text(
        json.dumps(scores), encoding="utf-8")
    (run_dir / "findings.json").write_text(
        json.dumps(findings), encoding="utf-8")
    return run_dir


# ----------------------------------------------------- loader


def test_load_run_summary_extracts_score_axes(tmp_path: Path) -> None:
    runs = tmp_path / "Runs"
    run = _write_run(runs, run_id="A", machine_id="MACHINE-aaa",
                     overall=82, stability=78, efficiency=70)
    summary = load_run_summary(str(run))
    assert summary is not None
    assert summary.run_id == "A"
    assert summary.machine_id == "MACHINE-aaa"
    assert summary.overall == 82
    assert summary.stability == 78
    assert summary.efficiency == 70
    assert summary.primary_bottleneck == "cpu"


def test_load_run_summary_returns_none_for_missing_manifest(tmp_path: Path) -> None:
    """Aborted runs that never wrote a manifest are skipped, not
    crash the aggregator."""
    bad = tmp_path / "BROKEN"
    bad.mkdir()
    assert load_run_summary(str(bad)) is None


def test_scan_runs_recursive_walks_subdirectories(tmp_path: Path) -> None:
    runs = tmp_path / "Runs"
    _write_run(runs, run_id="A", machine_id="MACHINE-aaa")
    _write_run(runs, run_id="B", machine_id="MACHINE-bbb")
    # Nested dir layout (e.g. archive of fleet runs)
    nested = tmp_path / "fleet" / "2026-04"
    _write_run(nested, run_id="C", machine_id="MACHINE-ccc")
    summaries = scan_runs_recursive(str(tmp_path))
    ids = sorted(s.run_id for s in summaries)
    assert ids == ["A", "B", "C"]


def test_scan_runs_skips_broken_folders(tmp_path: Path) -> None:
    runs = tmp_path / "Runs"
    _write_run(runs, run_id="A", machine_id="MACHINE-aaa")
    (runs / "BROKEN").mkdir()        # no manifest.json
    summaries = scan_runs_recursive(str(tmp_path))
    assert len(summaries) == 1


def test_scan_runs_root_does_not_exist(tmp_path: Path) -> None:
    assert scan_runs_recursive(str(tmp_path / "nope")) == []


# ----------------------------------------------------- aggregation primitives


def _summary(run_id: str, machine_id: str | None,
             overall: float, started_at: str = "2026-04-23T01:00:00",
             machine_class: str = "developer-workstation",
             baseline_devs: list[dict] | None = None) -> RunSummary:
    """Test helper — build a RunSummary in-memory without writing files."""
    return RunSummary(
        run_id=run_id, run_path=f"/runs/{run_id}",
        hostname=run_id.upper(), machine_id=machine_id,
        machine_id_source="smbios_uuid" if machine_id else None,
        machine_class=machine_class, capture_profile=None,
        started_at=started_at, duration_seconds=1800.0,
        overall=overall, stability=overall - 5, efficiency=overall - 10,
        workload_suitability=50, security_overhead=80,
        network_impact=90, resource_hygiene=75,
        primary_bottleneck="cpu", confidence="high",
        leak_count=0, deadlock_count=0,
        anomaly_count=0, slowdown_count=0,
        baseline_deviations=list(baseline_devs or []),
    )


def test_aggregate_computes_fleet_stats() -> None:
    summaries = [
        _summary("A", "MACHINE-1", overall=70),
        _summary("B", "MACHINE-2", overall=80),
        _summary("C", "MACHINE-3", overall=90),
    ]
    result = aggregate(summaries)
    overall_stats = result["fleet_stats"]["overall"]
    assert overall_stats["samples"] == 3
    assert 78 <= overall_stats["mean"] <= 82      # 80 ±2
    assert overall_stats["p50"] == 80.0
    # p95 of 3 points lands at the 95% mark — close to the max.
    assert overall_stats["p95"] >= 88


def test_outlier_detection_flags_below_fleet_at_z2() -> None:
    """5 healthy machines around 78 ±5, one bad machine at 35
    → that machine is flagged as outlier on overall."""
    summaries = [
        _summary("A", "MACHINE-good-1", overall=78),
        _summary("B", "MACHINE-good-2", overall=80),
        _summary("C", "MACHINE-good-3", overall=82),
        _summary("D", "MACHINE-good-4", overall=76),
        _summary("E", "MACHINE-good-5", overall=78),
        _summary("F", "MACHINE-BAD",   overall=35),
    ]
    fleet_stats = aggregate(summaries)["fleet_stats"]
    outliers = _detect_outliers(summaries, fleet_stats)
    bad_outliers = [o for o in outliers
                    if o["machine_id"] == "MACHINE-BAD"
                    and o["axis"] == "overall"]
    assert bad_outliers, "expected MACHINE-BAD on the outlier list"
    o = bad_outliers[0]
    assert o["direction"] == "below"
    assert o["z_score"] < -2.0


def test_outlier_uses_latest_run_per_machine() -> None:
    """If a machine has multiple runs, the outlier check uses its
    LATEST run — old data shouldn't trip the alarm forever."""
    summaries = [
        # Same MACHINE-X, but old run was bad and recent run is fine.
        _summary("OLD", "MACHINE-X", overall=20,
                 started_at="2026-01-01T00:00:00"),
        _summary("NEW", "MACHINE-X", overall=80,
                 started_at="2026-04-01T00:00:00"),
        _summary("A", "MACHINE-1", overall=78),
        _summary("B", "MACHINE-2", overall=82),
        _summary("C", "MACHINE-3", overall=80),
    ]
    fleet_stats = aggregate(summaries)["fleet_stats"]
    outliers = _detect_outliers(summaries, fleet_stats)
    # No outlier should be flagged for MACHINE-X — its latest score
    # (80) is in band.
    assert not any(o["machine_id"] == "MACHINE-X" for o in outliers)


def test_per_machine_groups_share_id() -> None:
    summaries = [
        _summary("A1", "MACHINE-X", overall=80,
                 started_at="2026-01-01T00:00:00"),
        _summary("A2", "MACHINE-X", overall=82,
                 started_at="2026-02-01T00:00:00"),
        _summary("A3", "MACHINE-X", overall=78,
                 started_at="2026-03-01T00:00:00"),
        _summary("B1", "MACHINE-Y", overall=70),
    ]
    groups = _group_by_machine(summaries)
    assert len(groups["MACHINE-X"]) == 3
    # Grouped runs are sorted by started_at.
    assert [r.run_id for r in groups["MACHINE-X"]] == ["A1", "A2", "A3"]


def test_per_machine_drift_first_vs_last() -> None:
    runs = [
        _summary("A", "M1", overall=80, started_at="2026-01-01T00:00:00"),
        _summary("B", "M1", overall=70, started_at="2026-02-01T00:00:00"),
        _summary("C", "M1", overall=60, started_at="2026-03-01T00:00:00"),
    ]
    view = _machine_view("M1", runs)
    assert view["runs"] == 3
    drift = view["score_drift"]["overall"]
    assert drift["first"] == 80.0
    assert drift["last"] == 60.0
    assert drift["delta"] == -20.0
    assert drift["direction"] == "down"


def test_no_machine_id_runs_get_grouped_by_hostname() -> None:
    summaries = [
        _summary("A", None, overall=80),
        _summary("B", None, overall=85),
    ]
    result = aggregate(summaries)
    # 2 distinct hostname-derived groups, neither counted as
    # "machines_with_id".
    assert result["machines_with_id"] == 0
    assert result["runs_without_machine_id"] == 2


def test_common_baseline_deviations_rolled_up() -> None:
    """Multiple kiosks all show the same baseline deviation → it's
    a fleet-wide problem, not per-machine."""
    dev_kiosk_cpu = {
        "machine_class": "kiosk",
        "metric": "cpu_total_pct_mean",
    }
    summaries = [
        _summary("A", "MK1", overall=50, machine_class="kiosk",
                 baseline_devs=[dev_kiosk_cpu]),
        _summary("B", "MK2", overall=52, machine_class="kiosk",
                 baseline_devs=[dev_kiosk_cpu]),
        _summary("C", "MK3", overall=58, machine_class="kiosk",
                 baseline_devs=[dev_kiosk_cpu]),
        _summary("D", "MD1", overall=80,
                 machine_class="developer-workstation"),
    ]
    result = aggregate(summaries)
    rolled = result["common_baseline_deviations"]
    assert rolled, "expected at least one rolled-up deviation"
    assert rolled[0]["machine_class"] == "kiosk"
    assert rolled[0]["machines_affected"] == 3
    assert rolled[0]["machines_in_class"] == 3


# ----------------------------------------------------- end-to-end CLI flow


def test_run_aggregate_writes_full_output(tmp_path: Path) -> None:
    runs_root = tmp_path / "Runs"
    _write_run(runs_root, run_id="A", machine_id="MACHINE-aaa",
               started_at="2026-01-01T00:00:00", overall=80)
    _write_run(runs_root, run_id="B", machine_id="MACHINE-aaa",
               started_at="2026-02-01T00:00:00", overall=70)
    _write_run(runs_root, run_id="C", machine_id="MACHINE-bbb",
               overall=85)

    out_dir = run_aggregate(str(tmp_path), str(tmp_path / "out"))
    out = Path(out_dir)

    assert (out / "manifest.json").exists()
    assert (out / "aggregated_findings.json").exists()
    assert (out / "per_machine.csv").exists()
    # HTML report is best-effort — assert when jinja is available.
    # In our environment it is, so we expect the file.
    assert (out / "fleet_report.html").exists()

    findings = json.loads((out / "aggregated_findings.json").read_text(encoding="utf-8"))
    assert findings["runs_scanned"] == 3
    assert findings["distinct_machines"] == 2

    # MACHINE-aaa has 2 runs → drift should be populated
    aaa_view = findings["per_machine"]["MACHINE-aaa"]
    assert aaa_view["runs"] == 2
    assert aaa_view["score_drift"]["overall"]["delta"] == -10.0


def test_run_aggregate_handles_empty_input(tmp_path: Path) -> None:
    """An empty runs/ tree must not crash. The aggregation folder
    is still created (with zero counts) so downstream tooling has
    something stable to read."""
    out_dir = run_aggregate(str(tmp_path), str(tmp_path / "out"))
    findings = json.loads(
        (Path(out_dir) / "aggregated_findings.json").read_text(encoding="utf-8")
    )
    assert findings["runs_scanned"] == 0
    assert findings["distinct_machines"] == 0
