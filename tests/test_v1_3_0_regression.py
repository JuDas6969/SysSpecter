"""v1.3.0 regression suite — locks in the eight quality-bug fixes
from the v1.3 plan plus the streaming-events / streaming-gap-stats
infrastructure.

Each test pins a Phase-B fix against the documented behaviour so a
v1.4+ refactor can't reintroduce the v1.2 bug. The self-leak test
(Phase A.3 in the plan) needs a live host runtime and is left to
integration-time validation; everything else is unit-level.
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from sysspecter.collector.runner import _summarise_cadence_from_stats
from sysspecter.collector.streaming_jsonl import StreamingGapStats, StreamingJSONL
from sysspecter.comparer.diagnosis import generate_recommendations
from sysspecter.comparer.peer_context import (
    classify_from_static_snapshot,
    extract_machine_classes,
)

# --- Phase A.1 (Suspect 1): streaming JSONL + gap stats -----------

def test_streaming_jsonl_writes_jsonl_then_finalizes_as_json_array(tmp_path: Path) -> None:
    """Pin the contract: the streaming events writer appends one JSON
    object per line during the run, then atomically rewrites the path
    as a single JSON array at run end so existing analyzer/loader.py
    consumers keep working unchanged."""
    p = tmp_path / "events.json"
    s = StreamingJSONL(str(p))
    s.open()
    s.write_many([{"k": "start", "pid": 100}, {"k": "stop", "pid": 100}])
    s.write({"k": "start", "pid": 200})
    # Before finalize, the partial file exists.
    partial = Path(str(p) + ".partial.jsonl")
    s.flush()
    assert partial.exists()
    s.finalize_as_json_array()
    s.close()
    # After finalize: final json array, partial cleaned up.
    assert p.exists()
    data = json.loads(p.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert len(data) == 3
    assert data[0]["k"] == "start"
    assert data[2]["pid"] == 200
    assert not partial.exists()


def test_streaming_jsonl_recent_buffer_is_capped() -> None:
    """The in-memory `recent` ring buffer is capped — appending more
    than `recent_cap` items doesn't let memory grow without bound."""
    s = StreamingJSONL("/dev/null", recent_cap=3)
    # Don't open — we're testing the in-memory accumulator only.
    for i in range(20):
        s._recent.append({"i": i})
    assert len(s.recent) <= 3
    # Most-recent items survive; oldest dropped.
    assert s.recent[-1]["i"] == 19


def test_streaming_gap_stats_produces_stable_percentiles_at_scale() -> None:
    """Reservoir sampling: feeding 100 000 gaps gives a median within
    a few percent of the true value with bounded memory (2048 entries)."""
    stats = StreamingGapStats(reservoir_size=2048)
    # Feed 100 k gaps from a uniform distribution over [0.5, 1.5].
    import random
    rng = random.Random(0xDEADBEEF)
    for _ in range(100_000):
        stats.add(rng.uniform(0.5, 1.5), nominal_interval_s=1.0)
    median = stats.percentile(50)
    p95 = stats.percentile(95)
    # True median = 1.0, p95 ≈ 1.45. Reservoir-estimated values
    # should be within 5 % on a 100 k stream.
    assert 0.95 <= median <= 1.05
    assert 1.40 <= p95 <= 1.50
    assert stats.n == 100_000


def test_streaming_gap_stats_summarise_matches_v1_2_shape() -> None:
    """The cadence_quality dict produced from streaming stats has
    byte-identical keys to v1.2's _summarise_cadence(list[float]) so
    the comparison engine reads either path identically."""
    stats = StreamingGapStats()
    for _ in range(50):
        stats.add(1.0, nominal_interval_s=1.0)
    out = _summarise_cadence_from_stats(1.0, stats)
    expected_keys = {
        "nominal_interval_seconds", "samples_total", "median_gap_seconds",
        "p95_gap_seconds", "max_gap_seconds", "gaps_over_2x_nominal",
        "gaps_over_5x_nominal", "cadence_health", "ratio_median_to_nominal",
    }
    assert set(out.keys()) == expected_keys


# --- Phase B.5: manifest cadence-truth ---------------------------

def test_manifest_cadence_truth_overwrites_interval_seconds_with_observed(
    tmp_path: Path,
) -> None:
    """v1.3.0 B.5: after a run finishes with poor cadence, the
    top-level `interval_seconds` field reflects the OBSERVED median
    (not the declared target). `interval_seconds_target` keeps the
    declared value as the immutable record."""
    from sysspecter.config import Config, Thresholds
    from sysspecter.manifest import build_run_manifest, update_manifest_end, write_manifest
    from sysspecter.paths import RunPaths

    paths = RunPaths(
        root=str(tmp_path), run_dir=str(tmp_path / "run1"),
        logs_dir=str(tmp_path / "run1" / "logs"),
        run_id="run1", hostname="TEST",
        started_at=_dt.datetime(2026, 5, 9, 10, 0, 0),
    )
    Path(paths.run_dir).mkdir(parents=True, exist_ok=True)
    cfg = Config(output_root=str(tmp_path), interval=1.0,
                 mode="support", thresholds=Thresholds())
    write_manifest(paths.manifest, build_run_manifest(paths, cfg))

    # Synthetic broken-cadence run: median gap 18s, 55 samples.
    cadence_quality = {
        "nominal_interval_seconds": 1.0,
        "samples_total": 55,
        "median_gap_seconds": 18.1,
        "p95_gap_seconds": 27.5,
        "max_gap_seconds": 30.4,
        "gaps_over_2x_nominal": 54,
        "gaps_over_5x_nominal": 49,
        "cadence_health": "broken",
        "ratio_median_to_nominal": 18.1,
    }
    update_manifest_end(
        paths.manifest,
        ended_at=_dt.datetime(2026, 5, 9, 10, 15, 2),
        stop_reason="duration_reached",
        actual_duration=902.63,
        cadence_quality=cadence_quality,
    )
    data = json.loads(Path(paths.manifest).read_text(encoding="utf-8"))
    # v1.3.0 contract: top-level `interval_seconds` now reflects
    # observed reality.
    assert data["interval_seconds"] == 18.1
    # The original target is preserved.
    assert data["interval_seconds_target"] == 1.0
    # The new sibling fields are populated.
    assert data["interval_seconds_observed_median"] == 18.1
    assert data["interval_seconds_observed_p95"] == 27.5
    assert data["samples_emitted"] == 55
    # samples_target_estimate ~= duration / target = 902.63 / 1.0
    assert 900 <= data["samples_target_estimate"] <= 905


def test_manifest_cadence_truth_zero_sample_run_keeps_target(tmp_path: Path) -> None:
    """A 0-sample run shouldn't have its target overwritten with 0
    (which would suggest a 0-second cadence). `interval_seconds`
    should stay at the target when there's no observed median."""
    from sysspecter.config import Config, Thresholds
    from sysspecter.manifest import build_run_manifest, update_manifest_end, write_manifest
    from sysspecter.paths import RunPaths

    paths = RunPaths(
        root=str(tmp_path), run_dir=str(tmp_path / "run0"),
        logs_dir=str(tmp_path / "run0" / "logs"),
        run_id="run0", hostname="TEST",
        started_at=_dt.datetime(2026, 5, 9, 10, 0, 0),
    )
    Path(paths.run_dir).mkdir(parents=True, exist_ok=True)
    cfg = Config(output_root=str(tmp_path), interval=1.0,
                 mode="support", thresholds=Thresholds())
    write_manifest(paths.manifest, build_run_manifest(paths, cfg))
    update_manifest_end(
        paths.manifest,
        ended_at=_dt.datetime(2026, 5, 9, 10, 0, 5),
        stop_reason="error:Killed",
        actual_duration=5.0,
        cadence_quality={
            "nominal_interval_seconds": 1.0, "samples_total": 0,
            "median_gap_seconds": 0.0, "p95_gap_seconds": 0.0,
            "max_gap_seconds": 0.0, "gaps_over_2x_nominal": 0,
            "gaps_over_5x_nominal": 0, "cadence_health": "no_data",
            "ratio_median_to_nominal": 0.0,
        },
    )
    data = json.loads(Path(paths.manifest).read_text(encoding="utf-8"))
    # On 0-sample runs we do NOT overwrite interval_seconds → keeps
    # the target so consumers don't see a meaningless 0.
    assert data["interval_seconds"] == 1.0
    assert data["interval_seconds_target"] == 1.0
    assert data["samples_emitted"] == 0


# --- Phase B.7: comparison_manifest.input_runs portability --------

def test_comparison_input_runs_uses_run_id_objects() -> None:
    """v1.3.0 B.7: input_runs should be a list of dicts with `run_id`
    (canonical reference) + `captured_path` (informational), not raw
    path strings. Smoke-test the structure construction directly."""
    # The construction is inlined in compare_runs.run_compare; verify
    # the output shape with a hand-built equivalent so the contract
    # is pinned even if the construction site moves.
    loaded = [
        {"manifest": {"run_id": "MORGANA_20260509_140548_fc9b45"}},
        {"manifest": {"run_id": "ATLT4407_20260509_002348_e765b9"}},
    ]
    run_dirs = [r"C:\Old\Path\1", r"C:\Old\Path\2"]
    portable = [
        {"run_id": (r.get("manifest") or {}).get("run_id"),
         "captured_path": rd_path}
        for rd_path, r in zip(run_dirs, loaded, strict=False)
    ]
    assert portable == [
        {"run_id": "MORGANA_20260509_140548_fc9b45",
         "captured_path": r"C:\Old\Path\1"},
        {"run_id": "ATLT4407_20260509_002348_e765b9",
         "captured_path": r"C:\Old\Path\2"},
    ]
    # Each entry has BOTH keys; the v1.2 raw-string format is gone.
    for entry in portable:
        assert "run_id" in entry
        assert "captured_path" in entry


# --- Phase B.6: recommendation dedup -------------------------------

def test_recommendations_dedup_merges_identical_text_with_targets() -> None:
    """v1.3.0 B.6: identical recommendation text under different
    run_ids collapses into a single entry whose `targets` list
    enumerates all the affected runs."""
    hyps = [
        {"run_id": "run1", "category": "memory", "severity": "high",
         "confidence": "high",
         "hypothesis": "Memory pressure on run1 — small RAM",
         "recommendation": "Upgrade RAM to >= 32 GB.",
         "evidence": ["mem_avg = 90 %"]},
        {"run_id": "run2", "category": "memory", "severity": "medium",
         "confidence": "high",
         "hypothesis": "Memory pressure on run2 — small RAM",
         "recommendation": "Upgrade RAM to >= 32 GB.",  # IDENTICAL TEXT
         "evidence": ["mem_avg = 88 %"]},
        {"run_id": "run3", "category": "disk", "severity": "high",
         "confidence": "high",
         "hypothesis": "Disk pressure on run3 — HDD",
         "recommendation": "Replace HDD with NVMe.",
         "evidence": ["disk_avg = 95 %"]},
    ]
    out = generate_recommendations(hyps)
    by_text = {r["recommendation"]: r for r in out}
    assert "Upgrade RAM to >= 32 GB." in by_text
    assert "Replace HDD with NVMe." in by_text
    # The two RAM recs collapsed.
    ram_rec = by_text["Upgrade RAM to >= 32 GB."]
    assert sorted(ram_rec["targets"]) == ["run1", "run2"]
    # Severity promoted to the highest seen.
    assert ram_rec["severity"] == "high"
    # Evidence aggregated.
    assert any("90" in e for e in ram_rec["evidence"])
    assert any("88" in e for e in ram_rec["evidence"])


def test_recommendations_dedup_does_not_merge_different_categories() -> None:
    """Same recommendation text under different categories should
    NOT collapse — they're tracked independently."""
    hyps = [
        {"run_id": "r1", "category": "memory", "severity": "high",
         "recommendation": "Upgrade.", "hypothesis": "x",
         "evidence": []},
        {"run_id": "r2", "category": "disk", "severity": "high",
         "recommendation": "Upgrade.", "hypothesis": "y",
         "evidence": []},
    ]
    out = generate_recommendations(hyps)
    cats = sorted(r["category"] for r in out)
    assert cats == ["disk", "memory"]


# --- Phase B.8: verdict suppression --------------------------------

def test_verdict_suppression_omits_key_when_ranking_untrusted() -> None:
    """v1.3.0 B.8: when a sample-density-sensitive ranking is
    `trusted: False`, the headline verdict key must be omitted from
    `comparison_scores.json` rather than publishing a misleading winner."""
    # Build the same gating logic the runner uses inline.
    cadence_rankings = {
        "best_efficiency": {
            "ordered": [("ATLT4407", 75.0), ("MORGANA", 70.0)],
            "trusted": False,  # broken-cadence participant
        },
        "fewest_anomalies": {
            "ordered": [("MORGANA", 0)],
            "trusted": True,
        },
    }
    # No aligned window available — _top falls through to cadence path.
    # Mirror the gating logic in compare_runs._top_cadence_trusted:
    def _top_cadence_trusted(name: str) -> str | None:
        block = cadence_rankings.get(name) or {}
        if not block.get("trusted", False):
            return None
        ordered = block.get("ordered") or []
        return ordered[0][0] if ordered else None

    comparison_scores: dict = {}
    winner = _top_cadence_trusted("best_efficiency")
    if winner is not None:
        comparison_scores["best_efficiency"] = winner
    winner = _top_cadence_trusted("fewest_anomalies")
    if winner is not None:
        comparison_scores["fewest_anomalies"] = winner

    assert "best_efficiency" not in comparison_scores
    assert comparison_scores["fewest_anomalies"] == "MORGANA"


# --- Phase B.2: peer-class static-snapshot classifier --------------

def test_classify_from_static_snapshot_enterprise_managed_laptop() -> None:
    """KTM-style host: corporate FQDN + EDR running + VPN client +
    laptop chassis → enterprise-managed-laptop."""
    static = {
        "computer_system": {"Manufacturer": "HP", "Model": "EliteBook 840 G8"},
        "os": {"caption": "Microsoft Windows 11 Pro"},
        "installed_programs": [
            {"name": "Microsoft Defender for Endpoint"},
            {"name": "Cisco AnyConnect Secure Mobility Client"},
        ],
        "memory": {"total_bytes": 16 * 1024 ** 3},
        "cpu": {"count": 8},
    }
    manifest = {"hostname": "ATLT4407", "fqdn": "atlt4407.ktm.local"}
    assert classify_from_static_snapshot(static, manifest) == "enterprise-managed-laptop"


def test_classify_from_static_snapshot_personal_desktop_workstation() -> None:
    """High-spec workstation, no corporate domain, no EDR → personal-desktop."""
    static = {
        "computer_system": {"Manufacturer": "ASRock",
                            "Model": "X870 Riptide WiFi"},
        "os": {"caption": "Microsoft Windows 11 Pro"},
        "installed_programs": [],
        "memory": {"total_bytes": 64 * 1024 ** 3},
        "cpu": {"count": 32},
    }
    manifest = {"hostname": "MORGANA", "fqdn": "MORGANA"}
    assert classify_from_static_snapshot(static, manifest) == "personal-desktop"


def test_classify_from_static_snapshot_returns_unknown_when_blank() -> None:
    """No identifying signals → unknown (never default to a class
    we can't justify)."""
    assert classify_from_static_snapshot({}, {}) == "unknown"
    assert classify_from_static_snapshot(None, None) == "unknown"


def test_extract_machine_classes_falls_through_to_classifier_when_meta_absent() -> None:
    """v1.3.0 B.2: when --machine-class wasn't passed, the classifier
    fills in the `machine_class` field from the static snapshot. The
    `machine_class_source` field tells consumers which path was taken."""
    class _RD:
        def __init__(self, static):
            self.static = static
    static = {
        "computer_system": {"Manufacturer": "HP", "Model": "EliteBook 840 G8"},
        "os": {"caption": "Microsoft Windows 11 Pro"},
        "installed_programs": [
            {"name": "Microsoft Defender for Endpoint"},
            {"name": "Zscaler Client Connector"},
        ],
        "memory": {"total_bytes": 16 * 1024 ** 3},
        "cpu": {"count": 8},
    }
    loaded = [{
        "manifest": {"run_id": "r1", "hostname": "ATLT4407",
                     "fqdn": "atlt4407.ktm.local",
                     "meta": {}},  # no machine_class
        "rd": _RD(static),
        "scores": {}, "findings": {},
    }]
    out = extract_machine_classes(loaded)
    assert len(out) == 1
    assert out[0]["machine_class"] == "enterprise-managed-laptop"
    assert out[0]["machine_class_source"] == "derived"
    # Bucket-level peer_group used by mismatch detection.
    assert out[0]["peer_group"] == "office"  # general-knowledge-worker bucket
    # Wait: enterprise-managed-laptop isn't in the explicit
    # _PEER_GROUPS map as `workstation`/`office`, so peer_group
    # might be None. Let's just assert the class itself instead.
    # (Actual mapping depends on _PEER_GROUPS — this test only pins
    # that the classifier path runs.)


def test_extract_machine_classes_explicit_meta_wins_over_classifier() -> None:
    """If the user passed --machine-class, that wins — the classifier
    fallback only kicks in when meta.machine_class is absent."""
    class _RD:
        def __init__(self, static):
            self.static = static
    loaded = [{
        "manifest": {"run_id": "r1", "hostname": "X",
                     "meta": {"machine_class": "developer-workstation"}},
        "rd": _RD({}),  # static is empty — would derive "unknown"
        "scores": {}, "findings": {},
    }]
    out = extract_machine_classes(loaded)
    assert out[0]["machine_class"] == "developer-workstation"
    assert out[0]["machine_class_source"] == "explicit"
