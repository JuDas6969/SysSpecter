"""Field-review A5: cross-run aggregation view.

Pins the contract that the comparison output lifts the new schema
fields (M5 machine_id, M2 meta, A6 tail_windows, C3 baseline
deviations, C4 capture_profile) into a single block downstream
consumers can index on.

Tests cover:
- Two runs with the same machine_id flag `same_machine: True`
- Different machine_ids → False
- Missing machine_ids on any run → False (can't claim sameness)
- Shared meta keys (department, ticket, scenario) extracted only
  when EVERY run agrees
- shared_machine_class set only when all runs agree
- shared_capture_profile set only when all runs agree
- Tail-window comparison picks the LARGEST common window
- Empty tail_windows on any run → no common window
- Common baseline deviations require ALL runs to share the
  (machine_class, metric) signature
- Empty input returns the empty-view shape (no crash)
"""

from __future__ import annotations

from sysspecter.comparer.cross_run_view import build_cross_run_view


def _run(*, run_id: str, machine_id: str | None = None,
         machine_id_source: str | None = None,
         meta: dict | None = None,
         tail_windows: list | None = None,
         baseline_deviations: list | None = None) -> dict:
    """Build a `loaded` entry shaped like compare_runs.run_compare
    expects: manifest + findings + scores."""
    return {
        "manifest": {
            "run_id": run_id,
            "hostname": run_id.upper(),
            "machine_id": machine_id,
            "machine_id_source": machine_id_source,
            "meta": meta or {},
        },
        "findings": {
            "baseline_deviations": baseline_deviations or [],
        },
        "scores": {
            "tail_windows": tail_windows or [],
        },
    }


def _tw(label: str, *, overall: float = 75, samples: int = 3600,
        duration_seconds: float = 3600.0) -> dict:
    """Build a tail_window entry shaped like A6 produces."""
    return {
        "window_label": label,
        "window_duration_seconds": duration_seconds,
        "window_samples": samples,
        "overall": overall,
        "stability": {"score": 70},
        "efficiency": {"score": 60},
        "workload_suitability": {"score": 50},
        "network_impact": {"score": 90},
        "resource_hygiene": {"score": 80},
    }


# ----------------------------------------------------- machine identity


def test_same_machine_id_flags_longitudinal() -> None:
    """The headline A5 question: are these runs from the same box?"""
    view = build_cross_run_view([
        _run(run_id="A", machine_id="MACHINE-deadbeef",
             machine_id_source="smbios_uuid"),
        _run(run_id="B", machine_id="MACHINE-deadbeef",
             machine_id_source="smbios_uuid"),
        _run(run_id="C", machine_id="MACHINE-deadbeef",
             machine_id_source="smbios_uuid"),
    ])
    assert view["same_machine"] is True
    assert len(view["machine_ids"]) == 3
    assert all(m["machine_id"] == "MACHINE-deadbeef"
               for m in view["machine_ids"])


def test_different_machine_ids_flag_not_same_machine() -> None:
    view = build_cross_run_view([
        _run(run_id="A", machine_id="MACHINE-aaaaaaaa"),
        _run(run_id="B", machine_id="MACHINE-bbbbbbbb"),
    ])
    assert view["same_machine"] is False


def test_missing_machine_id_on_any_run_blocks_same_machine() -> None:
    """Old-format runs (M5 not yet shipped when they ran) MUST
    fall back to "unknown" rather than falsely claiming sameness."""
    view = build_cross_run_view([
        _run(run_id="A", machine_id="MACHINE-deadbeef"),
        _run(run_id="B", machine_id=None),
    ])
    assert view["same_machine"] is False


# ----------------------------------------------------- shared metadata


def test_shared_meta_only_when_all_runs_agree() -> None:
    view = build_cross_run_view([
        _run(run_id="A", meta={"department": "engineering",
                               "ticket": "PERF-1234"}),
        _run(run_id="B", meta={"department": "engineering",
                               "ticket": "PERF-9999"}),  # different
    ])
    assert view["shared_meta"] == {"department": "engineering"}
    assert "ticket" not in view["shared_meta"]


def test_shared_meta_empty_when_no_agreement() -> None:
    view = build_cross_run_view([
        _run(run_id="A", meta={"department": "eng"}),
        _run(run_id="B", meta={"department": "support"}),
    ])
    assert view["shared_meta"] == {}


def test_shared_machine_class_extracted_when_all_agree() -> None:
    view = build_cross_run_view([
        _run(run_id="A", meta={"machine_class": "kiosk"}),
        _run(run_id="B", meta={"machine_class": "kiosk"}),
    ])
    assert view["shared_machine_class"] == "kiosk"


def test_shared_machine_class_none_when_disagree() -> None:
    view = build_cross_run_view([
        _run(run_id="A", meta={"machine_class": "kiosk"}),
        _run(run_id="B", meta={"machine_class": "developer-workstation"}),
    ])
    assert view["shared_machine_class"] is None


def test_shared_capture_profile_extracted() -> None:
    view = build_cross_run_view([
        _run(run_id="A", meta={"capture_profile": "av-overhead"}),
        _run(run_id="B", meta={"capture_profile": "av-overhead"}),
    ])
    assert view["shared_capture_profile"] == "av-overhead"


# ----------------------------------------------------- tail-window alignment


def test_tail_window_picks_largest_common() -> None:
    """All runs have last_1h, only some have last_8h → pick last_1h."""
    view = build_cross_run_view([
        _run(run_id="A",
             tail_windows=[_tw("last_1h"), _tw("last_8h")]),
        _run(run_id="B",
             tail_windows=[_tw("last_1h")]),
    ])
    assert view["tail_window_view"]["common_window_label"] == "last_1h"
    rows = view["tail_window_view"]["rows"]
    assert len(rows) == 2
    assert all(r["window_label"] == "last_1h" for r in rows)


def test_tail_window_picks_widest_when_all_have_both() -> None:
    """Both runs have last_8h → pick last_8h (more comparable data)."""
    view = build_cross_run_view([
        _run(run_id="A",
             tail_windows=[_tw("last_1h"), _tw("last_8h")]),
        _run(run_id="B",
             tail_windows=[_tw("last_1h"), _tw("last_8h")]),
    ])
    assert view["tail_window_view"]["common_window_label"] == "last_8h"


def test_tail_window_none_when_any_run_lacks_it() -> None:
    """Short run mixed with long run — no common tail."""
    view = build_cross_run_view([
        _run(run_id="A", tail_windows=[_tw("last_1h")]),
        _run(run_id="B", tail_windows=[]),     # too short
    ])
    assert view["tail_window_view"]["common_window_label"] is None
    assert view["tail_window_view"]["rows"] == []


def test_tail_window_row_carries_score_axes() -> None:
    view = build_cross_run_view([
        _run(run_id="A", tail_windows=[_tw("last_1h", overall=82)]),
        _run(run_id="B", tail_windows=[_tw("last_1h", overall=68)]),
    ])
    rows = view["tail_window_view"]["rows"]
    assert rows[0]["overall"] == 82
    assert rows[1]["overall"] == 68
    for r in rows:
        for axis in ("stability", "efficiency", "workload_suitability",
                     "network_impact", "resource_hygiene"):
            assert axis in r


# ----------------------------------------------------- baseline deviations


def test_common_baseline_deviations_require_all_runs() -> None:
    """A deviation present in 2 of 3 runs is NOT common."""
    dev_kiosk_cpu = {
        "machine_class": "kiosk", "metric": "cpu_total_pct_mean",
        "actual": 25, "severity": "high",
    }
    dev_kiosk_mem = {
        "machine_class": "kiosk", "metric": "mem_percent_mean",
        "actual": 70, "severity": "medium",
    }
    view = build_cross_run_view([
        _run(run_id="A", baseline_deviations=[dev_kiosk_cpu, dev_kiosk_mem]),
        _run(run_id="B", baseline_deviations=[dev_kiosk_cpu]),
        _run(run_id="C", baseline_deviations=[dev_kiosk_cpu, dev_kiosk_mem]),
    ])
    common = view["baseline_deviations"]["common"]
    # Only the CPU deviation appears in ALL three.
    assert common == [{"machine_class": "kiosk",
                       "metric": "cpu_total_pct_mean"}]


def test_per_run_baseline_deviations_preserved() -> None:
    """The per-run details stay accessible — common is just an index."""
    devs_a = [{"machine_class": "kiosk", "metric": "cpu_total_pct_mean"}]
    devs_b = [{"machine_class": "kiosk", "metric": "mem_percent_mean"}]
    view = build_cross_run_view([
        _run(run_id="A", baseline_deviations=devs_a),
        _run(run_id="B", baseline_deviations=devs_b),
    ])
    assert view["baseline_deviations"]["per_run"]["A"] == devs_a
    assert view["baseline_deviations"]["per_run"]["B"] == devs_b
    assert view["baseline_deviations"]["common"] == []


# ----------------------------------------------------- edge cases


def test_empty_input_returns_empty_view() -> None:
    view = build_cross_run_view([])
    assert view["same_machine"] is False
    assert view["machine_ids"] == []
    assert view["shared_meta"] == {}
    assert view["tail_window_view"]["common_window_label"] is None
    assert view["baseline_deviations"]["common"] == []
