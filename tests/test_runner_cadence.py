"""v3-priority-1 (S1+S3): runner cadence-quality summarisation.

The v2 production-test review showed the sampler silently drifted to
1/18 Hz on a weak host while the manifest still claimed 1 Hz. The
fix is two-fold: (a) write the actual gaps into the CSV (covered in
test_collector_system_sampler) and (b) summarise the run's cadence
into a manifest block so consumers — especially the cross-run
comparison engine — can refuse comparisons across heterogeneous
cadence quality.

These tests pin the math of the summariser and the empty-input edge
case. The HIGH_PRIORITY_CLASS path is a soft-degrade and only
exercised on Windows; we test that calling it on non-Windows returns
"UNCHANGED" without raising.
"""

from __future__ import annotations

import sys

from sysspecter.collector.runner import (
    _percentile,
    _set_high_priority_class,
    _summarise_cadence,
)

# --- _percentile ----------------------------------------------------

def test_percentile_empty_list_returns_zero() -> None:
    assert _percentile([], 50.0) == 0.0


def test_percentile_endpoints_clamp() -> None:
    s = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert _percentile(s, 0.0) == 1.0
    assert _percentile(s, 100.0) == 5.0
    # Below 0 clamps to first; above 100 clamps to last.
    assert _percentile(s, -10.0) == 1.0
    assert _percentile(s, 200.0) == 5.0


def test_percentile_median_on_odd_list() -> None:
    s = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert _percentile(s, 50.0) == 3.0


def test_percentile_p95_interpolates() -> None:
    s = list(range(1, 101))  # 1..100
    # rank = 0.95 * 99 = 94.05 -> between index 94 (=95) and 95 (=96)
    p95 = _percentile([float(x) for x in s], 95.0)
    assert 95.0 <= p95 <= 96.0


# --- _summarise_cadence --------------------------------------------

def test_summarise_cadence_no_data_path() -> None:
    """Edge case: a run that produced 0 or 1 sample has no real gaps."""
    out = _summarise_cadence(1.0, [])
    assert out["cadence_health"] == "no_data"
    assert out["samples_total"] == 0
    assert out["median_gap_seconds"] == 0.0


def test_summarise_cadence_good_run_on_target() -> None:
    """1 Hz nominal, gaps tightly around 1 s -> health=good."""
    gaps = [0.0] + [1.0 + 0.05 * i for i in range(-3, 4)]  # 0.85..1.15
    out = _summarise_cadence(1.0, gaps)
    assert out["cadence_health"] == "good"
    assert 0.95 <= out["median_gap_seconds"] <= 1.05
    assert out["gaps_over_2x_nominal"] == 0
    assert out["samples_total"] == 8  # 7 real gaps + 1 first sample


def test_summarise_cadence_atlt4407_pattern_is_broken() -> None:
    """Reproduces the ATLT4407 production observation: nominal 1 s,
    actual gaps clustered at 13–30 s. Must report cadence_health=broken
    and surface the over-thresholds counts."""
    # 50 gaps in the 13–30 s range, mimicking the production observation.
    gaps = [0.0] + [13.0 + (i % 18) for i in range(50)]
    out = _summarise_cadence(1.0, gaps)
    assert out["cadence_health"] == "broken"
    assert out["median_gap_seconds"] >= 13.0
    assert out["gaps_over_2x_nominal"] == 50
    assert out["gaps_over_5x_nominal"] == 50
    # ratio of median to nominal is well above 3x
    assert out["ratio_median_to_nominal"] >= 13.0


def test_summarise_cadence_intermediate_run_is_degraded() -> None:
    """Median gap 2 s on a 1 s nominal -> health=degraded (between
    good and broken)."""
    gaps = [0.0] + [2.0 for _ in range(20)]
    out = _summarise_cadence(1.0, gaps)
    assert out["cadence_health"] == "degraded"
    assert out["ratio_median_to_nominal"] == 2.0


def test_summarise_cadence_first_sample_zero_gap_is_filtered() -> None:
    """The first sample's gap is 0.0 (no predecessor). The summariser
    must NOT count it as a real gap — otherwise the median is biased
    towards 0 on tiny runs."""
    # 5 real gaps at 1 s, plus a leading 0.0 from the first sample
    gaps = [0.0, 1.0, 1.0, 1.0, 1.0, 1.0]
    out = _summarise_cadence(1.0, gaps)
    assert out["median_gap_seconds"] == 1.0
    assert out["samples_total"] == 6  # 5 real + 1 first


def test_summarise_cadence_max_gap_reflects_outliers() -> None:
    """A single 30 s spike must surface in max_gap_seconds even when
    most gaps are good (so the comparison engine can downgrade
    confidence)."""
    gaps = [0.0] + [1.0 for _ in range(99)] + [30.0]
    out = _summarise_cadence(1.0, gaps)
    assert out["max_gap_seconds"] == 30.0
    assert out["gaps_over_5x_nominal"] == 1


# --- _set_high_priority_class --------------------------------------

class _FakeLogger:
    def __init__(self) -> None:
        self.records: list[tuple[str, str]] = []

    def info(self, msg: str, *args) -> None:
        self.records.append(("info", msg % args if args else msg))

    def warning(self, msg: str, *args) -> None:
        self.records.append(("warning", msg % args if args else msg))


def test_set_high_priority_class_non_windows_is_unchanged() -> None:
    """On non-Windows the call must short-circuit to "UNCHANGED" without
    touching ctypes. We can't test this on a Windows test runner directly,
    but we can stub sys.platform via a minimal monkey-patch."""
    log = _FakeLogger()
    original = sys.platform
    try:
        sys.platform = "linux"  # type: ignore[misc]
        result = _set_high_priority_class(log)
    finally:
        sys.platform = original  # type: ignore[misc]
    assert result == "UNCHANGED"


def test_set_high_priority_class_records_outcome_on_windows() -> None:
    """On Windows the call must return one of the documented strings.
    On a healthy CI host it'll usually be HIGH or ABOVE_NORMAL; on a
    locked-down host it might be NORMAL or UNCHANGED. All four are
    valid; the contract is that the return is one of them and never
    raises."""
    if sys.platform != "win32":
        return  # Non-Windows path covered in the test above.
    log = _FakeLogger()
    result = _set_high_priority_class(log)
    assert result in {"HIGH", "ABOVE_NORMAL", "NORMAL", "UNCHANGED"}
