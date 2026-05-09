"""v3-priority-6 (A6): cap-window-aware comparison alignment.

The v2 production review made this priority urgent: the comparison
engine consumes raw scores computed over the full run window. ATLT4407
(902 s) vs MORGANA (1469 s) gives MORGANA a free advantage on every
"average over time" metric — it integrates over a 62 % longer window.

These tests pin the alignment layer that defends against that:

- pick the largest tail window every run can produce
- fall back to None when at least one run is too short, so callers
  know to surface a "length-bias" caveat
- aligned rankings prefer scores from the chosen window so headline
  verdicts (best_overall, most_stable, best_efficiency) are
  length-fair
- back-compat path: legacy runs without `tail_windows` block surface
  as `no_data`, runs that are merely too short surface as `too_short`
"""

from __future__ import annotations

from sysspecter.comparer.window_alignment import (
    aligned_rankings,
    aligned_score,
    build_aligned_view,
    detect_aligned_window,
)


def _run(
    run_id: str, *,
    tail_windows: list[dict] | None = None,
    duration_s: float = 1000.0,
    hostname: str | None = None,
) -> dict:
    """Build a minimal `loaded` entry shaped like comparer/loader output."""
    scores: dict = {}
    if tail_windows is not None:
        scores["tail_windows"] = tail_windows
    return {
        "manifest": {
            "run_id": run_id,
            "hostname": hostname or run_id,
            "duration_actual_seconds": duration_s,
        },
        "scores": scores,
        "findings": {},
        "rd": None,
    }


def _tail_block(
    label: str = "last_1h",
    *,
    overall: float = 80.0,
    stability: float = 75.0,
    efficiency: float = 78.0,
    workload: float = 70.0,
    network: float = 90.0,
    hygiene: float = 85.0,
    samples: int = 3500,
    duration_s: float = 3600.0,
) -> dict:
    """Mirror the shape produced by analyzer/scores.compute_tail_window_scores."""
    return {
        "window_label": label,
        "window_duration_seconds": duration_s,
        "window_samples": samples,
        "overall": overall,
        # Sub-scores nest the value under `.score`, matching scores.json shape.
        "stability": {"score": stability},
        "efficiency": {"score": efficiency},
        "workload_suitability": {"score": workload},
        "network_impact": {"score": network},
        "resource_hygiene": {"score": hygiene},
    }


# --- detect_aligned_window -----------------------------------------

def test_detect_aligned_window_picks_widest_common() -> None:
    """When all runs have last_1h AND last_8h, prefer last_8h (wider)."""
    loaded = [
        _run("a", tail_windows=[_tail_block("last_1h"), _tail_block("last_8h")]),
        _run("b", tail_windows=[_tail_block("last_1h"), _tail_block("last_8h")]),
    ]
    assert detect_aligned_window(loaded) == "last_8h"


def test_detect_aligned_window_falls_back_to_smaller_when_only_some_have_8h() -> None:
    """If A has both windows but B only has last_1h, last_1h is the
    widest the cohort can support."""
    loaded = [
        _run("a", tail_windows=[_tail_block("last_1h"), _tail_block("last_8h")]),
        _run("b", tail_windows=[_tail_block("last_1h")]),
    ]
    assert detect_aligned_window(loaded) == "last_1h"


def test_detect_aligned_window_returns_none_when_one_run_too_short() -> None:
    """ATLT4407 was 902 s — too short for a 1 h window. Without a
    common tail window, the score-based rankings should NOT be
    silently length-biased."""
    loaded = [
        _run("ATLT4407", tail_windows=[]),
        _run("MORGANA", tail_windows=[_tail_block("last_1h")]),
    ]
    assert detect_aligned_window(loaded) is None


def test_detect_aligned_window_returns_none_for_legacy_runs() -> None:
    """Pre-A6 runs have no tail_windows block at all."""
    loaded = [_run("a"), _run("b")]
    assert detect_aligned_window(loaded) is None


def test_detect_aligned_window_returns_none_for_single_run() -> None:
    """One run can't be 'aligned' with itself — return None so the
    caller doesn't claim cap-window framing on a degenerate input."""
    loaded = [_run("solo", tail_windows=[_tail_block("last_1h")])]
    assert detect_aligned_window(loaded) is None


# --- aligned_score -------------------------------------------------

def test_aligned_score_pulls_overall_from_correct_window() -> None:
    scores = {"tail_windows": [
        _tail_block("last_1h", overall=70.0),
        _tail_block("last_8h", overall=85.0),
    ]}
    assert aligned_score(scores, "last_8h", "overall") == 85.0
    assert aligned_score(scores, "last_1h", "overall") == 70.0


def test_aligned_score_resolves_subscore_score_field() -> None:
    """Sub-scores (stability/efficiency/...) nest the value under `.score`."""
    scores = {"tail_windows": [_tail_block("last_1h", efficiency=92.0)]}
    assert aligned_score(scores, "last_1h", "efficiency") == 92.0


def test_aligned_score_returns_none_for_missing_window() -> None:
    scores = {"tail_windows": [_tail_block("last_1h")]}
    assert aligned_score(scores, "last_8h", "overall") is None


def test_aligned_score_returns_none_for_missing_block() -> None:
    """Legacy run with no tail_windows."""
    assert aligned_score({}, "last_1h", "overall") is None


# --- build_aligned_view --------------------------------------------

def test_build_aligned_view_emits_aligned_status_when_window_present() -> None:
    loaded = [
        _run("a", tail_windows=[_tail_block("last_1h", overall=80.0)]),
        _run("b", tail_windows=[_tail_block("last_1h", overall=72.0)]),
    ]
    view = build_aligned_view(loaded, "last_1h")
    assert view["window_label"] == "last_1h"
    assert view["window_duration_seconds"] == 3600.0
    assert len(view["rows"]) == 2
    assert all(r["alignment_status"] == "aligned" for r in view["rows"])
    assert {r["run_id"] for r in view["rows"]} == {"a", "b"}


def test_build_aligned_view_marks_too_short_when_run_lacks_window() -> None:
    """A run that has tail_windows but not the requested label is
    'too_short' — it ran, but not long enough."""
    loaded = [
        _run("ok", tail_windows=[_tail_block("last_1h")]),
        _run("short", tail_windows=[_tail_block("last_1h")], duration_s=400.0),
    ]
    view = build_aligned_view(loaded, "last_8h")
    statuses = {r["run_id"]: r["alignment_status"] for r in view["rows"]}
    assert statuses == {"ok": "too_short", "short": "too_short"}


def test_build_aligned_view_marks_no_data_for_legacy_runs() -> None:
    """A run with no tail_windows block at all is pre-A6 — distinct
    from 'too_short' so consumers can tell which runs are legacy."""
    loaded = [
        _run("modern", tail_windows=[_tail_block("last_1h")]),
        _run("legacy"),  # no tail_windows
    ]
    view = build_aligned_view(loaded, "last_1h")
    statuses = {r["run_id"]: r["alignment_status"] for r in view["rows"]}
    assert statuses == {"modern": "aligned", "legacy": "no_data"}


def test_build_aligned_view_with_none_window_returns_no_data_rows() -> None:
    loaded = [_run("a", tail_windows=[_tail_block("last_1h")])]
    view = build_aligned_view(loaded, None)
    assert view["window_label"] is None
    assert view["rows"][0]["alignment_status"] == "no_data"


# --- aligned_rankings ----------------------------------------------

def test_aligned_rankings_orders_runs_by_window_score() -> None:
    """When 'a' wins overall on the aligned window but 'b' has a
    higher full-run score, the aligned ranking still picks 'a'."""
    loaded = [
        _run("a", tail_windows=[_tail_block("last_1h", overall=80.0)]),
        _run("b", tail_windows=[_tail_block("last_1h", overall=70.0)]),
    ]
    ranks = aligned_rankings(loaded, "last_1h")
    assert ranks["best_overall"][0][0] == "a"
    assert ranks["best_overall"][1][0] == "b"


def test_aligned_rankings_skips_runs_without_window() -> None:
    """A short run that doesn't have the aligned window is excluded
    from rankings rather than dragged in as missing data."""
    loaded = [
        _run("short", tail_windows=[]),
        _run("long", tail_windows=[_tail_block("last_1h", overall=85.0)]),
    ]
    ranks = aligned_rankings(loaded, "last_1h")
    assert ranks["best_overall"] == [("long", 85.0)]


def test_aligned_rankings_returns_empty_when_no_window() -> None:
    """Caller falls back to raw rankings."""
    loaded = [_run("a"), _run("b")]
    assert aligned_rankings(loaded, None) == {}


def test_aligned_rankings_covers_all_score_metrics() -> None:
    """All six score-based rankings should be populated."""
    loaded = [
        _run("a", tail_windows=[_tail_block("last_1h",
                                             overall=80, stability=75,
                                             efficiency=78, workload=70,
                                             network=90, hygiene=85)]),
        _run("b", tail_windows=[_tail_block("last_1h",
                                             overall=70, stability=80,
                                             efficiency=72, workload=85,
                                             network=88, hygiene=80)]),
    ]
    ranks = aligned_rankings(loaded, "last_1h")
    assert set(ranks.keys()) == {
        "best_overall", "best_stability", "best_efficiency",
        "best_workload", "best_network", "best_hygiene",
    }
    # 'a' wins overall + efficiency + network + hygiene; 'b' wins
    # stability + workload.
    assert ranks["best_overall"][0][0] == "a"
    assert ranks["best_stability"][0][0] == "b"
    assert ranks["best_workload"][0][0] == "b"


# --- ATLT4407-vs-MORGANA case --------------------------------------

def test_atlt4407_too_short_means_no_aligned_window() -> None:
    """The exact v2 case: ATLT4407 is 902 s (no canonical tail window
    fits) and MORGANA is 1469 s (last_1h fits). Cohort can't be aligned."""
    loaded = [
        _run("ATLT4407", tail_windows=[], duration_s=902.0),
        _run("MORGANA", tail_windows=[_tail_block("last_1h")], duration_s=1469.0),
    ]
    assert detect_aligned_window(loaded) is None


def test_two_runs_both_long_enough_for_1h_alignment() -> None:
    """If both runs are >= 1 h, last_1h is the cap-fair frame.
    MORGANA's 1469 s isn't enough for 1 h either — but a hypothetical
    pair of 2-hour runs would pass. Pin the happy case for completeness."""
    loaded = [
        _run("a", tail_windows=[_tail_block("last_1h", overall=82.0)]),
        _run("b", tail_windows=[_tail_block("last_1h", overall=79.0)]),
    ]
    assert detect_aligned_window(loaded) == "last_1h"
    view = build_aligned_view(loaded, "last_1h")
    assert all(r["alignment_status"] == "aligned" for r in view["rows"])
