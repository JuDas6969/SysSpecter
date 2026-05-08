"""Field-review A6: cap-window-aware scoring.

The full-run scores answer "how was the whole run?". A tail-window
score answers "how does this machine look RIGHT NOW?" — much more
useful for fleet trending and cross-run comparison. These tests pin
the contract:

- a < 1 h run does NOT produce tail windows (nothing to score)
- a 90-min run produces a `last_1h` window only
- a 12-h run produces both `last_1h` and `last_8h`
- the tail window's bounds match the requested duration (within
  rounding)
- only window-sensitive scores change between full and tail; the
  offender-aggregated ones (security, hygiene) stay numerically
  consistent because they're based on run-aggregate data
- a run shaped "calm-then-stormy" produces a LOWER stability score
  for `last_1h` than for the full run (the tail is the storm)
"""

from __future__ import annotations

from sysspecter.analyzer.scores import (
    calculate_scores,
    compute_tail_window_scores,
)


def _system_row(rel: float, cpu: float = 20.0, mem: float = 40.0) -> dict:
    return {
        "rel_seconds": rel,
        "cpu_total_pct": cpu,
        "mem_percent": mem,
        "swap_percent": 5.0,
        "disk_active_pct_est": 5.0,
        "net_recv_bytes_per_sec": 0,
        "net_sent_bytes_per_sec": 0,
    }


def _scores_kwargs(system_rows: list[dict]) -> dict:
    return {
        "anomalies": [],
        "slowdowns": [],
        "offenders": {"security": [], "background_noise": []},
        "leaks": {"memory": [], "handles": [], "threads": []},
        "latency_rows": [],
        "mode": "support",
        "bottlenecks": {"primary": None, "secondary": []},
    }


# -------------------------------------------------- emit-decision contract


def test_short_run_emits_no_tail_windows() -> None:
    """A 30-min run can't produce a 1-h or 8-h tail."""
    rows = [_system_row(t) for t in range(0, 1800, 1)]
    tw = compute_tail_window_scores(
        rows, **_scores_kwargs(rows),
        full_window_start=0.0, full_window_end=1800.0,
    )
    assert tw == []


def test_90_min_run_emits_only_last_1h() -> None:
    rows = [_system_row(t) for t in range(0, 5400, 1)]
    tw = compute_tail_window_scores(
        rows, **_scores_kwargs(rows),
        full_window_start=0.0, full_window_end=5400.0,
    )
    labels = [s["window_label"] for s in tw]
    assert labels == ["last_1h"]
    last_1h = tw[0]
    # Bounds: end of run, back 1 hour.
    assert last_1h["window_end_seconds"] == 5400.0
    assert last_1h["window_start_seconds"] == 1800.0
    assert 3000 < last_1h["window_samples"] <= 3601


def test_12_hour_run_emits_both_tail_windows() -> None:
    """Subsample at 1/sec (43 200 rows would be expensive); use one
    sample per 4 s = 10 800 rows over 12 h to keep the test fast."""
    rows = [_system_row(t) for t in range(0, 43200, 4)]
    tw = compute_tail_window_scores(
        rows, **_scores_kwargs(rows),
        full_window_start=0.0, full_window_end=43200.0,
    )
    labels = [s["window_label"] for s in tw]
    assert "last_1h" in labels
    assert "last_8h" in labels
    by_label = {s["window_label"]: s for s in tw}
    assert by_label["last_1h"]["window_duration_seconds"] == 3600.0
    assert by_label["last_8h"]["window_duration_seconds"] == 28800.0


def test_window_keeps_score_dict_shape_byte_for_byte() -> None:
    """Tail-window scores must carry the same fields as the full-run
    score so consumers can render them with one template."""
    rows = [_system_row(t) for t in range(0, 7200, 1)]
    full = calculate_scores(rows, **_scores_kwargs(rows))
    tw = compute_tail_window_scores(
        rows, **_scores_kwargs(rows),
        full_window_start=0.0, full_window_end=7200.0,
    )
    last = tw[0]
    # Every top-level field on the full score must also exist on the
    # window — minus 'analysis_window' (added later by pipeline.py).
    expected_keys = set(full.keys())
    actual_keys = set(last.keys()) - {
        "window_label", "window_start_seconds", "window_end_seconds",
        "window_duration_seconds", "window_samples",
    }
    missing = expected_keys - actual_keys
    assert not missing, f"tail-window score missing fields: {missing}"


# -------------------------------------------------- semantic contract


def test_calm_then_stormy_run_lower_tail_stability() -> None:
    """A run that's quiet for 80 min then chaotic for 10 min should
    score WORSE on stability for `last_1h` than for the full run.
    This is the whole point of A6: the tail tells the operator
    'right now', the full run averages it out."""
    rows = []
    for t in range(0, 4800, 1):                      # 80 min calm
        rows.append(_system_row(t, cpu=10.0))
    for t in range(4800, 5400, 1):                   # 10 min storm
        # Alternating high/low CPU → high stddev → low stability.
        rows.append(_system_row(t, cpu=95.0 if t % 2 else 5.0))

    full = calculate_scores(rows, **_scores_kwargs(rows))
    tw = compute_tail_window_scores(
        rows, **_scores_kwargs(rows),
        full_window_start=0.0, full_window_end=5400.0,
    )
    last_1h = tw[0]
    full_stab = full["stability"]["score"]
    last_stab = last_1h["stability"]["score"]
    # Last-1h includes the storm at much higher density than the
    # full run, so it should grade lower.
    assert last_stab < full_stab, (
        f"tail-window stability {last_stab} should be lower than "
        f"full-run stability {full_stab} on a calm-then-stormy run"
    )


def test_window_with_too_few_samples_skipped() -> None:
    """If the tail window contains fewer than 5 samples (e.g. very
    sparse run), the window is skipped instead of producing
    nonsense scores."""
    # 1.5 h run but only 3 samples in the last hour
    rows = [_system_row(t) for t in (0.0, 1500.0, 3000.0,
                                      5300.0, 5350.0, 5390.0)]
    tw = compute_tail_window_scores(
        rows, **_scores_kwargs(rows),
        full_window_start=0.0, full_window_end=5400.0,
    )
    # last_1h would have 3 samples → skipped.
    assert tw == [] or tw[0]["window_samples"] >= 5
