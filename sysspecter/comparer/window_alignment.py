"""v3-priority-6 (A6): cap-window-aware comparison alignment.

The v2 production review made this priority urgent: the comparison
engine consumes raw scores that are computed over the full run
window. ATLT4407 (902 s) vs MORGANA (1469 s) gives MORGANA an
intrinsic advantage on every "average over time" metric — it
integrates over a 62 % longer window. Any verdict like "MORGANA is
more efficient" is biased by length before it reflects true
behaviour.

The fix already partially exists: `analyzer/scores.compute_tail_window_scores`
emits canonical tail-window blocks (`last_1h`, `last_8h`) per run.
What was missing: the comparison engine never used them. This
module is that missing layer.

Public API:

    detect_aligned_window(loaded) -> str | None
        Largest common tail window across all runs. None when at
        least one run is too short (< 1 h) or when tail-window
        data is absent (legacy run pre-A6).

    build_aligned_view(loaded, window_label) -> dict
        Per-run scoring at the aligned window. Same shape the
        matrix expects, so downstream code can swap raw rankings
        for aligned ones without restructuring.

    aligned_score(scores, window_label, key) -> float | None
        Single-cell lookup — used by matrix.py + rankings.

    annotate_rankings_with_window(rankings, loaded, window_label)
        Returns parallel rankings computed against the aligned
        window. Preserves the original `rankings` so the report
        can show "raw" vs "cap-window-aligned" side by side when
        the analyst wants to verify the methodology.

The point: refuse to take the apparent winner of a length-biased
comparison at face value. Either we have a common cap window
(use it) or we don't (downgrade confidence on length-sensitive
metrics, same way cadence-quality already does in priority 2).
"""

from __future__ import annotations

from typing import Any

# Tail windows in widest-first order so we pick the largest the
# whole cohort can support. Mirrors `_TAIL_WINDOWS_S` in
# analyzer/scores.py — keep in sync.
_WINDOW_PRIORITY: tuple[str, ...] = ("last_8h", "last_1h")


def _tail_blocks(scores: dict[str, Any]) -> list[dict[str, Any]]:
    return list(scores.get("tail_windows") or [])


def detect_aligned_window(loaded: list[dict[str, Any]]) -> str | None:
    """Pick the widest tail window every loaded run can produce.

    Returns the window label (e.g. `"last_1h"`) or None when at
    least one run is too short. Single source of truth so the
    matrix, rankings and report all agree on the comparison frame.
    """
    if len(loaded) < 2:
        return None
    score_blocks = [r.get("scores") or {} for r in loaded]
    for label in _WINDOW_PRIORITY:
        if all(
            any(tw.get("window_label") == label for tw in _tail_blocks(s))
            for s in score_blocks
        ):
            return label
    return None


def aligned_score(
    scores: dict[str, Any],
    window_label: str,
    key: str,
) -> float | None:
    """Look up one score field at the aligned tail window.

    `key` follows the schema used elsewhere in the comparer:
    `"overall"` / `"stability"` / `"efficiency"` / etc. The
    sub-score schema nests the value under `.score`, e.g.
    `tail.stability.score`. We handle both shapes.
    """
    if not window_label:
        return None
    for tw in _tail_blocks(scores):
        if tw.get("window_label") != window_label:
            continue
        v = tw.get(key)
        if isinstance(v, dict):
            v = v.get("score")
        if v is None:
            return None
        try:
            return float(v)
        except (TypeError, ValueError):
            return None
    return None


def aligned_score_for_run_id(
    loaded: list[dict[str, Any]],
    run_id: str,
    window_label: str,
    key: str,
) -> float | None:
    for r in loaded:
        m = r.get("manifest") or {}
        if m.get("run_id") != run_id:
            continue
        return aligned_score(r.get("scores") or {}, window_label, key)
    return None


# Window-label → seconds mapping (mirrors analyzer/scores._TAIL_WINDOWS_S).
_WINDOW_SECONDS: dict[str, float] = {
    "last_1h": 3600.0,
    "last_8h": 28800.0,
}


def _compute_window_score_from_raw(
    r: dict[str, Any], window_label: str,
) -> dict[str, Any] | None:
    """v1.3.0 B.3: when a run's `scores.tail_windows` doesn't include
    the requested window, re-compute it from the raw timeline +
    findings. Returns the same shape as a pre-computed tail-window
    block (so the caller treats both paths identically), or None when
    the run doesn't have enough data.

    Re-uses `analyzer/scores.compute_tail_window_scores` so the
    formulas are byte-identical to the per-run path. No duplicated
    score logic.
    """
    rd = r.get("rd")
    findings = r.get("findings") or {}
    manifest = r.get("manifest") or {}
    if rd is None:
        return None
    system_rows = getattr(rd, "system_rows", None) or []
    latency_rows = getattr(rd, "latency_rows", None) or []
    if not system_rows:
        return None
    duration = manifest.get("duration_actual_seconds") or 0.0
    try:
        duration = float(duration)
    except (TypeError, ValueError):
        duration = 0.0
    if duration <= 0:
        # Try to derive from the timeline directly.
        try:
            duration = float(system_rows[-1].get("rel_seconds") or 0.0)
        except (TypeError, ValueError):
            duration = 0.0
    if duration < _WINDOW_SECONDS.get(window_label, 1e9):
        return None
    try:
        from ..analyzer.scores import compute_tail_window_scores
    except ImportError:
        return None
    blocks = compute_tail_window_scores(
        system_rows,
        findings.get("anomalies") or [],
        findings.get("slowdowns") or [],
        findings.get("offenders") or {},
        findings.get("leaks") or {},
        latency_rows,
        manifest.get("mode") or "support",
        findings.get("bottlenecks") or {},
        full_window_start=0.0,
        full_window_end=duration,
    )
    for block in blocks:
        if block.get("window_label") == window_label:
            return block
    return None


def build_aligned_view(
    loaded: list[dict[str, Any]],
    window_label: str | None,
) -> dict[str, Any]:
    """Build per-run scores at the aligned window plus a comparison-
    framing summary the report can show as a banner.

    Output:
        {
            "window_label": "last_1h" | None,
            "window_duration_seconds": float | None,
            "rows": [
                {
                    "run_id": ..., "hostname": ...,
                    "overall": float | None,
                    "stability": float | None,
                    "efficiency": float | None,
                    "workload": float | None,
                    "network": float | None,
                    "hygiene": float | None,
                    "samples_in_window": int | None,
                    "alignment_status": "aligned" | "too_short"
                                      | "empty" | "no_data",
                },
                ...
            ],
        }

    `alignment_status` is per-run:
      - `aligned`    — block found (pre-computed in scores.json OR
                        freshly computed from rd timeline in v1.3.0
                        B.3 fallback).
      - `too_short`  — duration < requested window.
      - `empty`      — 0 samples (run captured nothing).
      - `no_data`    — pre-v1.0 run with no usable timeline / no
                        scores data at all.

    With a `None` window the rows are still emitted with empty score
    fields so the report can render a "no common window" panel.
    """
    rows: list[dict[str, Any]] = []
    duration: float | None = None
    for r in loaded:
        m = r.get("manifest") or {}
        s = r.get("scores") or {}
        run_id = m.get("run_id") or "?"
        hostname = m.get("hostname")
        actual = m.get("duration_actual_seconds") or 0.0
        if window_label is None:
            rows.append({
                "run_id": run_id,
                "hostname": hostname,
                "overall": None,
                "stability": None,
                "efficiency": None,
                "workload": None,
                "network": None,
                "hygiene": None,
                "samples_in_window": None,
                "alignment_status": "no_data",
            })
            continue
        block = next(
            (tw for tw in _tail_blocks(s)
             if tw.get("window_label") == window_label),
            None,
        )
        if block is None:
            # v1.3.0 B.3: try the fresh-compute fallback before
            # giving up. This covers runs captured before A6 shipped
            # (tail_windows absent) and runs where the analyzer
            # didn't emit the block (rare).
            block = _compute_window_score_from_raw(r, window_label)
        if block is None:
            # Distinguish the failure modes so the report can be
            # honest about WHY a row is empty.
            #   `empty`     — rd present, 0 system rows captured.
            #   `too_short` — has SOME pre-computed tail-window block
            #                  but not this label; OR duration < window.
            #   `no_data`   — pre-A6 / pre-v1.3 run with no tail_windows
            #                  AND no usable timeline (rd absent).
            rd = r.get("rd")
            window_len = _WINDOW_SECONDS.get(window_label, 0)
            try:
                actual_f = float(actual)
            except (TypeError, ValueError):
                actual_f = 0.0
            samples = (
                len(getattr(rd, "system_rows", None) or [])
                if rd is not None else 0
            )
            has_some_tail_windows = bool(_tail_blocks(s))

            if rd is not None and samples == 0:
                status = "empty"
            elif rd is None and not has_some_tail_windows:
                # No timeline AND no tail_windows = pre-A6 legacy run.
                status = "no_data"
            elif has_some_tail_windows:
                # Has tail_windows but not THIS one → too_short
                # (e.g. has last_1h, was asked for last_8h).
                status = "too_short"
            elif actual_f > 0 and actual_f < window_len:
                status = "too_short"
            else:
                status = "no_data"
            rows.append({
                "run_id": run_id,
                "hostname": hostname,
                "overall": None,
                "stability": None,
                "efficiency": None,
                "workload": None,
                "network": None,
                "hygiene": None,
                "samples_in_window": None,
                "alignment_status": status,
                "actual_duration_seconds": actual,
            })
            continue
        if duration is None:
            d = block.get("window_duration_seconds")
            try:
                duration = float(d) if d is not None else None
            except (TypeError, ValueError):
                duration = None
        rows.append({
            "run_id": run_id,
            "hostname": hostname,
            "overall": _coerce_score(block.get("overall")),
            "stability": _coerce_score(_dig(block, "stability")),
            "efficiency": _coerce_score(_dig(block, "efficiency")),
            "workload": _coerce_score(_dig(block, "workload_suitability")),
            "network": _coerce_score(_dig(block, "network_impact")),
            "hygiene": _coerce_score(_dig(block, "resource_hygiene")),
            "samples_in_window": block.get("window_samples"),
            "alignment_status": "aligned",
        })
    return {
        "window_label": window_label,
        "window_duration_seconds": duration,
        "rows": rows,
    }


def aligned_rankings(
    loaded: list[dict[str, Any]],
    window_label: str | None,
) -> dict[str, list[tuple[str, float]]]:
    """Build the same set of rankings the matrix already produces,
    but using aligned-window scores instead of full-window ones.

    Returns empty dict when no aligned window — caller falls back to
    the raw rankings.
    """
    if not window_label:
        return {}
    metric_to_key = {
        "best_overall": "overall",
        "best_stability": "stability",
        "best_efficiency": "efficiency",
        "best_workload": "workload_suitability",
        "best_network": "network_impact",
        "best_hygiene": "resource_hygiene",
    }
    out: dict[str, list[tuple[str, float]]] = {}
    for ranking_name, score_key in metric_to_key.items():
        pairs: list[tuple[str, float]] = []
        for r in loaded:
            run_id = (r.get("manifest") or {}).get("run_id") or "?"
            v = aligned_score(r.get("scores") or {}, window_label, score_key)
            if v is None:
                continue
            pairs.append((run_id, v))
        # Higher is better for all of these.
        out[ranking_name] = sorted(pairs, key=lambda kv: kv[1], reverse=True)
    return out


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _dig(d: dict[str, Any] | None, key: str) -> Any:
    """Return d[key].score when it's a dict-shaped sub-score, else d[key]."""
    if not isinstance(d, dict):
        return None
    v = d.get(key)
    if isinstance(v, dict):
        return v.get("score")
    return v


def _coerce_score(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None
