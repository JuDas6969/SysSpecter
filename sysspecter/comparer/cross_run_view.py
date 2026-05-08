"""Cross-run aggregation view (Field-review A5).

Lifts the new schema fields shipped in B1 (analysis_window), M2
(structured meta), M5 (stable machine_id), A6 (tail_windows), and
C3 (baseline_deviations) into the comparison output. Without this,
two runs from the same machine would show as "same hostname" but
the operator couldn't tell whether they're (a) the same hardware
(M5), (b) the same machine class (M2/C3), or (c) producing
length-comparable scores (A6).

Output schema (lives at ``comparison_findings.cross_run_view``):

    {
        "same_machine": bool,
        "machine_ids": [
            {"run_id": ..., "machine_id": ..., "source": ...}
        ],
        "shared_machine_class":     str | None,
        "shared_capture_profile":   str | None,
        "shared_meta":              {key: value} where ALL runs agree,
        "tail_window_view": {
            "common_window_label":  "last_1h" | "last_8h" | None,
            "rows":                 [{run_id, overall, stability, …}]
        },
        "baseline_deviations": {
            "common":        [(machine_class, metric)],
            "per_run":       {run_id: [list of deviation dicts]},
        },
    }
"""

from __future__ import annotations

from typing import Any


def _dig(d: dict[str, Any] | None, *keys: str, default: Any = None) -> Any:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
    return cur if cur is not None else default


def _shared_dict(dicts: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the entries that appear with the same value in EVERY
    input dict. Used for shared_meta."""
    if not dicts:
        return {}
    head = dicts[0]
    out: dict[str, Any] = {}
    for k, v in head.items():
        if all(d.get(k) == v for d in dicts[1:]):
            out[k] = v
    return out


def _shared_value(values: list[Any]) -> Any | None:
    """Return the value if every element in `values` is identical
    AND non-None; else None."""
    if not values:
        return None
    first = values[0]
    if first is None:
        return None
    return first if all(v == first for v in values[1:]) else None


def _common_tail_window_label(score_blocks: list[dict[str, Any]]) -> str | None:
    """Largest tail window that ALL runs produced (i.e. that fits
    inside every run's analysis_window). Returns None if any run is
    too short for any tail."""
    candidates = ["last_8h", "last_1h"]   # widest first
    for label in candidates:
        if all(
            any(tw.get("window_label") == label
                for tw in (s.get("tail_windows") or []))
            for s in score_blocks
        ):
            return label
    return None


def _row_for_tail(run_id: str, scores: dict[str, Any],
                  window_label: str) -> dict[str, Any] | None:
    for tw in (scores.get("tail_windows") or []):
        if tw.get("window_label") == window_label:
            return {
                "run_id": run_id,
                "window_label": window_label,
                "window_duration_seconds": tw.get("window_duration_seconds"),
                "overall": tw.get("overall"),
                "stability": _dig(tw, "stability", "score"),
                "efficiency": _dig(tw, "efficiency", "score"),
                "workload_suitability": _dig(tw, "workload_suitability", "score"),
                "network_impact": _dig(tw, "network_impact", "score"),
                "resource_hygiene": _dig(tw, "resource_hygiene", "score"),
                "samples": tw.get("window_samples"),
            }
    return None


def build_cross_run_view(
    loaded_runs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the cross-run aggregation view from the same `loaded`
    list ``compare_runs.run_compare`` already produces (each entry
    has ``manifest`` / ``findings`` / ``scores`` keys).
    """
    if not loaded_runs:
        return _empty_view()

    manifests = [r.get("manifest") or {} for r in loaded_runs]
    findings = [r.get("findings") or {} for r in loaded_runs]
    scores = [r.get("scores") or {} for r in loaded_runs]
    metas = [m.get("meta") or {} for m in manifests]

    # Same-machine analysis (M5).
    machine_id_entries = [
        {
            "run_id": m.get("run_id"),
            "machine_id": m.get("machine_id"),
            "machine_id_source": m.get("machine_id_source"),
        }
        for m in manifests
    ]
    ids = [e["machine_id"] for e in machine_id_entries
           if e.get("machine_id")]
    same_machine = bool(ids) and len(set(ids)) == 1 and len(ids) == len(loaded_runs)

    # Shared structured metadata (M2 / C4).
    shared_meta = _shared_dict(metas)
    shared_class = _shared_value([m.get("machine_class") for m in metas])
    shared_profile = _shared_value([m.get("capture_profile") for m in metas])

    # Tail-window comparison (A6) — pick the largest common window.
    common_window = _common_tail_window_label(scores)
    tail_rows: list[dict[str, Any]] = []
    if common_window is not None:
        for m, s in zip(manifests, scores, strict=False):
            row = _row_for_tail(m.get("run_id") or "?", s, common_window)
            if row is not None:
                tail_rows.append(row)

    # Baseline deviations (C3) — common vs unique.
    per_run_devs: dict[str, list[dict[str, Any]]] = {}
    dev_signatures: list[set[tuple[str, str]]] = []
    for m, f in zip(manifests, findings, strict=False):
        run_id = m.get("run_id") or "?"
        devs = list(f.get("baseline_deviations") or [])
        per_run_devs[run_id] = devs
        sig = {
            (d.get("machine_class") or "?", d.get("metric") or "?")
            for d in devs
        }
        dev_signatures.append(sig)
    if dev_signatures:
        common_signatures = set.intersection(*dev_signatures)
    else:
        common_signatures = set()
    common_devs = [
        {"machine_class": cls, "metric": metric}
        for cls, metric in sorted(common_signatures)
    ]

    return {
        "same_machine": same_machine,
        "machine_ids": machine_id_entries,
        "shared_machine_class": shared_class,
        "shared_capture_profile": shared_profile,
        "shared_meta": shared_meta,
        "tail_window_view": {
            "common_window_label": common_window,
            "rows": tail_rows,
        },
        "baseline_deviations": {
            "common": common_devs,
            "per_run": per_run_devs,
        },
    }


def _empty_view() -> dict[str, Any]:
    return {
        "same_machine": False,
        "machine_ids": [],
        "shared_machine_class": None,
        "shared_capture_profile": None,
        "shared_meta": {},
        "tail_window_view": {
            "common_window_label": None,
            "rows": [],
        },
        "baseline_deviations": {"common": [], "per_run": {}},
    }
