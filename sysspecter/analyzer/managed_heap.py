"""v3-priority-5 (H2): managed-heap leak detection + native/managed
leak attribution.

The single biggest decision a leak diagnosis has to make:
*"is this a native bug or a .NET bug?"* The answers point at very
different fixes — a native leak means C/C++/COM unmanaged code, a
managed leak means retained roots in .NET. The two look identical
from outside (RSS grows over time) but managed leaks track the
gen-2 heap size while native leaks don't. With the v3-priority-5
sampler in place, the analyzer can finally make this distinction.

Output (under `findings.managed_heap_leaks`):

    {
        "samples_seen": int,
        "managed_leaks": [
            {
                "pid": int, "name": str,
                "first_gen2_bytes": int,
                "last_gen2_bytes": int,
                "delta_bytes": int,
                "duration_seconds": float,
                "slope_bytes_per_minute": float,
                "gen2_collections_observed": int,
                "severity": "high"|"medium"|"low",
                "confidence": "high"|"medium"|"low",
            },
            ...
        ],
        "native_only_leaks": [
            {  # PID with RSS leak signal but flat managed heap —
               # by elimination, the leak is in unmanaged memory
               # (C/C++/COM allocations, native handle stores, etc.)
                "pid": int, "name": str,
                "rss_slope_bytes_per_minute": float,
                "managed_slope_bytes_per_minute": float,
                "ratio_native_share": float,  # 1.0 means 100% native
            },
            ...
        ],
    }

Empty containers when no managed_heap_rows present (back-compat with
runs captured before v3-priority-5).
"""

from __future__ import annotations

from typing import Any

# Minimum samples per PID before we'll fire a finding. PDH counters
# need 3 samples to be confident the slope isn't startup noise.
_MIN_SAMPLES = 3

# Thresholds for gen-2 growth (bytes / minute). 50 KB/min sustained is
# a real leak signal; below that is GC jitter on a busy app.
_GEN2_THRESHOLD_LOW = 50 * 1024          # 50 KB/min
_GEN2_THRESHOLD_MEDIUM = 500 * 1024      # 500 KB/min
_GEN2_THRESHOLD_HIGH = 5 * 1024 * 1024   # 5 MB/min

# Native-vs-managed diff thresholds:
#   - the RSS slope must be at least leak_threshold to consider the
#     PID "leaking" at all.
#   - if managed slope is < 20% of RSS slope, the leak is "mostly
#     native" — flag as a native_only candidate.
_RSS_LEAK_THRESHOLD_BPM = 100 * 1024  # 100 KB/min RSS growth
_NATIVE_DOMINANCE_THRESHOLD = 0.80     # native >= 80% of total growth


def _least_squares_slope(xs: list[float], ys: list[float]) -> float | None:
    """Slope of y over x. Returns None when xs is degenerate."""
    n = len(xs)
    if n < 2:
        return None
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = sum((xs[i] - mean_x) * (ys[i] - mean_y) for i in range(n))
    den = sum((xs[i] - mean_x) ** 2 for i in range(n))
    if den == 0:
        return None
    return num / den


def _classify_gen2(slope_bytes_per_minute: float) -> tuple[str, str]:
    """Severity + confidence from gen-2 slope. Mirrors the handle-leak
    analyzer's three-tier classification."""
    if slope_bytes_per_minute >= _GEN2_THRESHOLD_HIGH:
        return ("high", "high")
    if slope_bytes_per_minute >= _GEN2_THRESHOLD_MEDIUM:
        return ("medium", "medium")
    if slope_bytes_per_minute >= _GEN2_THRESHOLD_LOW:
        return ("low", "medium")
    return ("low", "low")


def _series_for_pid(
    rows: list[dict[str, Any]],
    pid: int,
    field: str,
) -> list[tuple[float, float]]:
    """Return [(rel_seconds, value), ...] for one PID's `field`."""
    out: list[tuple[float, float]] = []
    for r in rows:
        try:
            rid = int(r.get("pid") or 0)
        except (TypeError, ValueError):
            continue
        if rid != pid:
            continue
        try:
            rel = float(r.get("rel_seconds") or 0.0)
            val = float(r.get(field) or 0.0)
        except (TypeError, ValueError):
            continue
        out.append((rel, val))
    out.sort(key=lambda t: t[0])
    return out


def _slope_per_minute(series: list[tuple[float, float]]) -> float | None:
    if len(series) < 2:
        return None
    xs = [s[0] for s in series]
    ys = [s[1] for s in series]
    slope_per_second = _least_squares_slope(xs, ys)
    if slope_per_second is None:
        return None
    return slope_per_second * 60.0


def _rss_series_for_pid(
    process_rows: list[dict[str, Any]], pid: int,
) -> list[tuple[float, float]]:
    """Lift the per-process RSS series so we can diff vs gen-2."""
    out: list[tuple[float, float]] = []
    for r in process_rows or []:
        try:
            rid = int(r.get("pid") or 0)
        except (TypeError, ValueError):
            continue
        if rid != pid:
            continue
        try:
            rel = float(r.get("rel_seconds") or 0.0)
            rss = float(r.get("rss_bytes") or 0.0)
        except (TypeError, ValueError):
            continue
        out.append((rel, rss))
    out.sort(key=lambda t: t[0])
    return out


def detect_managed_heap_leaks(
    managed_heap_rows: list[dict[str, Any]] | None,
    process_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run gen-2 leak detection + native/managed diff.

    `managed_heap_rows` is from RunData.managed_heap_rows.
    `process_rows` is from RunData.process_rows; used to compute the
    native_only diff (RSS growth vs managed-heap growth on the same
    PID). When process_rows is empty the diff is skipped — gen-2
    findings still fire.
    """
    out: dict[str, Any] = {
        "samples_seen": 0,
        "managed_leaks": [],
        "native_only_leaks": [],
    }
    if not managed_heap_rows:
        return out

    sample_times: set[float] = set()
    pids_seen: dict[int, str] = {}
    for r in managed_heap_rows:
        try:
            pid = int(r.get("pid") or 0)
            rel = float(r.get("rel_seconds") or 0.0)
        except (TypeError, ValueError):
            continue
        if pid <= 0:
            continue
        sample_times.add(rel)
        pids_seen[pid] = str(r.get("name") or "?")
    out["samples_seen"] = len(sample_times)

    # --- gen-2 leak findings ------------------------------------------
    managed_findings: list[dict[str, Any]] = []
    managed_slope_by_pid: dict[int, float] = {}
    for pid, name in pids_seen.items():
        gen2 = _series_for_pid(managed_heap_rows, pid, "gen2_heap_size")
        if len(gen2) < _MIN_SAMPLES:
            continue
        slope_bpm = _slope_per_minute(gen2)
        if slope_bpm is None:
            continue
        managed_slope_by_pid[pid] = slope_bpm
        if slope_bpm < _GEN2_THRESHOLD_LOW:
            continue
        # Pull collection counts to flag "leak with no GC pressure"
        # vs "leak despite gen-2 collections" — the latter is the
        # textbook retained-roots scenario.
        gen2_coll = _series_for_pid(managed_heap_rows, pid, "gen2_collections")
        gen2_coll_observed = (
            int(gen2_coll[-1][1]) - int(gen2_coll[0][1])
            if gen2_coll else 0
        )
        severity, confidence = _classify_gen2(slope_bpm)
        managed_findings.append({
            "pid": pid,
            "name": name,
            "first_gen2_bytes": int(gen2[0][1]),
            "last_gen2_bytes": int(gen2[-1][1]),
            "delta_bytes": int(gen2[-1][1]) - int(gen2[0][1]),
            "duration_seconds": round(gen2[-1][0] - gen2[0][0], 2),
            "slope_bytes_per_minute": round(slope_bpm, 1),
            "gen2_collections_observed": gen2_coll_observed,
            "severity": severity,
            "confidence": confidence,
        })

    severity_rank = {"high": 3, "medium": 2, "low": 1}
    managed_findings.sort(
        key=lambda f: (
            -severity_rank.get(f["severity"], 0),
            -f["slope_bytes_per_minute"],
        )
    )
    out["managed_leaks"] = managed_findings

    # --- native-only diff ---------------------------------------------
    if process_rows:
        native_only: list[dict[str, Any]] = []
        for pid, name in pids_seen.items():
            rss_series = _rss_series_for_pid(process_rows, pid)
            if len(rss_series) < _MIN_SAMPLES:
                continue
            rss_slope = _slope_per_minute(rss_series)
            if rss_slope is None or rss_slope < _RSS_LEAK_THRESHOLD_BPM:
                continue
            mh_slope = managed_slope_by_pid.get(pid, 0.0)
            # If managed-heap slope is missing / negative, treat as 0.
            mh_slope = max(0.0, mh_slope)
            total = rss_slope + 0.0001  # avoid /0
            native_share = max(0.0, (rss_slope - mh_slope) / total)
            if native_share >= _NATIVE_DOMINANCE_THRESHOLD:
                native_only.append({
                    "pid": pid,
                    "name": name,
                    "rss_slope_bytes_per_minute": round(rss_slope, 1),
                    "managed_slope_bytes_per_minute": round(mh_slope, 1),
                    "ratio_native_share": round(native_share, 3),
                })
        native_only.sort(
            key=lambda f: -f["rss_slope_bytes_per_minute"],
        )
        out["native_only_leaks"] = native_only

    return out
