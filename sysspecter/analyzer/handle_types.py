"""v3-priority-4 (H1): per-(PID, type) handle-leak analyzer.

The aggregate handle-leak rule in `leaks.py` operates on `num_handles`
(a single integer per process per sample). It tells you "PID X is
leaking handles." The new per-type signal lifts that into "PID X is
leaking File handles AND Event handles" — which is what makes the
difference between a vague COM-RCW leak hypothesis and a verified one.

Inputs: `RunData.handles_rows` (rows of {timestamp, rel_seconds, pid,
name, type_name, count}), one row per (sample, pid, type_name)
emitted by the v3-priority-4 sampler.

Output (under `findings.handle_leaks_by_type`):

    {
        "samples_seen": int,          # total snapshots in the run
        "per_type_findings": [
            {
                "pid": int,
                "name": str,
                "type_name": str,
                "samples": int,
                "first_count": int,
                "last_count": int,
                "delta": int,
                "duration_seconds": float,
                "slope_per_minute": float,
                "severity": "high" | "medium" | "low",
                "confidence": "high" | "medium" | "low",
            },
            ...
        ],
        "rcw_signature_candidates": [
            {  # processes leaking BOTH Section AND Event handles
               # — the textbook COM Runtime-Callable-Wrapper signature
                "pid": int, "name": str,
                "section_slope_per_minute": float,
                "event_slope_per_minute": float,
                "samples": int,
            },
            ...
        ],
    }

Empty containers when no handles_rows present (back-compat with runs
captured before v3-priority-4).
"""

from __future__ import annotations

from typing import Any

# Minimum number of (pid, type) snapshots before we'll fire a finding.
# Less than 3 and the slope is meaningless; with 3+ we can at least
# distinguish "going up" from "stable".
_MIN_SAMPLES = 3

# Growth thresholds in handles per minute, per type. Below "low" we
# don't fire at all — most processes drift a few handles up and down
# during normal operation.
_THRESHOLD_LOW = 5.0       # 5 handles/min sustained
_THRESHOLD_MEDIUM = 30.0   # 30 handles/min — measurable
_THRESHOLD_HIGH = 200.0    # 200 handles/min — definite leak

# Types we never report as "leaking" because their counts naturally
# drift hard. Process / Thread are example: a process that spawns
# children adds Process handles continually but isn't leaking.
_NOISY_TYPES: frozenset[str] = frozenset({
    # Job control naturally grows in containerised workloads.
    "Job",
    # Driver / Type / Adapter are kernel-controlled and don't reflect
    # user-process leaks.
    "Driver", "Type", "Adapter",
})


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


def _classify(slope_per_minute: float) -> tuple[str, str]:
    """Return (severity, confidence) for a per-minute slope."""
    if slope_per_minute >= _THRESHOLD_HIGH:
        return ("high", "high")
    if slope_per_minute >= _THRESHOLD_MEDIUM:
        return ("medium", "medium")
    if slope_per_minute >= _THRESHOLD_LOW:
        return ("low", "medium")
    return ("low", "low")


def detect_handle_type_leaks(
    handles_rows: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Run per-(pid, type) leak analysis. See module docstring for shape."""
    out: dict[str, Any] = {
        "samples_seen": 0,
        "per_type_findings": [],
        "rcw_signature_candidates": [],
    }
    if not handles_rows:
        return out

    # Group rows by (pid, type_name). Each group is a per-snapshot
    # series of (rel_seconds, count).
    series: dict[tuple[int, str], list[tuple[float, int, str]]] = {}
    sample_times: set[float] = set()
    for r in handles_rows:
        try:
            pid = int(r.get("pid") or 0)
            count = int(r.get("count") or 0)
            rel = float(r.get("rel_seconds") or 0.0)
        except (TypeError, ValueError):
            continue
        if pid <= 0 or count <= 0:
            continue
        type_name = str(r.get("type_name") or "")
        if not type_name or type_name in _NOISY_TYPES:
            continue
        name = str(r.get("name") or "?")
        sample_times.add(rel)
        series.setdefault((pid, type_name), []).append((rel, count, name))

    out["samples_seen"] = len(sample_times)

    findings: list[dict[str, Any]] = []
    # Index for the RCW pass below.
    by_pid: dict[int, dict[str, dict[str, Any]]] = {}
    for (pid, type_name), pts in series.items():
        if len(pts) < _MIN_SAMPLES:
            continue
        pts.sort(key=lambda t: t[0])
        xs_seconds = [p[0] for p in pts]
        ys = [float(p[1]) for p in pts]
        # Convert slope from handles-per-second to handles-per-minute
        # so the threshold numbers match human intuition.
        slope_s = _least_squares_slope(xs_seconds, ys)
        if slope_s is None:
            continue
        slope_per_minute = slope_s * 60.0
        if slope_per_minute < _THRESHOLD_LOW:
            continue
        severity, confidence = _classify(slope_per_minute)
        first_count = int(ys[0])
        last_count = int(ys[-1])
        finding = {
            "pid": pid,
            "name": pts[-1][2],  # most recent process name we saw
            "type_name": type_name,
            "samples": len(pts),
            "first_count": first_count,
            "last_count": last_count,
            "delta": last_count - first_count,
            "duration_seconds": round(xs_seconds[-1] - xs_seconds[0], 2),
            "slope_per_minute": round(slope_per_minute, 2),
            "severity": severity,
            "confidence": confidence,
        }
        findings.append(finding)
        by_pid.setdefault(pid, {})[type_name] = finding

    # Sort findings: highest severity first, then by slope.
    severity_rank = {"high": 3, "medium": 2, "low": 1}
    findings.sort(
        key=lambda f: (
            -severity_rank.get(f["severity"], 0),
            -f["slope_per_minute"],
        )
    )
    out["per_type_findings"] = findings

    # COM Runtime-Callable-Wrapper signature: a process leaking BOTH
    # `Section` AND `Event` handles in tandem is the classic RCW leak.
    # If both sides cross the medium threshold we have strong evidence.
    rcw: list[dict[str, Any]] = []
    for pid, types in by_pid.items():
        section = types.get("Section")
        event = types.get("Event")
        if not section or not event:
            continue
        if (section["severity"] in ("medium", "high")
                and event["severity"] in ("medium", "high")):
            rcw.append({
                "pid": pid,
                "name": section["name"],
                "section_slope_per_minute": section["slope_per_minute"],
                "event_slope_per_minute": event["slope_per_minute"],
                "samples": min(section["samples"], event["samples"]),
            })
    out["rcw_signature_candidates"] = rcw
    return out
