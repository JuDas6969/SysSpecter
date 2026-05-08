"""Periodicity detection (Field-review A3).

Detects periodic spikes in system and per-process metrics by Pearson
autocorrelation, so questions like "what's running during the idle
period?" get answered without 30 minutes of manual chart-staring.

Motivating cases from the field review (real production runs):
    Defender scan       every 593 s
    MsSense.exe         every 989 s
    NetSetupSvc         every 291 s

The detector consumes the binned time series for each metric, walks
lags from 30 s (anything shorter is sample-rate noise) up to 30 min
(anything longer needs at least 4 cycles of run length to be
detectable), and reports local peaks above a correlation strength
threshold. All-stdlib — no scipy / numpy dependency.

Output schema (one entry per detected period):
    {
        "metric": "cpu_total_pct",
        "label": "CPU total",
        "pid": 4242,                       # only for per-PID
        "process_name": "MsSense.exe",     # only for per-PID
        "period_seconds": 989,
        "strength": 0.71,
        "description": "MsSense.exe (pid 4242) CPU spikes every "
                       "989 s (correlation 0.71)"
    }
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .stats import mean

_BIN_SECONDS = 5.0          # bin width — 5 s smooths sample-rate jitter
_MIN_PERIOD_S = 30.0        # below this is just noise
_MAX_PERIOD_S = 1800.0      # above this needs > 2 h of data for >1 cycle
_MIN_STRENGTH = 0.30        # autocorrelation threshold for "this is real"
_TOP_N_PER_SYSTEM_METRIC = 3
_TOP_N_PER_PROCESS = 1
_MIN_PROCESS_SAMPLES = 100  # PIDs with fewer samples can't show periodicity


def _bin_series(
    rows: list[dict[str, Any]], key: str, bin_s: float,
) -> tuple[list[float], list[float]]:
    """Bin per-row metric values into fixed-width time bins. Returns
    (rel_axis_seconds, mean_value_per_bin). Empty bins read as 0.0
    so the lag arithmetic stays consistent on sparse data."""
    if not rows:
        return [], []
    bins: dict[int, list[float]] = defaultdict(list)
    for r in rows:
        rel = r.get("rel_seconds")
        v = r.get(key)
        if rel is None or v is None:
            continue
        try:
            b = int(float(rel) // bin_s)
            bins[b].append(float(v))
        except (TypeError, ValueError):
            continue
    if not bins:
        return [], []
    bmin, bmax = min(bins), max(bins)
    out_x: list[float] = []
    out_y: list[float] = []
    for b in range(bmin, bmax + 1):
        out_x.append(b * bin_s)
        out_y.append(mean(bins[b]) if bins[b] else 0.0)
    return out_x, out_y


def _autocorrelation(
    series: list[float], min_lag: int, max_lag: int,
) -> list[tuple[int, float]]:
    """Pearson-style autocorrelation over an integer lag range.

    Detrends by subtracting the mean so the result is bounded in
    roughly [-1, +1]. A constant series (zero variance) returns an
    empty list — there's no meaningful periodicity in flat data.
    """
    n = len(series)
    if n < min_lag * 2 + 4:
        return []
    m = sum(series) / n
    detrended = [v - m for v in series]
    norm = sum(v * v for v in detrended)
    if norm <= 0:
        return []
    out: list[tuple[int, float]] = []
    for lag in range(min_lag, max_lag + 1):
        if n - lag < 10:
            break
        s = sum(detrended[i] * detrended[i + lag] for i in range(n - lag))
        out.append((lag, s / norm))
    return out


def _find_peaks(
    corrs: list[tuple[int, float]],
    *,
    min_strength: float,
    top_n: int,
) -> list[dict[str, Any]]:
    """Local-maximum peak detection — a value is a peak if it
    exceeds both neighbours and the correlation threshold. The
    field review's example (Defender at 593 s, MsSense at 989 s,
    NetSetupSvc at 291 s) all show up as distinct local maxima
    because their periods are well separated."""
    peaks: list[dict[str, Any]] = []
    for i in range(1, len(corrs) - 1):
        lag, val = corrs[i]
        if val < min_strength:
            continue
        prev_v = corrs[i - 1][1]
        next_v = corrs[i + 1][1]
        if val > prev_v and val > next_v:
            peaks.append({"lag": lag, "strength": val})
    peaks.sort(key=lambda p: p["strength"], reverse=True)
    return peaks[:top_n]


def _detect_for_metric(
    rows: list[dict[str, Any]],
    metric: str,
    bin_s: float,
    *,
    top_n: int,
) -> list[dict[str, Any]]:
    """Run the binning + autocorrelation + peak-finding pipeline for
    one (rows, metric) pair. Returns raw peaks; caller adds metadata."""
    _xs, ys = _bin_series(rows, metric, bin_s)
    if len(ys) < 20:
        return []
    min_lag = max(1, int(_MIN_PERIOD_S / bin_s))
    max_lag = min(len(ys) // 2, int(_MAX_PERIOD_S / bin_s))
    if max_lag <= min_lag:
        return []
    corrs = _autocorrelation(ys, min_lag, max_lag)
    return _find_peaks(corrs, min_strength=_MIN_STRENGTH, top_n=top_n)


_SYSTEM_METRICS: tuple[tuple[str, str], ...] = (
    ("cpu_total_pct",            "CPU total"),
    ("net_sent_bytes_per_sec",   "Network sent"),
    ("net_recv_bytes_per_sec",   "Network recv"),
    ("disk_read_bytes_per_sec",  "Disk read"),
    ("disk_write_bytes_per_sec", "Disk write"),
)


def detect_periodicities(
    system_rows: list[dict[str, Any]],
    process_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Top-level entry. Returns:

        {
            "system":      list of system-level periodicities,
            "per_process": list of per-PID CPU periodicities,
            "method":      "autocorrelation",
            "bin_seconds": <bin width>,
            "min_period_seconds": <floor>,
            "max_period_seconds": <ceiling>,
        }
    """
    process_rows = process_rows or []
    bin_s = _BIN_SECONDS

    # System-level metrics.
    system_results: list[dict[str, Any]] = []
    for metric, label in _SYSTEM_METRICS:
        peaks = _detect_for_metric(
            system_rows, metric, bin_s, top_n=_TOP_N_PER_SYSTEM_METRIC,
        )
        for p in peaks:
            period = int(p["lag"] * bin_s)
            system_results.append({
                "metric": metric,
                "label": label,
                "period_seconds": period,
                "strength": round(p["strength"], 3),
                "description": (
                    f"{label} shows a periodic pattern every {period} s "
                    f"(autocorrelation {p['strength']:.2f})"
                ),
            })

    # Per-PID CPU spikes — useful for spotting EDR / scanner cycles.
    per_pid_results: list[dict[str, Any]] = []
    by_pid: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for r in process_rows:
        pid = r.get("pid")
        if pid is None:
            continue
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            continue
        by_pid[pid].append(r)

    for pid, rows in by_pid.items():
        if len(rows) < _MIN_PROCESS_SAMPLES:
            continue
        # Canonical name = most frequent (handles PID recycling).
        name_counts: dict[str, int] = defaultdict(int)
        for r in rows:
            name_counts[r.get("name") or "?"] += 1
        canonical_name = max(name_counts.items(), key=lambda kv: kv[1])[0]
        peaks = _detect_for_metric(
            rows, "cpu_pct", bin_s, top_n=_TOP_N_PER_PROCESS,
        )
        for p in peaks:
            period = int(p["lag"] * bin_s)
            per_pid_results.append({
                "pid": pid,
                "process_name": canonical_name,
                "metric": "cpu_pct",
                "period_seconds": period,
                "strength": round(p["strength"], 3),
                "description": (
                    f"{canonical_name} (pid {pid}) CPU spikes every "
                    f"{period} s (autocorrelation {p['strength']:.2f})"
                ),
            })

    per_pid_results.sort(key=lambda e: e["strength"], reverse=True)
    system_results.sort(key=lambda e: e["strength"], reverse=True)

    return {
        "system": system_results,
        "per_process": per_pid_results,
        "method": "autocorrelation",
        "bin_seconds": bin_s,
        "min_period_seconds": _MIN_PERIOD_S,
        "max_period_seconds": _MAX_PERIOD_S,
    }
