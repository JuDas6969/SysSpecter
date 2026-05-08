"""Field-review A3: periodic-pattern detection.

Pins the contract that synthetic series with known periods produce
the expected detections, and that pure noise / flat data does NOT.
"""

from __future__ import annotations

import math

import pytest

from sysspecter.analyzer.periodicity import (
    _autocorrelation,
    _bin_series,
    _find_peaks,
    detect_periodicities,
)


def _sin_series(period_s: float, duration_s: float = 7200.0,
                amplitude: float = 30.0, baseline: float = 20.0,
                step_s: float = 1.0) -> list[dict]:
    """Build per-row system samples following a clean sine wave with
    the given period — the textbook input for an autocorrelation
    detector."""
    rows = []
    n = int(duration_s / step_s)
    for i in range(n):
        t = i * step_s
        v = baseline + amplitude * math.sin(2 * math.pi * t / period_s)
        rows.append({"rel_seconds": t, "cpu_total_pct": v})
    return rows


def _square_pulse_series(period_s: float, pulse_s: float,
                         duration_s: float, base: float = 1.0,
                         high: float = 80.0,
                         step_s: float = 1.0) -> list[dict]:
    """A periodic burst pattern (closer to real EDR / AV scans)."""
    rows = []
    n = int(duration_s / step_s)
    for i in range(n):
        t = i * step_s
        phase = t % period_s
        v = high if phase < pulse_s else base
        rows.append({"rel_seconds": t, "cpu_total_pct": v})
    return rows


# ----------------------------------------------------- primitive tests


def test_bin_series_handles_empty_and_filters_none() -> None:
    assert _bin_series([], "x", 5.0) == ([], [])
    rows = [
        {"rel_seconds": 0, "x": None},
        {"rel_seconds": 1, "x": 10.0},
        {"rel_seconds": 2, "x": 20.0},
        {"rel_seconds": None, "x": 5.0},
    ]
    xs, ys = _bin_series(rows, "x", bin_s=5.0)
    assert len(xs) == 1
    assert ys[0] == pytest.approx(15.0)


def test_autocorrelation_returns_empty_for_constant_series() -> None:
    """A flat series has zero variance — autocorrelation is undefined."""
    series = [42.0] * 200
    assert _autocorrelation(series, 5, 50) == []


def test_autocorrelation_peak_aligns_with_period() -> None:
    """Sine wave with period 60 should produce its first positive
    peak past the central lobe at lag = 60. We skip the central
    lobe (low lags where the wave hasn't crossed zero yet) — that's
    what the production code does too via _MIN_PERIOD_S."""
    period = 60
    series = [math.sin(2 * math.pi * i / period) for i in range(600)]
    # Start past half the period so we land beyond the central lobe.
    corrs = _autocorrelation(series, period // 2 + 1, 200)
    best = max(corrs, key=lambda kv: kv[1])
    assert abs(best[0] - period) <= 2, (
        f"expected peak near lag={period}, got lag={best[0]} "
        f"strength={best[1]:.2f}"
    )


def test_find_peaks_filters_below_threshold() -> None:
    corrs = [
        (10, 0.10),
        (20, 0.50),     # peak
        (30, 0.15),
        (40, 0.40),     # below threshold (0.45)
        (50, 0.30),
    ]
    peaks = _find_peaks(corrs, min_strength=0.45, top_n=5)
    assert len(peaks) == 1
    assert peaks[0]["lag"] == 20


# ----------------------------------------------------- end-to-end


def test_clean_sine_period_is_detected() -> None:
    """A 2-h CPU series oscillating at 600 s period should be
    flagged with a period close to 600 s and a strong correlation."""
    rows = _sin_series(period_s=600, duration_s=7200)
    result = detect_periodicities(rows)
    assert result["system"], "expected at least one system periodicity"
    cpu_periods = [
        p for p in result["system"] if p["metric"] == "cpu_total_pct"
    ]
    assert cpu_periods, "expected a CPU-total periodicity"
    best = cpu_periods[0]
    # The detector bins at 5 s; tolerate +/- one bin.
    assert abs(best["period_seconds"] - 600) <= 10
    assert best["strength"] >= 0.7


def test_square_pulse_pattern_is_detected() -> None:
    """Realistic EDR-like burst pattern: 80% CPU for 30 s every
    300 s — the canonical Defender / scanner shape."""
    rows = _square_pulse_series(period_s=300, pulse_s=30,
                                duration_s=3600)
    result = detect_periodicities(rows)
    cpu_periods = [
        p for p in result["system"] if p["metric"] == "cpu_total_pct"
    ]
    assert cpu_periods, "expected CPU periodicity for square-pulse pattern"
    # Top peak should be at the fundamental; harmonics may also fire,
    # but the fundamental must be detected.
    fundamental_seen = any(
        abs(p["period_seconds"] - 300) <= 15 for p in cpu_periods
    )
    assert fundamental_seen, (
        f"expected fundamental near 300 s, got "
        f"{[p['period_seconds'] for p in cpu_periods]}"
    )


def test_pure_noise_does_not_produce_false_positives() -> None:
    """Random uniform CPU values must NOT produce periodicities at
    high strength — guards against the detector hallucinating
    patterns in noise."""
    import random
    rng = random.Random(42)
    rows = [
        {"rel_seconds": t, "cpu_total_pct": rng.uniform(10, 30)}
        for t in range(0, 3600, 1)
    ]
    result = detect_periodicities(rows)
    cpu_periods = [
        p for p in result["system"] if p["metric"] == "cpu_total_pct"
    ]
    # Random noise might produce weak peaks, but nothing strong.
    high = [p for p in cpu_periods if p["strength"] >= 0.50]
    assert not high, (
        f"detector saw strong periodicity in noise: {high}"
    )


def test_flat_input_yields_empty_system_section() -> None:
    rows = [{"rel_seconds": t, "cpu_total_pct": 50.0}
            for t in range(0, 3600, 1)]
    result = detect_periodicities(rows)
    assert result["system"] == []


def test_too_short_run_yields_empty_result() -> None:
    """Need at least 60 s of data (12 bins of 5 s) for the smallest
    detectable period to even fit one cycle."""
    rows = [{"rel_seconds": t, "cpu_total_pct": float(t)}
            for t in range(0, 30, 1)]
    result = detect_periodicities(rows)
    assert result["system"] == []
    assert result["per_process"] == []


def test_per_process_periodicity_detected() -> None:
    """A specific PID with periodic CPU bursts (EDR pattern) is
    surfaced separately so the operator can name the offender."""
    rows = []
    for t in range(0, 3600, 1):
        # MsSense-like pattern: 30 s burst every 300 s
        phase = t % 300
        cpu = 70.0 if phase < 30 else 0.5
        rows.append({
            "pid": 4242, "name": "MsSense.exe",
            "rel_seconds": t, "cpu_pct": cpu,
        })
    result = detect_periodicities([], rows)
    pp = result["per_process"]
    assert pp, "expected at least one per-PID periodicity"
    finding = pp[0]
    assert finding["pid"] == 4242
    assert finding["process_name"] == "MsSense.exe"
    assert abs(finding["period_seconds"] - 300) <= 15
    assert "cpu" in finding["description"].lower()


def test_short_pid_history_is_not_examined() -> None:
    """A PID with < _MIN_PROCESS_SAMPLES samples is skipped — too
    short to confirm any cycle."""
    rows = [
        {"pid": 99, "name": "tiny.exe", "rel_seconds": t, "cpu_pct": 10.0}
        for t in range(20)
    ]
    result = detect_periodicities([], rows)
    assert result["per_process"] == []


def test_metadata_fields_populated() -> None:
    """The result carries provenance metadata so the report can
    explain how the numbers were produced."""
    rows = _sin_series(period_s=600, duration_s=3600)
    result = detect_periodicities(rows)
    assert result["method"] == "autocorrelation"
    assert result["bin_seconds"] > 0
    assert result["min_period_seconds"] > 0
    assert result["max_period_seconds"] > result["min_period_seconds"]
