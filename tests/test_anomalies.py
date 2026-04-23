"""Tests for the anomaly detectors."""

from __future__ import annotations

from sysspecter.analyzer.anomalies import detect_anomalies
from sysspecter.config import Thresholds


def _row(rel: float, cpu: float, mem: float = 40, disk: float = 0) -> dict:
    return {
        "rel_seconds": rel,
        "cpu_total_pct": cpu,
        "mem_percent": mem,
        "disk_active_pct_est": disk,
        "cpu_per_core_pct": [cpu],
        "swap_percent": 0.0,
    }


def test_cpu_sustained_high_fires() -> None:
    # 15 seconds at 95 % CPU - sustained high (threshold 85 %, min 10 s)
    rows = [_row(t, 95) for t in range(15)]
    out = detect_anomalies(rows, latency_rows=[], th=Thresholds())
    assert any(a["kind"] == "cpu_sustained_high" for a in out)


def test_cpu_blip_does_not_fire() -> None:
    # Single spike: should NOT fire (threshold needs sustained >=10 s)
    rows = [_row(0, 95)] + [_row(t, 10) for t in range(1, 30)]
    out = detect_anomalies(rows, latency_rows=[], th=Thresholds())
    assert not any(a["kind"] == "cpu_sustained_high" for a in out)


def test_memory_pressure_fires_at_high_watermark() -> None:
    rows = [_row(t, 10, mem=95) for t in range(60)]
    out = detect_anomalies(rows, latency_rows=[], th=Thresholds())
    kinds = {a["kind"] for a in out}
    assert "memory_pressure" in kinds


def test_no_false_positives_on_idle_system() -> None:
    rows = [_row(t, 5, mem=30) for t in range(120)]
    out = detect_anomalies(rows, latency_rows=[], th=Thresholds())
    assert out == []


def test_latency_spike_fires() -> None:
    rows = [_row(t, 5) for t in range(30)]
    latency = [
        {"rel_seconds": t, "avg_ms": 600, "loss_pct": 0, "target": "1.1.1.1"}
        for t in range(5)
    ]
    out = detect_anomalies(rows, latency_rows=latency, th=Thresholds())
    assert any("latency" in a["kind"] for a in out)


def test_severity_escalates_on_critical_memory() -> None:
    rows = [_row(t, 10, mem=96) for t in range(60)]
    out = detect_anomalies(rows, latency_rows=[], th=Thresholds())
    mem_anom = [a for a in out if a["kind"] == "memory_pressure"]
    assert mem_anom, "memory_pressure should fire"
    assert mem_anom[0]["severity"] == "high"
