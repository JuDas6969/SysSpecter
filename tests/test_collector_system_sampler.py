"""Smoke tests for collector/system_sampler.py.

The sampler wraps psutil and computes per-second rates. These tests make
sure:

1. `collect_system_sample()` returns a valid SystemSample on a real system
   (integration-ish).
2. The rate math does not divide by zero when two samples are taken in
   quick succession.
3. `sample_to_dict()` produces the exact schema the CSV writer expects.
4. The helper fall-back paths (psutil.cpu_freq() returns None, disk_io
   returns None) don't crash the pipeline.
"""

from __future__ import annotations

import time
from unittest.mock import patch

from sysspecter.collector import system_sampler as ss


def test_collect_sample_returns_schema() -> None:
    ss._last_disk = None
    ss._last_net = None
    ss._last_ts = None
    ss._last_cpu_stats = None

    started = time.monotonic()
    sample = ss.collect_system_sample(started)

    assert sample.cpu_total_pct >= 0.0
    assert sample.cpu_total_pct <= 100.0
    assert isinstance(sample.cpu_per_core_pct, list)
    assert len(sample.cpu_per_core_pct) >= 1
    assert sample.mem_total_bytes > 0
    assert 0.0 <= sample.mem_percent <= 100.0


def test_two_samples_compute_non_negative_rates() -> None:
    ss._last_disk = None
    ss._last_net = None
    ss._last_ts = None

    started = time.monotonic()
    ss.collect_system_sample(started)
    time.sleep(0.05)
    sample = ss.collect_system_sample(started)

    # Rates may be zero on an idle system, but must not be negative.
    assert sample.disk_read_bytes_per_sec >= 0
    assert sample.disk_write_bytes_per_sec >= 0
    assert sample.net_sent_bytes_per_sec >= 0
    assert sample.net_recv_bytes_per_sec >= 0


def test_sample_to_dict_has_expected_keys() -> None:
    ss._last_disk = None
    ss._last_net = None
    ss._last_ts = None

    sample = ss.collect_system_sample(time.monotonic())
    row = ss.sample_to_dict(sample)

    expected = {
        "timestamp", "rel_seconds", "cpu_total_pct", "cpu_per_core_pct",
        "mem_percent", "disk_active_pct_est",
        "net_sent_bytes_per_sec", "net_recv_bytes_per_sec",
    }
    missing = expected - set(row.keys())
    assert not missing, f"CSV row schema missing keys: {missing}"

    # cpu_per_core_pct must be the CSV-friendly string form.
    assert isinstance(row["cpu_per_core_pct"], str)
    assert ";" in row["cpu_per_core_pct"] or row["cpu_per_core_pct"] != ""


def test_freq_mhz_handles_psutil_unavailable() -> None:
    """psutil.cpu_freq() can raise on some virtualized hardware; we must
    return None rather than bubble up."""
    with patch("sysspecter.collector.system_sampler.psutil.cpu_freq",
               side_effect=OSError("not available")):
        assert ss._freq_mhz() is None


def test_disk_totals_handles_psutil_unavailable() -> None:
    with patch("sysspecter.collector.system_sampler.psutil.disk_io_counters",
               side_effect=PermissionError("ETW not admin")):
        read_b, write_b, read_c, write_c, busy, total = ss._disk_totals()
        assert (read_b, write_b, read_c, write_c, busy, total) == (0.0, 0.0, 0.0, 0.0, 0, 0)


def test_net_totals_handles_psutil_unavailable() -> None:
    with patch("sysspecter.collector.system_sampler.psutil.net_io_counters",
               side_effect=RuntimeError("iface gone")):
        assert ss._net_totals() == {}


def test_disk_totals_handles_none_return() -> None:
    """psutil on some machines returns None from disk_io_counters() when
    no disks are ready. Must not crash."""
    with patch("sysspecter.collector.system_sampler.psutil.disk_io_counters",
               return_value=None):
        result = ss._disk_totals()
        assert result == (0.0, 0.0, 0.0, 0.0, 0, 0)
