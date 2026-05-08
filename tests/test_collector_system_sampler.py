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
    """When BOTH NtPowerInformation and psutil.cpu_freq are unavailable
    (e.g. heavily-sandboxed Windows or non-Windows), _freq_mhz must
    return None rather than bubble up."""
    with (
        patch("sysspecter.collector.system_sampler._cpu_freq_via_ntpower",
              return_value=(None, None, None)),
        patch("sysspecter.collector.system_sampler.psutil.cpu_freq",
              side_effect=OSError("not available")),
    ):
        assert ss._freq_mhz() is None


def test_freq_mhz_prefers_ntpower_peak_over_psutil() -> None:
    """Field-review B4: when NtPowerInformation reports a turbo-boosted
    core (e.g. 5200 MHz on an i7-13800H whose nominal is 2500 MHz),
    we must surface the boosted value — not the nominal P-state value
    psutil would return."""
    with (
        patch("sysspecter.collector.system_sampler._cpu_freq_via_ntpower",
              return_value=(5200.0, 3700.0, 5200.0)),
        # psutil shouldn't even be called, but if it were it would
        # return the (broken) nominal — make the divergence loud.
        patch("sysspecter.collector.system_sampler.psutil.cpu_freq",
              return_value=type("F", (), {"current": 2500.0,
                                          "min": 0.0, "max": 5200.0})()),
    ):
        assert ss._freq_mhz() == 5200.0


def test_freq_mhz_falls_back_when_ntpower_fails() -> None:
    """If powrprof is missing, we still get a number — even if it's
    the broken WMI value, that's better than None for the rest of the
    pipeline."""
    with (
        patch("sysspecter.collector.system_sampler._cpu_freq_via_ntpower",
              return_value=(None, None, None)),
        patch("sysspecter.collector.system_sampler.psutil.cpu_freq",
              return_value=type("F", (), {"current": 2500.0,
                                          "min": 0.0, "max": 5200.0})()),
    ):
        assert ss._freq_mhz() == 2500.0


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
