"""Streaming CSV writers for timeline data.

Opened once per run, flushed per row, closed at end. No in-memory accumulation."""

from __future__ import annotations

import csv
from typing import Any, IO


SYSTEM_FIELDS = [
    "timestamp", "rel_seconds",
    "cpu_total_pct", "cpu_per_core_pct", "cpu_freq_current_mhz",
    "ctx_switches_per_sec", "interrupts_per_sec", "proc_queue_len",
    "mem_total_bytes", "mem_available_bytes", "mem_used_bytes", "mem_percent",
    "swap_total_bytes", "swap_used_bytes", "swap_percent",
    "commit_used_bytes", "commit_total_bytes",
    "disk_read_bytes_per_sec", "disk_write_bytes_per_sec",
    "disk_read_count_per_sec", "disk_write_count_per_sec", "disk_active_pct_est",
    "net_sent_bytes_per_sec", "net_recv_bytes_per_sec",
    "net_packets_sent_per_sec", "net_packets_recv_per_sec",
    "net_errin_per_sec", "net_errout_per_sec",
    "net_dropin_per_sec", "net_dropout_per_sec",
]

PROCESS_FIELDS = [
    "timestamp", "rel_seconds", "pid", "name",
    "cpu_pct", "rss_bytes", "vms_bytes",
    "num_threads", "num_handles",
    "io_read_bps", "io_write_bps",
    "cpu_time_user", "cpu_time_system",
    "username", "ppid", "is_target",
]

NETWORK_FIELDS = [
    "timestamp", "rel_seconds", "adapter",
    "bytes_sent_per_sec", "bytes_recv_per_sec",
    "packets_sent_per_sec", "packets_recv_per_sec",
    "errin_per_sec", "errout_per_sec",
    "dropin_per_sec", "dropout_per_sec",
    "is_up", "speed_mbps", "connections_established",
]

LATENCY_FIELDS = [
    "timestamp", "rel_seconds", "target", "count",
    "avg_ms", "min_ms", "max_ms", "jitter_ms", "loss_pct", "raw_times_ms",
]


class StreamingCSV:
    def __init__(self, path: str, fields: list[str]):
        self.path = path
        self.fields = fields
        self._fh: IO[str] | None = None
        self._writer: csv.DictWriter | None = None

    def open(self) -> None:
        self._fh = open(self.path, "w", encoding="utf-8", newline="")
        self._writer = csv.DictWriter(self._fh, fieldnames=self.fields, extrasaction="ignore")
        self._writer.writeheader()

    def write(self, row: dict[str, Any]) -> None:
        assert self._writer is not None
        self._writer.writerow(row)

    def write_many(self, rows: list[dict[str, Any]]) -> None:
        assert self._writer is not None
        self._writer.writerows(rows)

    def flush(self) -> None:
        if self._fh is not None:
            self._fh.flush()

    def close(self) -> None:
        if self._fh is not None:
            self._fh.flush()
            self._fh.close()
            self._fh = None
            self._writer = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()
