"""Global configuration: defaults, thresholds, latency targets.

All thresholds are documented so the report can explain the logic."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field


def _default_output_root() -> str:
    """Pick a sensible default output root.

    When running as a PyInstaller-frozen EXE (e.g. from a USB stick), we
    want reports to land next to the executable so the whole workflow
    stays on the stick. Otherwise fall back to the conventional location
    under C:\\Temp.
    """
    if getattr(sys, "frozen", False):
        try:
            exe_dir = os.path.dirname(os.path.abspath(sys.executable))
            return os.path.join(exe_dir, "SysSpecter")
        except Exception:
            pass
    return r"C:\Temp\SysSpecter"


DEFAULT_OUTPUT_ROOT = _default_output_root()
DEFAULT_INTERVAL_SECONDS = 1.0
DEFAULT_DURATION_SECONDS_BASELINE = 1800
DEFAULT_DURATION_SECONDS_WORKLOAD = 1800

EXPENSIVE_COLLECTOR_INTERVAL = 30
PROCESS_ENUM_REFRESH_INTERVAL = 10
TOP_N_PROCESSES = 20
LATENCY_PROBE_INTERVAL = 15
# v3-priority-4 (H1): per-PID handle counts by object type. The
# system-wide handle table on a busy host can be 100 MB+; sampling
# every minute keeps the cost near zero while still giving the
# leak detector enough resolution to spot a 1000 handles/min growth.
HANDLES_PROBE_INTERVAL = 60
HANDLES_TOP_N_PIDS = 50

DEFAULT_LATENCY_TARGETS = [
    "127.0.0.1",
    "8.8.8.8",
    "1.1.1.1",
]


@dataclass
class Thresholds:
    cpu_sustained_pct: float = 85.0
    cpu_sustained_seconds: int = 10

    cpu_single_core_pct: float = 95.0
    cpu_single_core_seconds: int = 10

    mem_used_pct_high: float = 85.0
    mem_used_pct_critical: float = 93.0
    mem_commit_growth_mb_per_min: float = 50.0

    disk_active_pct: float = 85.0
    disk_active_seconds: int = 8

    net_latency_ms_high: float = 200.0
    net_latency_ms_critical: float = 500.0

    handle_growth_per_min_suspicious: float = 50.0
    handle_growth_per_min_likely: float = 150.0
    thread_growth_per_min_suspicious: float = 10.0
    thread_growth_per_min_likely: float = 30.0

    leak_min_duration_seconds: int = 120
    leak_min_slope_bytes_per_sec: float = 50_000.0

    slowdown_merge_gap_seconds: int = 5
    slowdown_min_duration_seconds: int = 3


@dataclass
class Config:
    output_root: str = DEFAULT_OUTPUT_ROOT
    interval: float = DEFAULT_INTERVAL_SECONDS
    mode: str = "support"
    duration: int | None = None
    target_name: str | None = None
    target_pid: int | None = None
    target_path: str | None = None
    tags: list[str] = field(default_factory=list)
    # Field-review M2: structured fleet metadata. `tags` stays as a
    # free-form list for backwards compatibility; `meta` carries
    # well-defined keys (department / ticket / scenario / change /
    # machine_class) that downstream tools can filter on without
    # parsing free-text. Always lower-cased keys, str values.
    meta: dict[str, str] = field(default_factory=dict)
    latency_targets: list[str] = field(default_factory=lambda: list(DEFAULT_LATENCY_TARGETS))
    manual_stop: bool = False
    thresholds: Thresholds = field(default_factory=Thresholds)

    # Phase 3 optional collectors (all default off; opt-in via CLI)
    enable_gpu: bool = False
    enable_event_logs: bool = False
    enable_etw_disk: bool = False
