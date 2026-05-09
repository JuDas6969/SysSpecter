"""v1.3.0 Phase A.0: tracemalloc-based self-leak diagnostic.

Activated by `--profile-leak`. Captures `tracemalloc` snapshots every
60 s of run time, keeps the last 20 (oldest dropped), and writes a
`leak_profile.txt` to the run dir at run-end with:

  1. snapshot_last.compare_to(snapshot_first, 'lineno')[:30] — the top
     30 source locations growing fastest, with byte-deltas.
  2. snapshot_last.statistics('filename') — totals per file, sorted.

The point: pinpoint the exact source line(s) responsible for the
self-leak observed in v1.2.x (RSS == VMS, ~140 KB/s on MORGANA, etc.)
before changing any logic. The four hypotheses in the v1.3 plan are
guesses from outside the binary; this picks the actual culprit.

Soft-degrades on every error path. tracemalloc itself imposes ~5–15 %
overhead on the sampler — too expensive for default-on, so we gate
behind a CLI flag.
"""

from __future__ import annotations

import logging
import os
import tracemalloc
from typing import Any

_log = logging.getLogger("sysspecter.leak_profiler")

# How many frames per traceback. 25 is plenty for nearly all stacks
# Python builds at runtime; bigger numbers cost memory.
_FRAMES = 25

# Cap on retained snapshots (each ~1–10 MB depending on alloc count).
# 20 minutes of context at the 60 s cadence is enough to spot a
# linear leak; anything beyond is diminishing returns.
_MAX_SNAPSHOTS = 20

# Top-N rows to surface in the report.
_TOP_LINENO = 30
_TOP_FILE = 30


class LeakProfiler:
    """Periodic tracemalloc snapshotter. Caller invokes:

        prof = LeakProfiler.start_if_enabled(config.profile_leak)
        ...
        if prof: prof.maybe_snapshot(now_mono)   # in the runner loop
        ...
        if prof: prof.write_report(run_dir)      # at run end
    """

    _ENABLED: bool = False

    def __init__(self) -> None:
        self._snapshots: list[tracemalloc.Snapshot] = []
        self._next_snapshot_mono: float | None = None
        self._first_snapshot_at: float | None = None

    @classmethod
    def start_if_enabled(cls, enabled: bool) -> LeakProfiler | None:
        if not enabled:
            return None
        try:
            tracemalloc.start(_FRAMES)
            inst = cls()
            cls._ENABLED = True
            _log.info("tracemalloc started (frames=%d)", _FRAMES)
            return inst
        except Exception as e:
            _log.warning("could not start tracemalloc: %s", e)
            return None

    def maybe_snapshot(self, now_mono: float) -> None:
        """Take a snapshot if 60 s have elapsed since the last one."""
        if self._next_snapshot_mono is None:
            # First call: take an immediate baseline snapshot, then
            # arm the next one for +60 s.
            self._take_snapshot(now_mono)
            self._first_snapshot_at = now_mono
            self._next_snapshot_mono = now_mono + 60.0
            return
        if now_mono >= self._next_snapshot_mono:
            self._take_snapshot(now_mono)
            self._next_snapshot_mono = now_mono + 60.0

    def _take_snapshot(self, now_mono: float) -> None:
        try:
            snap = tracemalloc.take_snapshot()
            self._snapshots.append(snap)
            if len(self._snapshots) > _MAX_SNAPSHOTS:
                self._snapshots.pop(0)
        except Exception as e:
            _log.debug("tracemalloc.take_snapshot failed: %s", e)

    def write_report(self, run_dir: str) -> None:
        """Write `leak_profile.txt` to the run dir. Safe to call even
        when no snapshots were taken (e.g. very short run)."""
        try:
            tracemalloc.stop()
        except Exception:
            pass
        if not self._snapshots:
            _log.info("no tracemalloc snapshots collected; skipping report")
            return
        first = self._snapshots[0]
        last = self._snapshots[-1]
        path = os.path.join(run_dir, "leak_profile.txt")
        try:
            lines: list[str] = []
            lines.append("=" * 78)
            lines.append("SysSpecter self-leak profile (--profile-leak)")
            lines.append("=" * 78)
            lines.append(f"snapshots: {len(self._snapshots)} (cap {_MAX_SNAPSHOTS})")
            lines.append(f"window: {self._first_snapshot_at:.1f} s "
                         f"to {self._first_snapshot_at + 60 * len(self._snapshots):.1f} s "
                         f"(approx)")
            lines.append("")
            lines.append("Top growing source locations (last vs first snapshot):")
            lines.append("-" * 78)
            try:
                growth = last.compare_to(first, "lineno")
            except Exception as e:
                lines.append(f"compare_to failed: {e}")
                growth = []
            for stat in growth[:_TOP_LINENO]:
                # stat.size_diff is bytes, can be negative when freed.
                size_kb = stat.size_diff / 1024.0
                count_diff = stat.count_diff
                tb = stat.traceback
                where = (tb.format()[0] if tb else "?")
                lines.append(
                    f"  {size_kb:+9.1f} KB  ({count_diff:+6d} blocks)  {where.strip()}"
                )
            lines.append("")
            lines.append("Per-file totals (last snapshot):")
            lines.append("-" * 78)
            try:
                file_stats = last.statistics("filename")
            except Exception as e:
                lines.append(f"statistics(filename) failed: {e}")
                file_stats = []
            for stat in file_stats[:_TOP_FILE]:
                fname = stat.traceback[0].filename if stat.traceback else "?"
                lines.append(
                    f"  {stat.size / 1024.0:9.1f} KB  ({stat.count} blocks)  {fname}"
                )
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            _log.info("leak profile written: %s", path)
        except Exception as e:
            _log.warning("could not write leak_profile.txt: %s", e)


def summarise_for_findings(prof: LeakProfiler | None) -> dict[str, Any]:
    """Return a small dict that can be embedded in `findings.json` so
    the report knows whether profiling was active and where the
    detail file lives. Empty dict when profiling was off.
    """
    if prof is None:
        return {}
    return {
        "tracemalloc_enabled": True,
        "snapshots_collected": len(prof._snapshots),
        "report_filename": "leak_profile.txt",
    }
