"""Phase 3 (optional): Kernel ETW disk-I/O session wrapper.

Captures `NT Kernel Logger`-style disk-I/O events for the duration of the run
using `logman.exe`, then converts the resulting .etl to CSV via `tracerpt.exe`
and aggregates per-process read / write bytes.

This is the strongest Phase 3 signal because psutil on Windows cannot report
per-process disk bytes — ETW is the documented path. Requires admin.

Safe design:
- Unique session name per run (avoids collision with user's own sessions)
- Always stops the session on finalize, even on error
- Degrades silently if admin is missing or logman/tracerpt are unavailable"""

from __future__ import annotations

import csv
import logging
import os
import subprocess
from collections import defaultdict
from typing import Any

CREATE_NO_WINDOW = 0x08000000


def _have_tool(name: str) -> bool:
    from shutil import which
    return which(name) is not None


class EtwDiskSession:
    def __init__(self, etl_path: str, logger: logging.Logger | None = None):
        self.etl_path = etl_path
        self.logger = logger
        self.session_name = f"sysspecter_disk_{os.getpid()}"
        self.started = False

    def start(self) -> bool:
        if not _have_tool("logman.exe"):
            if self.logger:
                self.logger.warning("ETW: logman.exe not on PATH")
            return False

        # Providers keyword NT Kernel Logger "disk" gives FileIo + DiskIo events.
        # Using `logman create trace -ets` with `-p "Windows Kernel Trace" 0x301`
        # (PROCESS | DISK_IO | FILE_IO) captures what we need to attribute bytes
        # to PIDs. -nb/-bs set buffer sizing; -f bincirc with max file size keeps
        # the .etl bounded.
        etl_dir = os.path.dirname(self.etl_path)
        os.makedirs(etl_dir, exist_ok=True)
        cmd = [
            "logman.exe", "create", "trace", self.session_name,
            "-ets",
            "-p", "Windows Kernel Trace", "0x301",
            "-o", self.etl_path,
            "-nb", "16", "256",
            "-bs", "64",
            "-f", "bincirc",
            "-max", "256",
            "-ft", "10",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace",
                                  timeout=15.0, creationflags=CREATE_NO_WINDOW)
        except Exception as e:
            if self.logger:
                self.logger.warning("ETW logman start failed: %s", e)
            return False
        if proc.returncode != 0:
            if self.logger:
                self.logger.warning("ETW logman start rc=%s stderr=%s stdout=%s",
                                    proc.returncode,
                                    (proc.stderr or "").strip()[:200],
                                    (proc.stdout or "").strip()[:200])
            return False
        self.started = True
        return True

    def stop_and_summarize(self, etl_path: str) -> dict[str, Any]:
        """Stop the session, convert ETL to CSV via tracerpt, aggregate per PID."""
        if not self.started:
            return {"enabled": False, "reason": "not_started"}
        # Stop
        try:
            subprocess.run(
                ["logman.exe", "stop", self.session_name, "-ets"],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=30.0, creationflags=CREATE_NO_WINDOW,
            )
        except Exception as e:
            if self.logger:
                self.logger.warning("ETW logman stop failed: %s", e)

        # tracerpt converts to a CSV dump
        if not _have_tool("tracerpt.exe"):
            return {
                "enabled": True, "etl": etl_path,
                "reason": "tracerpt_unavailable",
                "by_pid": [], "totals": {},
            }
        csv_path = etl_path + ".csv"
        summary_path = etl_path + ".summary.xml"
        try:
            proc = subprocess.run(
                ["tracerpt.exe", etl_path,
                 "-o", csv_path, "-summary", summary_path,
                 "-of", "CSV", "-y"],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=180.0, creationflags=CREATE_NO_WINDOW,
            )
        except Exception as e:
            if self.logger:
                self.logger.warning("ETW tracerpt failed: %s", e)
            return {"enabled": True, "etl": etl_path,
                    "reason": f"tracerpt_error:{type(e).__name__}",
                    "by_pid": [], "totals": {}}
        if proc.returncode != 0:
            return {
                "enabled": True, "etl": etl_path,
                "reason": f"tracerpt_rc_{proc.returncode}",
                "stderr": (proc.stderr or "").strip()[:300],
                "by_pid": [], "totals": {},
            }

        return _summarize_csv(csv_path)


def _summarize_csv(csv_path: str) -> dict[str, Any]:
    """Read a tracerpt CSV dump and aggregate FileIo / DiskIo bytes per PID.

    tracerpt's CSV format is quirky — columns vary by event type. We key off
    the `Event Name` column and pull Process ID and byte counts from known
    column positions per event type. The file can be large; we stream it."""
    if not os.path.exists(csv_path):
        return {"enabled": True, "reason": "no_csv_produced",
                "by_pid": [], "totals": {}}

    per_pid_read: dict[int, int] = defaultdict(int)
    per_pid_write: dict[int, int] = defaultdict(int)
    per_pid_read_ops: dict[int, int] = defaultdict(int)
    per_pid_write_ops: dict[int, int] = defaultdict(int)
    per_pid_name: dict[int, str] = {}

    total_events = 0
    matched_events = 0
    with open(csv_path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        current_header: list[str] | None = None
        header_by_event: dict[str, list[str]] = {}
        for row in reader:
            if not row:
                continue
            # tracerpt CSV has per-event header lines that start with the event
            # name. Typical layout: first col is Event Name (or "BeginHeader"),
            # next is "Event Header", etc. We treat any row where first cell
            # looks like a known event type as an event.
            first = row[0].strip()
            if first in ("BeginHeader", "EndHeader"):
                continue
            if first.endswith("Header") or "Event Name" in row or "TID" in row:
                current_header = [c.strip() for c in row]
                # Associate with the preceding event-type tag if any
                continue
            total_events += 1

            # Look up a column by fuzzy name
            def _col(name_substrs: tuple[str, ...]) -> str | None:
                if current_header is None:
                    return None
                for idx, h in enumerate(current_header):
                    hl = h.lower()
                    for ns in name_substrs:
                        if ns in hl:
                            if idx < len(row):
                                return row[idx].strip()
                return None

            ev = first.lower()
            if ev not in ("fileio", "diskio", "fileiow", "diskiow",
                          "read", "write", "fileread", "filewrite",
                          "diskread", "diskwrite"):
                # Some tracerpt dumps use "FileIo" as the event-group name and
                # a sub-name field — keep heuristic tolerant.
                continue

            pid_s = _col(("process id", "pid"))
            bytes_s = _col(("size", "iosize", "bytes"))
            image_s = _col(("image name", "process name"))
            try:
                pid = int(pid_s) if pid_s else 0
            except ValueError:
                pid = 0
            try:
                b = int(bytes_s) if bytes_s else 0
            except ValueError:
                b = 0
            if pid <= 0 or b <= 0:
                continue
            matched_events += 1
            if image_s:
                per_pid_name.setdefault(pid, image_s)
            if "read" in ev:
                per_pid_read[pid] += b
                per_pid_read_ops[pid] += 1
            elif "write" in ev:
                per_pid_write[pid] += b
                per_pid_write_ops[pid] += 1

    rows: list[dict[str, Any]] = []
    pids = set(per_pid_read) | set(per_pid_write)
    for pid in pids:
        rd = per_pid_read.get(pid, 0)
        wr = per_pid_write.get(pid, 0)
        rows.append({
            "pid": pid,
            "name": per_pid_name.get(pid) or "?",
            "read_bytes": rd,
            "write_bytes": wr,
            "read_ops": per_pid_read_ops.get(pid, 0),
            "write_ops": per_pid_write_ops.get(pid, 0),
            "total_bytes": rd + wr,
        })
    rows.sort(key=lambda r: r["total_bytes"], reverse=True)

    totals = {
        "read_bytes": sum(per_pid_read.values()),
        "write_bytes": sum(per_pid_write.values()),
        "events_total": total_events,
        "events_attributed": matched_events,
    }
    return {
        "enabled": True,
        "csv": csv_path,
        "by_pid": rows[:25],
        "totals": totals,
    }
