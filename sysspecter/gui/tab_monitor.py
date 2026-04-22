"""Monitor tab: configure + start/stop a monitor session."""

from __future__ import annotations

import ctypes
import os
import re
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from .duration import DurationParseError, format_duration, parse_duration
from .runner import SubprocessRunner
from .tooltip import attach as tooltip
from .widgets import LogPane


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


_HEARTBEAT_RE = re.compile(
    r"\[laeuft\]\s+(\d+)m(\d+)s\s+"
    r"(?:(\d+\.\d)% von (\d+)s|manueller Stopp)"
)


_TT_MODE = (
    "support     — free-running 'my PC is slow' diagnostics; use Ctrl+C / Stop to end.\n"
    "baseline    — measure idle noise; targets not needed.\n"
    "workload    — measure a specific app; set Target name/PID/path for best attribution."
)
_TT_DURATION = (
    "Length of the session. Type a number + unit, or use the + / - buttons.\n"
    "Examples: 1800 (default unit = s), 30 min, 1.5 h, 2 hrs, 1 day, 2h 30min, 1,5 min.\n"
    "If 'Manual stop' is ticked, the duration is ignored and the session runs until you press Stop."
)
_TT_UNIT = "Unit used when you typed only a number above. 'auto' keeps whatever unit was parsed from the text."
_TT_MANUAL = "Ignore duration and keep running until Stop (Ctrl+C sends the same STOP signal)."
_TT_TARGET_NAME = "Exe name to watch, e.g. 'StressApp.exe'. The report will mark this process as the 'target'."
_TT_TARGET_PID = "Process ID to watch. Preferred when there are multiple instances with the same name."
_TT_TARGET_PATH = "Full path to the executable. Matches regardless of how the process was spawned."
_TT_TAGS = (
    "Free-text labels stored in the manifest, used by 'compare' to correlate runs. "
    "Comma-separated, e.g. 'autopilot, vpn-on, gpu-off'."
)
_TT_LAT = (
    "ICMP-pinged hosts for per-second latency probes. Comma-separated. "
    "Defaults hit loopback + Google DNS + Cloudflare DNS; add internal gateways if relevant."
)
_TT_OUTPUT = (
    "Where runs and comparisons are written. Defaults to C:\\Temp\\SysSpecter on a dev install "
    "or <exe_dir>\\SysSpecter when running the portable EXE from a USB stick."
)
_TT_GPU = "Sample GPU engine/memory every 30 s (Phase 3). Low overhead."
_TT_EVENT = "Pull Windows event-log entries for the run window. May be slow on busy machines."
_TT_ETW = "Kernel-level disk-I/O per-process trace. Needs Administrator rights."
_TT_ALL3 = "Enable all three optional Phase 3 collectors at once."
_TT_START = "Kick off the monitor run. Artifacts go under <Output root>\\Runs\\<HOST>_<timestamp>\\."
_TT_STOP = (
    "Send the STOP signal to the running session. Finalization (report, analyzer, markdown) "
    "runs automatically -- do not close the window while it is shutting down."
)


class MonitorTab(ttk.Frame):
    def __init__(
        self,
        master: tk.Misc,
        default_output_root: str,
        on_run_finished: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(master, padding=10)
        self._output_root = tk.StringVar(value=default_output_root)
        self._mode = tk.StringVar(value="support")
        self._duration_value = tk.StringVar(value="30")
        self._duration_unit = tk.StringVar(value="min")
        self._manual_stop = tk.BooleanVar(value=True)
        self._target_name = tk.StringVar(value="")
        self._target_pid = tk.StringVar(value="")
        self._target_path = tk.StringVar(value="")
        self._tags = tk.StringVar(value="")
        self._latency_targets = tk.StringVar(value="127.0.0.1, 8.8.8.8, 1.1.1.1")
        self._enable_gpu = tk.BooleanVar(value=False)
        self._enable_eventlog = tk.BooleanVar(value=False)
        self._enable_etw = tk.BooleanVar(value=False)

        self._runner: SubprocessRunner | None = None
        self._stopper: SubprocessRunner | None = None
        self._on_run_finished = on_run_finished

        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(99, weight=1)

        form = ttk.LabelFrame(self, text="Session options", padding=8)
        form.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        form.columnconfigure(1, weight=1)

        # --- Mode
        mode_lbl = ttk.Label(form, text="Mode:")
        mode_lbl.grid(row=0, column=0, sticky="w", pady=2)
        tooltip(mode_lbl, _TT_MODE)
        mode_frame = ttk.Frame(form)
        mode_frame.grid(row=0, column=1, sticky="w")
        for i, (val, txt) in enumerate((("support", "support"),
                                        ("baseline", "baseline"),
                                        ("workload", "workload"))):
            rb = ttk.Radiobutton(mode_frame, text=txt, value=val, variable=self._mode)
            rb.grid(row=0, column=i, padx=(0, 8))
            tooltip(rb, _TT_MODE)

        # --- Duration
        dur_lbl = ttk.Label(form, text="Duration:")
        dur_lbl.grid(row=1, column=0, sticky="w", pady=2)
        tooltip(dur_lbl, _TT_DURATION)

        dur_frame = ttk.Frame(form)
        dur_frame.grid(row=1, column=1, sticky="w")
        dur_entry = ttk.Entry(dur_frame, textvariable=self._duration_value, width=10)
        dur_entry.grid(row=0, column=0)
        tooltip(dur_entry, _TT_DURATION)

        unit_combo = ttk.Combobox(
            dur_frame, textvariable=self._duration_unit, width=6, state="readonly",
            values=("s", "min", "h", "d"),
        )
        unit_combo.grid(row=0, column=1, padx=(4, 0))
        tooltip(unit_combo, _TT_UNIT)

        self._dur_preview = tk.StringVar(value="")
        preview = ttk.Label(dur_frame, textvariable=self._dur_preview,
                            foreground="#555", font=("Segoe UI", 9, "italic"))
        preview.grid(row=0, column=2, padx=(10, 0))
        self._duration_value.trace_add("write", lambda *a: self._refresh_preview())
        self._duration_unit.trace_add("write", lambda *a: self._refresh_preview())

        manual_cb = ttk.Checkbutton(dur_frame, text="Manual stop (ignore duration)",
                                    variable=self._manual_stop)
        manual_cb.grid(row=0, column=3, padx=(16, 0))
        tooltip(manual_cb, _TT_MANUAL)
        self._refresh_preview()

        # --- Targets
        tn_lbl = ttk.Label(form, text="Target name:")
        tn_lbl.grid(row=2, column=0, sticky="w", pady=2)
        tooltip(tn_lbl, _TT_TARGET_NAME)
        tn_entry = ttk.Entry(form, textvariable=self._target_name)
        tn_entry.grid(row=2, column=1, sticky="ew", pady=2)
        tooltip(tn_entry, _TT_TARGET_NAME)

        tp_lbl = ttk.Label(form, text="Target PID:")
        tp_lbl.grid(row=3, column=0, sticky="w", pady=2)
        tooltip(tp_lbl, _TT_TARGET_PID)
        tp_entry = ttk.Entry(form, textvariable=self._target_pid, width=10)
        tp_entry.grid(row=3, column=1, sticky="w", pady=2)
        tooltip(tp_entry, _TT_TARGET_PID)

        tpath_lbl = ttk.Label(form, text="Target path:")
        tpath_lbl.grid(row=4, column=0, sticky="w", pady=2)
        tooltip(tpath_lbl, _TT_TARGET_PATH)
        tpath_entry = ttk.Entry(form, textvariable=self._target_path)
        tpath_entry.grid(row=4, column=1, sticky="ew", pady=2)
        tooltip(tpath_entry, _TT_TARGET_PATH)

        # --- Tags
        tag_lbl = ttk.Label(form, text="Tags (comma-separated):")
        tag_lbl.grid(row=5, column=0, sticky="w", pady=2)
        tooltip(tag_lbl, _TT_TAGS)
        tag_entry = ttk.Entry(form, textvariable=self._tags)
        tag_entry.grid(row=5, column=1, sticky="ew", pady=2)
        tooltip(tag_entry, _TT_TAGS)

        # --- Latency
        lat_lbl = ttk.Label(form, text="Latency targets:")
        lat_lbl.grid(row=6, column=0, sticky="w", pady=2)
        tooltip(lat_lbl, _TT_LAT)
        lat_entry = ttk.Entry(form, textvariable=self._latency_targets)
        lat_entry.grid(row=6, column=1, sticky="ew", pady=2)
        tooltip(lat_entry, _TT_LAT)

        # --- Output root
        out_lbl = ttk.Label(form, text="Output root:")
        out_lbl.grid(row=7, column=0, sticky="w", pady=2)
        tooltip(out_lbl, _TT_OUTPUT)
        out_frame = ttk.Frame(form)
        out_frame.grid(row=7, column=1, sticky="ew", pady=2)
        out_frame.columnconfigure(0, weight=1)
        out_entry = ttk.Entry(out_frame, textvariable=self._output_root)
        out_entry.grid(row=0, column=0, sticky="ew")
        tooltip(out_entry, _TT_OUTPUT)
        browse_btn = ttk.Button(out_frame, text="Browse...", command=self._pick_output)
        browse_btn.grid(row=0, column=1, padx=(6, 0))
        tooltip(browse_btn, "Pick a different folder to store this session's artifacts.")

        # --- Phase 3
        p3 = ttk.LabelFrame(self, text="Phase 3 optional collectors", padding=8)
        p3.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        gpu_cb = ttk.Checkbutton(p3, text="GPU metrics", variable=self._enable_gpu)
        gpu_cb.grid(row=0, column=0, padx=6)
        tooltip(gpu_cb, _TT_GPU)
        ev_cb = ttk.Checkbutton(p3, text="Windows event log", variable=self._enable_eventlog)
        ev_cb.grid(row=0, column=1, padx=6)
        tooltip(ev_cb, _TT_EVENT)
        etw_cb = ttk.Checkbutton(p3, text="ETW disk I/O (admin req.)", variable=self._enable_etw)
        etw_cb.grid(row=0, column=2, padx=6)
        tooltip(etw_cb, _TT_ETW)
        all3_btn = ttk.Button(p3, text="Enable all", command=self._enable_all_phase3)
        all3_btn.grid(row=0, column=3, padx=(16, 0))
        tooltip(all3_btn, _TT_ALL3)

        # --- Actions
        # Admin warning banner
        if not _is_admin():
            warn = ttk.Label(
                self,
                text=("⚠ Not running as Administrator — ETW disk I/O, some WMI "
                      "classes, and handle counts on protected processes are unavailable."),
                foreground="#a8071a", background="#fff1f0",
                padding=(10, 6),
            )
            warn.grid(row=2, column=0, sticky="ew", pady=(0, 6))

        # --- Actions
        actions = ttk.Frame(self)
        actions.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        self.start_btn = ttk.Button(actions, text="Start monitor", command=self._start)
        self.start_btn.grid(row=0, column=0, padx=(0, 8))
        tooltip(self.start_btn, _TT_START)
        self.stop_btn = ttk.Button(actions, text="Stop (graceful)", command=self._stop,
                                   state="disabled")
        self.stop_btn.grid(row=0, column=1, padx=(0, 8))
        tooltip(self.stop_btn, _TT_STOP)
        self.status = tk.StringVar(value="idle")
        ttk.Label(actions, textvariable=self.status, foreground="#555").grid(
            row=0, column=2, padx=(12, 0),
        )

        # --- Progress bar
        progress_row = ttk.Frame(self)
        progress_row.grid(row=4, column=0, sticky="ew", pady=(0, 8))
        progress_row.columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(progress_row, mode="determinate", maximum=100)
        self.progress.grid(row=0, column=0, sticky="ew")
        self.progress_label = tk.StringVar(value="")
        ttk.Label(progress_row, textvariable=self.progress_label,
                  foreground="#555", width=24, anchor="e").grid(
            row=0, column=1, padx=(8, 0),
        )

        ttk.Label(self, text="Live output:").grid(row=98, column=0, sticky="w")
        self.log = LogPane(self)
        self.log.grid(row=99, column=0, sticky="nsew")
        # Tap the log stream so the progress bar updates from heartbeats.
        self.log.on_line = self._on_log_line

    # --------------------------------------------------------------- Helpers
    def _refresh_preview(self) -> None:
        try:
            s = self._duration_seconds(raise_on_empty=False)
            if s is None or s <= 0:
                self._dur_preview.set("")
            else:
                self._dur_preview.set(f"= {format_duration(s)} ({int(s)} s)")
        except DurationParseError as e:
            self._dur_preview.set(f"! {e}")

    def _duration_seconds(self, raise_on_empty: bool = True) -> float | None:
        text = self._duration_value.get().strip()
        unit = self._duration_unit.get().strip() or "s"
        if not text:
            if raise_on_empty:
                raise DurationParseError("duration is empty")
            return None
        return parse_duration(text, default_unit=unit)

    def _pick_output(self) -> None:
        path = filedialog.askdirectory(
            initialdir=self._output_root.get() or os.path.expanduser("~"),
            title="Select output root folder",
        )
        if path:
            self._output_root.set(path)

    def _enable_all_phase3(self) -> None:
        self._enable_gpu.set(True)
        self._enable_eventlog.set(True)
        self._enable_etw.set(True)

    def _build_args(self) -> list[str] | None:
        args = ["monitor", "--mode", self._mode.get()]
        if self._manual_stop.get():
            args.append("--manual-stop")
        else:
            try:
                secs = self._duration_seconds()
            except DurationParseError as e:
                messagebox.showerror(
                    "SysSpecter",
                    f"Duration not understood: {e}\n\nExamples: 1800, 30 min, 1.5 h, 2 hrs, 1 day.",
                )
                return None
            if secs is None or secs <= 0:
                messagebox.showerror("SysSpecter", "Duration must be > 0 or tick 'Manual stop'.")
                return None
            args.extend(["--duration", str(int(secs))])
        if self._target_name.get().strip():
            args.extend(["--target-name", self._target_name.get().strip()])
        if self._target_pid.get().strip():
            args.extend(["--target-pid", self._target_pid.get().strip()])
        if self._target_path.get().strip():
            args.extend(["--target-path", self._target_path.get().strip()])
        for tag in [t.strip() for t in self._tags.get().split(",") if t.strip()]:
            args.extend(["--tag", tag])
        for host in [t.strip() for t in self._latency_targets.get().split(",") if t.strip()]:
            args.extend(["--latency-target", host])
        args.extend(["--output-root", self._output_root.get()])
        if self._enable_gpu.get():
            args.append("--gpu")
        if self._enable_eventlog.get():
            args.append("--event-logs")
        if self._enable_etw.get():
            args.append("--etw")
        return args

    # ---------------------------------------------------------------- Actions
    def _start(self) -> None:
        if self._runner and self._runner.is_running():
            return
        args = self._build_args()
        if args is None:
            return
        self.log.clear()
        self.log.append(f"$ sysspecter {' '.join(args)}")
        self._runner = SubprocessRunner(args)
        try:
            self._runner.start()
        except Exception as e:
            self.log.append(f"failed to spawn: {e}")
            return
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status.set("running")
        self.log.poll_runner(self._runner, on_exit=self._on_exit)

    def _stop(self) -> None:
        if not (self._runner and self._runner.is_running()):
            return
        self.status.set("stopping")
        self.stop_btn.configure(state="disabled")
        stop_args = ["stop", "--output-root", self._output_root.get()]
        self.log.append(f"$ sysspecter {' '.join(stop_args)}")
        self._stopper = SubprocessRunner(stop_args)
        try:
            self._stopper.start()
            self.log.poll_runner(self._stopper)
        except Exception as e:
            self.log.append(f"stop command failed: {e}")
            self._runner.send_ctrl_break()

    def _on_exit(self, rc: int) -> None:
        self.status.set(f"finished (rc={rc})")
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        try:
            self.progress.configure(value=100 if rc == 0 else 0)
            self.progress_label.set("")
        except Exception:
            pass
        if self._on_run_finished:
            self._on_run_finished()

    def _on_log_line(self, line: str) -> None:
        """Update progress bar + ETA from the collector's heartbeat lines."""
        m = _HEARTBEAT_RE.search(line)
        if not m:
            return
        mins, secs = int(m.group(1)), int(m.group(2))
        elapsed = mins * 60 + secs
        pct_str = m.group(3)
        total_str = m.group(4)
        if pct_str and total_str:
            try:
                pct = float(pct_str)
                total = int(total_str)
            except ValueError:
                return
            self.progress.configure(mode="determinate", value=pct)
            remaining = max(0, total - elapsed)
            rm_min, rm_sec = divmod(remaining, 60)
            self.progress_label.set(f"{pct:.0f}% — {rm_min:02d}:{rm_sec:02d} left")
        else:
            # manual stop — indeterminate
            if self.progress.cget("mode") != "indeterminate":
                self.progress.configure(mode="indeterminate")
                self.progress.start(80)
            self.progress_label.set(f"running {mins:02d}:{secs:02d}")
