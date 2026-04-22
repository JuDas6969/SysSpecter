"""Monitor tab: configure + start/stop a monitor session."""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, ttk
from typing import Callable

from .runner import SubprocessRunner
from .widgets import LogPane


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
        self._duration = tk.StringVar(value="1800")
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
        self.rowconfigure(99, weight=1)  # log area at bottom

        form = ttk.LabelFrame(self, text="Session options", padding=8)
        form.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Mode:").grid(row=0, column=0, sticky="w", pady=2)
        mode_frame = ttk.Frame(form)
        mode_frame.grid(row=0, column=1, sticky="w")
        for i, (val, txt) in enumerate((("support", "support"),
                                        ("baseline", "baseline"),
                                        ("workload", "workload"))):
            ttk.Radiobutton(mode_frame, text=txt, value=val,
                            variable=self._mode).grid(row=0, column=i, padx=(0, 8))

        ttk.Label(form, text="Duration (s):").grid(row=1, column=0, sticky="w", pady=2)
        dur_frame = ttk.Frame(form)
        dur_frame.grid(row=1, column=1, sticky="w")
        ttk.Entry(dur_frame, textvariable=self._duration, width=10).grid(row=0, column=0)
        ttk.Checkbutton(dur_frame, text="Manual stop (ignore duration)",
                        variable=self._manual_stop).grid(row=0, column=1, padx=(10, 0))

        ttk.Label(form, text="Target name:").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Entry(form, textvariable=self._target_name).grid(row=2, column=1, sticky="ew", pady=2)
        ttk.Label(form, text="Target PID:").grid(row=3, column=0, sticky="w", pady=2)
        ttk.Entry(form, textvariable=self._target_pid, width=10).grid(row=3, column=1, sticky="w", pady=2)
        ttk.Label(form, text="Target path:").grid(row=4, column=0, sticky="w", pady=2)
        ttk.Entry(form, textvariable=self._target_path).grid(row=4, column=1, sticky="ew", pady=2)

        ttk.Label(form, text="Tags (comma-separated):").grid(row=5, column=0, sticky="w", pady=2)
        ttk.Entry(form, textvariable=self._tags).grid(row=5, column=1, sticky="ew", pady=2)

        ttk.Label(form, text="Latency targets:").grid(row=6, column=0, sticky="w", pady=2)
        ttk.Entry(form, textvariable=self._latency_targets).grid(row=6, column=1, sticky="ew", pady=2)

        ttk.Label(form, text="Output root:").grid(row=7, column=0, sticky="w", pady=2)
        out_frame = ttk.Frame(form)
        out_frame.grid(row=7, column=1, sticky="ew", pady=2)
        out_frame.columnconfigure(0, weight=1)
        ttk.Entry(out_frame, textvariable=self._output_root).grid(row=0, column=0, sticky="ew")
        ttk.Button(out_frame, text="Browse…", command=self._pick_output).grid(row=0, column=1, padx=(6, 0))

        p3 = ttk.LabelFrame(self, text="Phase 3 optional collectors", padding=8)
        p3.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        ttk.Checkbutton(p3, text="GPU metrics", variable=self._enable_gpu).grid(row=0, column=0, padx=6)
        ttk.Checkbutton(p3, text="Windows event log", variable=self._enable_eventlog).grid(row=0, column=1, padx=6)
        ttk.Checkbutton(p3, text="ETW disk I/O (admin req.)", variable=self._enable_etw).grid(row=0, column=2, padx=6)
        ttk.Button(p3, text="Enable all", command=self._enable_all_phase3).grid(row=0, column=3, padx=(16, 0))

        actions = ttk.Frame(self)
        actions.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        self.start_btn = ttk.Button(actions, text="Start monitor", command=self._start)
        self.start_btn.grid(row=0, column=0, padx=(0, 8))
        self.stop_btn = ttk.Button(actions, text="Stop (graceful)", command=self._stop, state="disabled")
        self.stop_btn.grid(row=0, column=1, padx=(0, 8))
        self.status = tk.StringVar(value="idle")
        ttk.Label(actions, textvariable=self.status, foreground="#555").grid(row=0, column=2, padx=(12, 0))

        ttk.Label(self, text="Live output:").grid(row=98, column=0, sticky="w")
        self.log = LogPane(self)
        self.log.grid(row=99, column=0, sticky="nsew")

    # --------------------------------------------------------------- Helpers
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

    def _build_args(self) -> list[str]:
        args = ["monitor", "--mode", self._mode.get()]
        if self._manual_stop.get():
            args.append("--manual-stop")
        else:
            dur = self._duration.get().strip()
            if dur:
                args.extend(["--duration", dur])
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
        """Preferred stop path: spawn `sysspecter stop` which writes STOP file."""
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
            # Fall back to signaling the process directly
            self._runner.send_ctrl_break()

    def _on_exit(self, rc: int) -> None:
        self.status.set(f"finished (rc={rc})")
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        if self._on_run_finished:
            self._on_run_finished()
