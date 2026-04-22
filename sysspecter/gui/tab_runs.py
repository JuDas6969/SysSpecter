"""Runs tab: browse existing runs, open reports, rebuild/trim/split."""

from __future__ import annotations

import os
import subprocess
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from typing import Callable

from .runner import SubprocessRunner
from .runs import scan_runs
from .widgets import LogPane, RunsTable


class RunsTab(ttk.Frame):
    def __init__(
        self,
        master: tk.Misc,
        default_output_root: str,
        get_output_root: Callable[[], str] | None = None,
    ) -> None:
        super().__init__(master, padding=10)
        self._output_root_var = tk.StringVar(value=default_output_root)
        self._get_output_root = get_output_root or (lambda: self._output_root_var.get())
        self._runner: SubprocessRunner | None = None
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=2)
        self.rowconfigure(3, weight=1)

        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text="Output root:").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self._output_root_var).grid(row=0, column=1, sticky="ew", padx=(6, 6))
        ttk.Button(top, text="Refresh", command=self.refresh).grid(row=0, column=2)

        self.table = RunsTable(self, selectmode="browse")
        self.table.grid(row=1, column=0, sticky="nsew")
        self.table.bind_double_click(lambda p: self._open_report(p))

        actions = ttk.Frame(self)
        actions.grid(row=2, column=0, sticky="ew", pady=(8, 8))
        ttk.Button(actions, text="Open report", command=self._action_open_report).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(actions, text="Open folder", command=self._action_open_folder).grid(row=0, column=1, padx=(0, 6))
        ttk.Button(actions, text="Rebuild report", command=self._action_rebuild).grid(row=0, column=2, padx=(0, 6))
        ttk.Button(actions, text="Rebuild (trim…)", command=self._action_trim).grid(row=0, column=3, padx=(0, 6))
        ttk.Button(actions, text="Split into phases", command=self._action_split).grid(row=0, column=4, padx=(0, 6))
        ttk.Button(actions, text="Inspect", command=self._action_inspect).grid(row=0, column=5, padx=(0, 6))

        ttk.Label(self, text="Command output:").grid(row=2, column=0, sticky="sw", pady=(0, 0))
        self.log = LogPane(self)
        self.log.grid(row=3, column=0, sticky="nsew")

    # ------------------------------------------------------------------ helpers
    def refresh(self) -> None:
        try:
            rows = scan_runs(self._get_output_root())
        except Exception as e:
            self.log.append(f"scan failed: {e}")
            rows = []
        self.table.set_rows(rows)
        self.log.append(f"[refresh: {len(rows)} run(s) under {self._get_output_root()}]")

    def _require_selection(self) -> str | None:
        paths = self.table.selected_paths()
        if not paths:
            messagebox.showinfo("SysSpecter", "Select a run first.")
            return None
        return paths[0]

    def _launch(self, args: list[str]) -> None:
        if self._runner and self._runner.is_running():
            messagebox.showinfo("SysSpecter", "A command is already running.")
            return
        self.log.append(f"$ sysspecter {' '.join(args)}")
        self._runner = SubprocessRunner(args)
        try:
            self._runner.start()
        except Exception as e:
            self.log.append(f"failed to spawn: {e}")
            return
        self.log.poll_runner(self._runner, on_exit=lambda rc: self.refresh())

    # -------------------------------------------------------------- actions
    def _action_open_report(self) -> None:
        path = self._require_selection()
        if path:
            self._open_report(path)

    def _open_report(self, run_path: str) -> None:
        report = os.path.join(run_path, "final_report.html")
        if not os.path.exists(report):
            messagebox.showwarning("SysSpecter",
                                   f"No final_report.html in {run_path}. Use 'Rebuild report' first.")
            return
        try:
            os.startfile(report)  # type: ignore[attr-defined]
        except AttributeError:
            subprocess.Popen(["xdg-open", report])

    def _action_open_folder(self) -> None:
        path = self._require_selection()
        if not path:
            return
        try:
            os.startfile(path)  # type: ignore[attr-defined]
        except AttributeError:
            subprocess.Popen(["xdg-open", path])

    def _action_rebuild(self) -> None:
        path = self._require_selection()
        if not path:
            return
        self._launch(["report", "--run", path])

    def _action_trim(self) -> None:
        path = self._require_selection()
        if not path:
            return
        val = simpledialog.askfloat("Rebuild with trim",
                                    "Trim to first N seconds:",
                                    minvalue=1.0, parent=self)
        if val is None:
            return
        self._launch(["report", "--run", path, "--trim-seconds", str(val)])

    def _action_split(self) -> None:
        path = self._require_selection()
        if not path:
            return
        self._launch(["split", "--run", path])

    def _action_inspect(self) -> None:
        path = self._require_selection()
        if not path:
            return
        self._launch(["inspect", "--run", path])
