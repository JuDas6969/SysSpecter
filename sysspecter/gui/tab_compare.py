"""Compare tab: multi-select runs, kick off `sysspecter compare`."""

from __future__ import annotations

import os
import subprocess
import tkinter as tk
from collections.abc import Callable
from tkinter import messagebox, ttk

from .runner import SubprocessRunner
from .runs import scan_runs
from .tooltip import attach as tooltip
from .widgets import LogPane, RunsTable

_TT_OUTPUT = ("Folder that contains Runs/. Comparison output lands in "
              "<this folder>/Comparisons/CMP_<timestamp>_<id>/.")
_TT_REFRESH = "Re-scan the output root (Ctrl+R)."
_TT_SELECT_ALL = "Select every visible run."
_TT_CLEAR = "Unselect everything."
_TT_START = ("Run the comparison on the selected runs. Mode is auto-detected "
             "from hostnames: all the same = before/after, exactly 2 distinct = "
             "pair diagnosis, 3+ = fleet. Hardware/software/config diffs and "
             "evidence-based recommendations are included in the report.")
_TT_OPEN = "Open the most recently generated comparison_report.html."


class CompareTab(ttk.Frame):
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
        self._latest_output_dir: str | None = None
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        # Layout (each widget in its OWN row so nothing overlaps):
        #   row 0  top bar (Output root + Refresh)
        #   row 1  help label
        #   row 2  runs table           <- stretches (weight=2)
        #   row 3  action buttons
        #   row 4  progress bar
        #   row 5  "Comparer output:" label
        #   row 6  log pane              <- stretches (weight=1)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=2)
        self.rowconfigure(6, weight=1)

        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        top.columnconfigure(1, weight=1)
        lbl = ttk.Label(top, text="Output root:")
        lbl.grid(row=0, column=0, sticky="w", padx=(0, 6), pady=4)
        tooltip(lbl, _TT_OUTPUT)
        ent = ttk.Entry(top, textvariable=self._output_root_var)
        ent.grid(row=0, column=1, sticky="ew", padx=(0, 6), pady=4)
        tooltip(ent, _TT_OUTPUT)
        btn_ref = ttk.Button(top, text="Refresh", command=self.refresh)
        btn_ref.grid(row=0, column=2, pady=4)
        tooltip(btn_ref, _TT_REFRESH)

        help_lbl = ttk.Label(self, foreground="#555",
                             text="Select 2+ runs (Ctrl/Shift-click), then 'Start compare'. "
                                  "Mode is auto-detected from hostnames.")
        help_lbl.grid(row=1, column=0, sticky="w", pady=(0, 8))

        self.table = RunsTable(self, selectmode="extended")
        self.table.grid(row=2, column=0, sticky="nsew")

        actions = ttk.Frame(self)
        actions.grid(row=3, column=0, sticky="ew", pady=(8, 8))
        sel_all = ttk.Button(actions, text="Select all", command=self._select_all)
        sel_all.grid(row=0, column=0, padx=(0, 6))
        tooltip(sel_all, _TT_SELECT_ALL)
        clr = ttk.Button(actions, text="Clear selection", command=self._clear_sel)
        clr.grid(row=0, column=1, padx=(0, 6))
        tooltip(clr, _TT_CLEAR)
        start = ttk.Button(actions, text="Start compare", command=self._start)
        start.grid(row=0, column=2, padx=(0, 6))
        tooltip(start, _TT_START)
        self.open_btn = ttk.Button(actions, text="Open last report", command=self._open_last,
                                   state="disabled")
        self.open_btn.grid(row=0, column=3, padx=(0, 6))
        tooltip(self.open_btn, _TT_OPEN)
        self.cancel_btn = ttk.Button(actions, text="Cancel", command=self._cancel,
                                     state="disabled")
        self.cancel_btn.grid(row=0, column=4, padx=(0, 6))
        tooltip(self.cancel_btn, "Abort the running comparison.")

        # Progress bar — indeterminate while the child runs.
        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.grid(row=4, column=0, sticky="ew", pady=(0, 6))

        ttk.Label(self, text="Comparer output:").grid(row=5, column=0, sticky="w",
                                                      pady=(0, 2))
        self.log = LogPane(self)
        self.log.grid(row=6, column=0, sticky="nsew")

    def refresh(self) -> None:
        try:
            rows = scan_runs(self._get_output_root())
        except Exception as e:
            self.log.append(f"scan failed: {e}")
            rows = []
        self.table.set_rows(rows)
        self.log.append(f"[refresh: {len(rows)} run(s) under {self._get_output_root()}]")

    def _select_all(self) -> None:
        self.table.tree.selection_set(self.table.tree.get_children())

    def _clear_sel(self) -> None:
        self.table.tree.selection_remove(self.table.tree.get_children())

    def _start(self) -> None:
        paths = self.table.selected_paths()
        if len(paths) < 2:
            messagebox.showinfo("SysSpecter", "Select at least 2 runs to compare.")
            return
        if self._runner and self._runner.is_running():
            messagebox.showinfo("SysSpecter", "A comparison is already running.")
            return
        args = ["compare", "--runs"] + paths + ["--output-root", self._get_output_root()]
        self.log.append(f"$ sysspecter compare --runs <{len(paths)} runs> "
                        f"--output-root {self._get_output_root()}")
        self._runner = SubprocessRunner(args)
        try:
            self._runner.start()
        except Exception as e:
            self.log.append(f"failed to spawn: {e}")
            return
        self._latest_output_dir = None
        self.open_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        try:
            self.progress.configure(mode="indeterminate")
            self.progress.start(80)
        except Exception:
            pass
        self.log.poll_runner(self._runner, on_exit=self._on_exit)

    def _cancel(self) -> None:
        if self._runner and self._runner.is_running():
            try:
                self._runner.send_ctrl_break()
            except Exception:
                pass
            # give it a moment, then hard-kill
            self.after(2000, self._force_kill)

    def _force_kill(self) -> None:
        if self._runner and self._runner.is_running():
            try:
                self._runner.kill()
            except Exception:
                pass

    def _on_exit(self, rc: int) -> None:
        try:
            self.progress.stop()
            self.progress.configure(value=0)
        except Exception:
            pass
        self.cancel_btn.configure(state="disabled")
        if rc == 0:
            root = self._get_output_root()
            cmp_root = os.path.join(root, "Comparisons")
            try:
                dirs = [os.path.join(cmp_root, d) for d in os.listdir(cmp_root)
                        if os.path.isdir(os.path.join(cmp_root, d))]
                if dirs:
                    dirs.sort(key=lambda p: os.path.getmtime(p), reverse=True)
                    self._latest_output_dir = dirs[0]
                    self.open_btn.configure(state="normal")
                    self.log.append(f"[latest comparison: {dirs[0]}]")
            except OSError:
                pass

    def _open_last(self) -> None:
        if not self._latest_output_dir:
            return
        report = os.path.join(self._latest_output_dir, "comparison_report.html")
        if os.path.exists(report):
            try:
                os.startfile(report)  # type: ignore[attr-defined]
            except AttributeError:
                subprocess.Popen(["xdg-open", report])
        else:
            messagebox.showwarning("SysSpecter", f"Report not found: {report}")
