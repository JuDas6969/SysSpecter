"""SysSpecter GUI main application window."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ..config import DEFAULT_OUTPUT_ROOT
from .tab_compare import CompareTab
from .tab_monitor import MonitorTab
from .tab_runs import RunsTab


_ABOUT_TEXT = (
    "SysSpecter — See everything. Find the cause.\n\n"
    "This GUI is a thin wrapper around the same commands you can run from the "
    "terminal:\n\n"
    "  • Monitor — captures system + process timelines for a session\n"
    "  • Runs — browse finished runs; rebuild, trim, split into phases\n"
    "  • Compare — select 2+ runs; auto-detects before/after / pair / fleet mode\n\n"
    "All reports and artifacts live under the output-root folder "
    f"(default: {DEFAULT_OUTPUT_ROOT}).\n\n"
    "Phase 3 collectors (GPU / event log / ETW disk) are opt-in on the Monitor tab. "
    "ETW requires running as Administrator."
)


class App:
    def __init__(self, output_root: str = DEFAULT_OUTPUT_ROOT) -> None:
        self.root = tk.Tk()
        self.root.title("SysSpecter")
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)

        try:
            ttk.Style().theme_use("vista" if self.root.tk.call("tk", "windowingsystem") == "win32" else "clam")
        except tk.TclError:
            pass

        self._output_root = output_root

        header = ttk.Frame(self.root, padding=(12, 8))
        header.pack(fill="x")
        ttk.Label(header, text="SysSpecter",
                  font=("Segoe UI", 14, "bold")).pack(side="left")
        ttk.Label(header, text="See everything. Find the cause.",
                  foreground="#6b7a99").pack(side="left", padx=12)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.monitor_tab = MonitorTab(
            self.notebook, default_output_root=output_root,
            on_run_finished=self._on_run_finished,
        )
        self.runs_tab = RunsTab(
            self.notebook, default_output_root=output_root,
            get_output_root=lambda: self._output_root,
        )
        self.compare_tab = CompareTab(
            self.notebook, default_output_root=output_root,
            get_output_root=lambda: self._output_root,
        )

        self.notebook.add(self.monitor_tab, text="Monitor")
        self.notebook.add(self.runs_tab, text="Runs")
        self.notebook.add(self.compare_tab, text="Compare")

        about = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(about, text="About")
        lbl = tk.Text(about, wrap="word", height=14, relief="flat",
                      background=about.cget("background"))
        lbl.insert("1.0", _ABOUT_TEXT)
        lbl.configure(state="disabled")
        lbl.pack(fill="both", expand=True)

    def _on_run_finished(self) -> None:
        # Refresh the runs list so newly-completed runs show up.
        try:
            self.runs_tab.refresh()
            self.compare_tab.refresh()
        except Exception:
            pass

    def mainloop(self) -> None:
        self.root.mainloop()


def run_gui(output_root: str = DEFAULT_OUTPUT_ROOT) -> int:
    App(output_root=output_root).mainloop()
    return 0
