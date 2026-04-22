"""Shared Tkinter widgets used across GUI tabs."""

from __future__ import annotations

import queue
import tkinter as tk
from tkinter import ttk
from typing import Callable

from .runner import EXIT_MARKER, SubprocessRunner


class LogPane(ttk.Frame):
    """Scrolling text widget that drains a queue via Tk `after()` polling."""

    POLL_MS = 80

    def __init__(self, master: tk.Misc, **kwargs) -> None:
        super().__init__(master, **kwargs)
        self.text = tk.Text(self, wrap="none", height=12, state="disabled",
                            font=("Consolas", 9), background="#f7f7f9")
        self.vbar = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        self.hbar = ttk.Scrollbar(self, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=self.vbar.set, xscrollcommand=self.hbar.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        self.vbar.grid(row=0, column=1, sticky="ns")
        self.hbar.grid(row=1, column=0, sticky="ew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self._pollers: list[str] = []

    def append(self, line: str) -> None:
        self.text.configure(state="normal")
        self.text.insert("end", line + "\n")
        self.text.see("end")
        self.text.configure(state="disabled")

    def clear(self) -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")

    def poll_runner(
        self,
        runner: SubprocessRunner,
        on_exit: Callable[[int], None] | None = None,
    ) -> None:
        """Start a polling loop that drains `runner.output_queue`."""
        def tick() -> None:
            drained = 0
            try:
                while drained < 200:
                    line = runner.output_queue.get_nowait()
                    if line.startswith(EXIT_MARKER):
                        rc_str = line[len(EXIT_MARKER):]
                        try:
                            rc = int(rc_str)
                        except ValueError:
                            rc = -1
                        self.append(f"[process exited rc={rc}]")
                        if on_exit:
                            on_exit(rc)
                        return  # stop polling
                    self.append(line)
                    drained += 1
            except queue.Empty:
                pass
            self._pollers.append(self.after(self.POLL_MS, tick))
        self._pollers.append(self.after(self.POLL_MS, tick))


class RunsTable(ttk.Frame):
    """Treeview-based table for browsing runs.

    Rows carry an anonymous id; the owner maps id -> run path via `set_rows`.
    """

    COLUMNS = (
        ("run_id", "Run ID", 200),
        ("host", "Host", 110),
        ("mode", "Mode", 80),
        ("duration", "Dur (s)", 70),
        ("score", "Overall", 70),
        ("primary", "Primary", 90),
        ("stop_reason", "Stop", 140),
        ("flags", "Artifacts", 120),
    )

    def __init__(self, master: tk.Misc, selectmode: str = "browse", **kwargs) -> None:
        super().__init__(master, **kwargs)
        self.tree = ttk.Treeview(self,
                                 columns=[c[0] for c in self.COLUMNS],
                                 show="headings",
                                 selectmode=selectmode)
        for key, label, width in self.COLUMNS:
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, anchor="w")
        vbar = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self._paths: dict[str, str] = {}

    def set_rows(self, rows) -> None:
        """rows: iterable of RunInfo objects."""
        self.tree.delete(*self.tree.get_children())
        self._paths.clear()
        for r in rows:
            flags: list[str] = []
            if r.has_final_report:
                flags.append("report")
            if r.has_phases:
                flags.append("phases")
            item_id = self.tree.insert(
                "", "end",
                values=(
                    r.run_id,
                    r.hostname,
                    r.mode,
                    f"{r.duration_seconds:.0f}" if r.duration_seconds is not None else "—",
                    f"{r.overall_score:.0f}" if r.overall_score is not None else "—",
                    r.primary_bottleneck or "—",
                    r.stop_reason or "—",
                    ", ".join(flags) or "—",
                ),
            )
            self._paths[item_id] = r.path

    def selected_paths(self) -> list[str]:
        return [self._paths[i] for i in self.tree.selection() if i in self._paths]

    def bind_double_click(self, callback: Callable[[str], None]) -> None:
        def _handle(event: tk.Event) -> None:
            iid = self.tree.identify_row(event.y)
            if iid and iid in self._paths:
                callback(self._paths[iid])
        self.tree.bind("<Double-1>", _handle)
