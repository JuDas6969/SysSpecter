"""Runs tab: browse existing runs, open reports, rebuild/trim/split."""

from __future__ import annotations

import os
import shutil
import subprocess
import tkinter as tk
import zipfile
from collections.abc import Callable
from tkinter import messagebox, simpledialog, ttk

from .runner import SubprocessRunner
from .runs import scan_runs
from .tooltip import attach as tooltip
from .widgets import LogPane, RunsTable

_TT = {
    "output_root": ("Folder that contains the Runs/ subdirectory. Defaults to "
                    "C:\\Temp\\SysSpecter on a dev install, or <exe_dir>\\SysSpecter "
                    "on the portable EXE."),
    "refresh": "Re-scan the output root and update the table. Shortcut: Ctrl+R.",
    "open_report": ("Open the selected run's final_report.html. "
                    "Double-click a row does the same thing."),
    "open_folder": "Open the selected run folder in Windows Explorer.",
    "rebuild": ("Re-run the analyzer + reporter on the stored CSVs. Use this when a "
                "report is outdated or was produced by an older tool version."),
    "trim": ("Rebuild the report considering only the first N seconds of captured "
             "data -- handy when the operator forgot to Stop and the tail is idle."),
    "split": ("Detect phase boundaries (step / slope / inflection / process-end) and "
              "emit a sub-report per phase plus a phases_report.html overview."),
    "inspect": "Print a short console summary (verdict + top scores).",
    "delete": ("Permanently delete the selected run folder. There is NO undo. "
               "You are asked to confirm first."),
    "archive": ("Zip the selected run next to its folder for sharing "
                "(good for sending findings to a vendor without exposing the live tree)."),
    "sanitize": ("Produce a de-identified copy: hostnames, FQDN, BIOS / disk serials, "
                 "user paths are replaced with [REDACTED] and the report is re-rendered. "
                 "Use before forwarding findings to an external vendor."),
}


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
        # Layout (each widget in its OWN row so nothing overlaps):
        #   row 0  top bar (Output root + Refresh)
        #   row 1  filter bar
        #   row 2  runs table           <- stretches (weight=2)
        #   row 3  action buttons
        #   row 4  "Command output:" label
        #   row 5  log pane              <- stretches (weight=1)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=2)
        self.rowconfigure(5, weight=1)

        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        top.columnconfigure(1, weight=1)
        lbl = ttk.Label(top, text="Output root:")
        lbl.grid(row=0, column=0, sticky="w", padx=(0, 6), pady=4)
        tooltip(lbl, _TT["output_root"])
        ent = ttk.Entry(top, textvariable=self._output_root_var)
        ent.grid(row=0, column=1, sticky="ew", padx=(0, 6), pady=4)
        tooltip(ent, _TT["output_root"])
        btn_refresh = ttk.Button(top, text="Refresh", command=self.refresh)
        btn_refresh.grid(row=0, column=2, pady=4)
        tooltip(btn_refresh, _TT["refresh"])

        # Filter toolbar (hostname / tag / substring)
        filter_bar = ttk.Frame(self)
        filter_bar.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        filter_bar.columnconfigure(1, weight=1)
        ttk.Label(filter_bar, text="Filter:").grid(row=0, column=0, sticky="w")
        self._filter_var = tk.StringVar(value="")
        filter_entry = ttk.Entry(filter_bar, textvariable=self._filter_var)
        filter_entry.grid(row=0, column=1, sticky="ew", padx=(6, 6))
        tooltip(filter_entry,
                "Substring match across run_id, hostname, mode, tags, "
                "and primary bottleneck. Case-insensitive.")
        self._match_count_var = tk.StringVar(value="")
        ttk.Label(filter_bar, textvariable=self._match_count_var,
                  foreground="#6b7a99").grid(row=0, column=2, padx=(0, 6))
        ttk.Button(filter_bar, text="Clear",
                   command=lambda: self._filter_var.set("")).grid(row=0, column=3)
        self._filter_var.trace_add("write", lambda *a: self._apply_filter())
        self._all_rows: list = []  # cached full scan

        self.table = RunsTable(self, selectmode="browse")
        self.table.grid(row=2, column=0, sticky="nsew")
        self.table.bind_double_click(lambda p: self._open_report(p))

        # Action buttons — split onto two rows so Archive / Delete are not
        # clipped on narrower windows (960 px minimum).
        actions = ttk.Frame(self)
        actions.grid(row=3, column=0, sticky="ew", pady=(8, 8))
        defs_row_1 = [
            ("Open report", self._action_open_report, _TT["open_report"]),
            ("Open folder", self._action_open_folder, _TT["open_folder"]),
            ("Rebuild", self._action_rebuild, _TT["rebuild"]),
            ("Rebuild (trim…)", self._action_trim, _TT["trim"]),
            ("Split", self._action_split, _TT["split"]),
        ]
        defs_row_2 = [
            ("Sanitize", self._action_sanitize, _TT["sanitize"]),
            ("Inspect", self._action_inspect, _TT["inspect"]),
            ("Archive ZIP", self._action_archive, _TT["archive"]),
            ("Delete", self._action_delete, _TT["delete"]),
        ]
        for col, (label, cmd, tip) in enumerate(defs_row_1):
            btn = ttk.Button(actions, text=label, command=cmd)
            btn.grid(row=0, column=col, padx=(0, 6), pady=(0, 4), sticky="w")
            tooltip(btn, tip)
        for col, (label, cmd, tip) in enumerate(defs_row_2):
            btn = ttk.Button(actions, text=label, command=cmd)
            btn.grid(row=1, column=col, padx=(0, 6), sticky="w")
            tooltip(btn, tip)

        ttk.Label(self, text="Command output:").grid(row=4, column=0, sticky="w",
                                                     pady=(0, 2))
        self.log = LogPane(self)
        self.log.grid(row=5, column=0, sticky="nsew")

    # ------------------------------------------------------------------ helpers
    def refresh(self) -> None:
        try:
            rows = scan_runs(self._get_output_root())
        except Exception as e:
            self.log.append(f"scan failed: {e}")
            rows = []
        self._all_rows = list(rows)
        self._apply_filter()
        self.log.append(f"[refresh: {len(rows)} run(s) under {self._get_output_root()}]")

    def _apply_filter(self) -> None:
        needle = (self._filter_var.get() or "").strip().lower()
        if not needle:
            visible = self._all_rows
        else:
            def _match(r) -> bool:
                # M2: include meta + tags in the searchable haystack so a
                # filter like `ticket:PERF-1234` or `engineering` finds
                # runs by their structured metadata.
                meta_str = " ".join(
                    f"{k}:{v} {v}" for k, v in (r.meta or {}).items()
                )
                tags_str = " ".join(r.tags or [])
                haystack = " ".join(filter(None, [
                    r.run_id, r.hostname, r.mode,
                    r.primary_bottleneck,
                    r.stop_reason,
                    meta_str, tags_str,
                ])).lower()
                return needle in haystack
            visible = [r for r in self._all_rows if _match(r)]
        self.table.set_rows(visible)
        self._match_count_var.set(
            f"{len(visible)} / {len(self._all_rows)}" if self._all_rows else ""
        )

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

    def _action_sanitize(self) -> None:
        path = self._require_selection()
        if not path:
            return
        self._launch(["sanitize", "--run", path])

    def _action_inspect(self) -> None:
        path = self._require_selection()
        if not path:
            return
        self._launch(["inspect", "--run", path])

    def _action_archive(self) -> None:
        path = self._require_selection()
        if not path:
            return
        parent = os.path.dirname(path)
        base = os.path.basename(path)
        zip_path = os.path.join(parent, base + ".zip")
        if os.path.exists(zip_path):
            if not messagebox.askyesno(
                "SysSpecter",
                f"{zip_path} already exists. Overwrite?",
            ):
                return
            try:
                os.remove(zip_path)
            except OSError as e:
                messagebox.showerror("SysSpecter", f"Cannot overwrite existing ZIP: {e}")
                return
        self.log.append(f"[archive] zipping {base} -> {os.path.basename(zip_path)}")
        try:
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for root, _dirs, files in os.walk(path):
                    for name in files:
                        full = os.path.join(root, name)
                        arc = os.path.relpath(full, parent)
                        zf.write(full, arc)
        except OSError as e:
            messagebox.showerror("SysSpecter", f"Archive failed: {e}")
            return
        self.log.append(f"[archive] done: {zip_path}")
        messagebox.showinfo("SysSpecter", f"Archive written:\n{zip_path}")

    def _action_delete(self) -> None:
        path = self._require_selection()
        if not path:
            return
        base = os.path.basename(path)
        if not messagebox.askyesno(
            "Delete run",
            f"Permanently delete this run?\n\n{base}\n\nThis cannot be undone.",
            icon="warning",
        ):
            return
        try:
            shutil.rmtree(path)
        except OSError as e:
            messagebox.showerror("SysSpecter", f"Delete failed: {e}")
            return
        self.log.append(f"[delete] removed {base}")
        self.refresh()
