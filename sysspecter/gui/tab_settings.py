"""Settings tab: persistent user preferences for the GUI.

Fields mirror the monitor-tab defaults plus a theme toggle and an
output-root MRU. Saving writes to `%APPDATA%\\SysSpecter\\config.toml`
and notifies the host app so the other tabs can refresh.
"""

from __future__ import annotations

import os
import tkinter as tk
from collections.abc import Callable
from tkinter import filedialog, messagebox, ttk

from ..settings import UserPrefs, config_path, load_prefs, push_output_root, save_prefs
from .tooltip import attach as tooltip


class SettingsTab(ttk.Frame):
    def __init__(
        self,
        master: tk.Misc,
        *,
        prefs: UserPrefs,
        on_saved: Callable[[UserPrefs], None] | None = None,
    ) -> None:
        super().__init__(master, padding=16)
        self._prefs = prefs
        self._on_saved = on_saved

        self._output_root = tk.StringVar(value=(prefs.output_root_mru[0]
                                                if prefs.output_root_mru else ""))
        self._mode = tk.StringVar(value=prefs.default_mode)
        self._duration = tk.IntVar(value=prefs.default_duration_seconds)
        self._manual_stop = tk.BooleanVar(value=prefs.default_manual_stop)
        self._latency = tk.StringVar(
            value=", ".join(prefs.default_latency_targets))
        self._phase3_gpu = tk.BooleanVar(value=prefs.default_phase3_gpu)
        self._phase3_ev = tk.BooleanVar(value=prefs.default_phase3_event_logs)
        self._phase3_etw = tk.BooleanVar(value=prefs.default_phase3_etw_disk)
        self._theme = tk.StringVar(value=prefs.theme)
        self._check_updates = tk.BooleanVar(value=prefs.check_updates_on_start)

        self._status_var = tk.StringVar(value="")

        self._build_ui()

    def _build_ui(self) -> None:
        self.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(self, text="Configuration file:",
                  font=("Segoe UI", 10, "bold")).grid(row=row, column=0, sticky="w", pady=(0, 2))
        row += 1
        ttk.Label(self, text=config_path(), foreground="#6b7a99",
                  font=("Consolas", 9)).grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 14))
        row += 1

        # Output root
        ttk.Label(self, text="Default output root:").grid(row=row, column=0, sticky="w", pady=4)
        out_frame = ttk.Frame(self)
        out_frame.grid(row=row, column=1, columnspan=2, sticky="ew", pady=4)
        out_frame.columnconfigure(0, weight=1)

        # Use a Combobox so MRU entries are selectable
        self._output_root_combo = ttk.Combobox(
            out_frame, textvariable=self._output_root,
            values=list(self._prefs.output_root_mru),
        )
        self._output_root_combo.grid(row=0, column=0, sticky="ew")
        browse = ttk.Button(out_frame, text="Browse…", command=self._browse_output_root)
        browse.grid(row=0, column=1, padx=(6, 0))
        tooltip(self._output_root_combo,
                "Where runs are written. Drop-down shows the 5 most recently used folders.")
        row += 1

        # Default mode
        ttk.Label(self, text="Default mode:").grid(row=row, column=0, sticky="w", pady=4)
        mode_frame = ttk.Frame(self)
        mode_frame.grid(row=row, column=1, columnspan=2, sticky="w", pady=4)
        for i, val in enumerate(("support", "baseline", "workload")):
            ttk.Radiobutton(mode_frame, text=val, value=val,
                            variable=self._mode).grid(row=0, column=i, padx=(0, 12))
        row += 1

        # Default duration
        ttk.Label(self, text="Default duration (s):").grid(row=row, column=0, sticky="w", pady=4)
        dur_frame = ttk.Frame(self)
        dur_frame.grid(row=row, column=1, columnspan=2, sticky="w", pady=4)
        ttk.Spinbox(dur_frame, from_=30, to=86400, increment=60,
                    textvariable=self._duration, width=10).grid(row=0, column=0)
        ttk.Checkbutton(dur_frame, text="Manual stop (ignore duration by default)",
                        variable=self._manual_stop).grid(row=0, column=1, padx=(12, 0))
        row += 1

        # Latency targets
        ttk.Label(self, text="Default latency targets:").grid(row=row, column=0, sticky="w", pady=4)
        lat_entry = ttk.Entry(self, textvariable=self._latency)
        lat_entry.grid(row=row, column=1, columnspan=2, sticky="ew", pady=4)
        tooltip(lat_entry,
                "Comma-separated hosts / IPs for ICMP latency probes.")
        row += 1

        # Phase 3 defaults
        ttk.Label(self, text="Default Phase 3 collectors:").grid(row=row, column=0, sticky="w", pady=4)
        p3_frame = ttk.Frame(self)
        p3_frame.grid(row=row, column=1, columnspan=2, sticky="w", pady=4)
        ttk.Checkbutton(p3_frame, text="GPU",
                        variable=self._phase3_gpu).grid(row=0, column=0, padx=(0, 12))
        ttk.Checkbutton(p3_frame, text="Event log",
                        variable=self._phase3_ev).grid(row=0, column=1, padx=(0, 12))
        ttk.Checkbutton(p3_frame, text="ETW disk (admin)",
                        variable=self._phase3_etw).grid(row=0, column=2)
        row += 1

        # Theme
        ttk.Label(self, text="Theme:").grid(row=row, column=0, sticky="w", pady=4)
        theme_frame = ttk.Frame(self)
        theme_frame.grid(row=row, column=1, columnspan=2, sticky="w", pady=4)
        for i, val in enumerate(("light", "dark")):
            rb = ttk.Radiobutton(theme_frame, text=val.capitalize(),
                                 value=val, variable=self._theme)
            rb.grid(row=0, column=i, padx=(0, 12))
        hint = ttk.Label(theme_frame, text=" (dark mode previewed in a future release)",
                         foreground="#6b7a99", font=("Segoe UI", 9, "italic"))
        hint.grid(row=0, column=2, sticky="w")
        row += 1

        # Update checker
        ttk.Label(self, text="On startup:").grid(row=row, column=0, sticky="w", pady=4)
        ttk.Checkbutton(self, text="Check for newer SysSpecter releases",
                        variable=self._check_updates).grid(
            row=row, column=1, columnspan=2, sticky="w", pady=4)
        row += 1

        # Actions
        action_frame = ttk.Frame(self)
        action_frame.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(18, 0))
        save_btn = ttk.Button(action_frame, text="Save", command=self._save,
                              style="Primary.TButton")
        save_btn.grid(row=0, column=0, padx=(0, 8))
        tooltip(save_btn, "Write preferences to config.toml and apply them.")
        reset_btn = ttk.Button(action_frame, text="Reset to defaults",
                               command=self._reset)
        reset_btn.grid(row=0, column=1, padx=(0, 8))
        tooltip(reset_btn, "Restore factory settings (does not delete the file).")
        ttk.Label(action_frame, textvariable=self._status_var,
                  foreground="#389e0d").grid(row=0, column=2, padx=(12, 0))

    # -------------------------------------------------------------- helpers

    def _browse_output_root(self) -> None:
        path = filedialog.askdirectory(
            initialdir=self._output_root.get() or os.path.expanduser("~"),
            title="Select output root folder",
        )
        if path:
            self._output_root.set(path)

    def _current_prefs(self) -> UserPrefs:
        targets = [s.strip() for s in self._latency.get().split(",") if s.strip()]
        prefs = UserPrefs(
            output_root_mru=list(self._prefs.output_root_mru),
            default_mode=self._mode.get(),
            default_duration_seconds=int(self._duration.get() or 0),
            default_manual_stop=bool(self._manual_stop.get()),
            default_latency_targets=targets,
            default_phase3_gpu=bool(self._phase3_gpu.get()),
            default_phase3_event_logs=bool(self._phase3_ev.get()),
            default_phase3_etw_disk=bool(self._phase3_etw.get()),
            theme=self._theme.get(),
            show_admin_banner=self._prefs.show_admin_banner,
            check_updates_on_start=bool(self._check_updates.get()),
        )
        root = self._output_root.get().strip()
        if root:
            prefs = push_output_root(prefs, root)
        return prefs

    def _save(self) -> None:
        try:
            prefs = self._current_prefs()
            path = save_prefs(prefs)
        except OSError as e:
            messagebox.showerror("SysSpecter", f"Could not save settings:\n{e}")
            return
        self._prefs = prefs
        self._output_root_combo.configure(values=list(prefs.output_root_mru))
        self._status_var.set(f"Saved → {path}")
        self.after(3500, lambda: self._status_var.set(""))
        if self._on_saved:
            try:
                self._on_saved(prefs)
            except Exception:
                pass

    def _reset(self) -> None:
        if not messagebox.askyesno("SysSpecter",
                                   "Reset every preference to factory defaults?"):
            return
        defaults = UserPrefs()
        self._mode.set(defaults.default_mode)
        self._duration.set(defaults.default_duration_seconds)
        self._manual_stop.set(defaults.default_manual_stop)
        self._latency.set(", ".join(defaults.default_latency_targets))
        self._phase3_gpu.set(defaults.default_phase3_gpu)
        self._phase3_ev.set(defaults.default_phase3_event_logs)
        self._phase3_etw.set(defaults.default_phase3_etw_disk)
        self._theme.set(defaults.theme)
        self._check_updates.set(defaults.check_updates_on_start)
        self._status_var.set("Defaults restored — click Save to persist.")


def load_initial_prefs() -> UserPrefs:
    return load_prefs()
