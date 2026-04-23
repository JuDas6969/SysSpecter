"""First-run onboarding dialog.

Shown once, gated by `UserPrefs.first_run_completed`. A 3-choice
routing card: 'Diagnose a slow PC' / 'Compare two machines' /
'Just browse runs'. Each choice switches the notebook to the right
tab and optionally pre-fills a preset.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from tkinter import ttk


class OnboardingDialog(tk.Toplevel):
    """Modal welcome dialog routed to the right tab on click."""

    def __init__(
        self,
        master: tk.Misc,
        *,
        on_choice: Callable[[str], None],
        on_dismiss: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(master)
        self.title("Welcome to SysSpecter")
        self.transient(master)
        self.grab_set()
        self.geometry("520x320")
        self.resizable(False, False)
        self._on_choice = on_choice
        self._on_dismiss = on_dismiss
        self.protocol("WM_DELETE_WINDOW", self._dismiss)

        body = ttk.Frame(self, padding=20)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text="What would you like to do?",
                  font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=(0, 4))
        ttk.Label(body,
                  text="Pick a starting point — you can always switch tabs later.",
                  foreground="#6b7a99").pack(anchor="w", pady=(0, 14))

        def _card(title: str, subtitle: str, tab: str) -> None:
            f = ttk.Frame(body, padding=10, relief="solid", borderwidth=1)
            f.pack(fill="x", pady=4)
            lft = ttk.Frame(f)
            lft.pack(side="left", fill="x", expand=True)
            ttk.Label(lft, text=title, font=("Segoe UI", 11, "bold")).pack(anchor="w")
            ttk.Label(lft, text=subtitle, foreground="#6b7a99").pack(anchor="w")
            ttk.Button(f, text="Start", style="Primary.TButton",
                       command=lambda: self._pick(tab)).pack(side="right")

        _card("Diagnose a slow PC",
              "Monitor tab, 'Support: user complaint' preset, manual stop.",
              tab="monitor")
        _card("Compare two machines",
              "Compare tab with hardware diff + evidence-based recommendations.",
              tab="compare")
        _card("Browse existing runs",
              "Runs tab — open / rebuild / split / sanitize previous sessions.",
              tab="runs")

        ttk.Button(body, text="Dismiss",
                   command=self._dismiss).pack(side="right", pady=(14, 0))

    def _pick(self, tab: str) -> None:
        try:
            self._on_choice(tab)
        finally:
            self._dismiss()

    def _dismiss(self) -> None:
        try:
            self.destroy()
        except tk.TclError:
            pass
        if self._on_dismiss:
            try:
                self._on_dismiss()
            except Exception:
                pass
