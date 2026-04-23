"""First-run onboarding dialog.

Shown once, gated by `UserPrefs.first_run_completed`. A 3-choice
routing card: 'Diagnose a slow PC' / 'Compare two machines' /
'Browse existing runs'. Each choice switches the notebook to the
right tab.

The dialog uses wraplength-based labels and sizes itself from
content rather than a fixed geometry so the cards never clip the
subtitle. The user can still resize it.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable
from tkinter import ttk

_CARDS = (
    ("monitor",
     "Diagnose a slow PC",
     "Start the Monitor tab with the 'Support: user complaint' preset. "
     "Manual stop — leave it running until the user reproduces the problem."),
    ("compare",
     "Compare two machines",
     "Pick two or more finished runs. SysSpecter auto-detects whether you "
     "want a before/after, a pair diagnosis, or a fleet overview — and "
     "emits hardware/software diffs plus evidence-based recommendations."),
    ("runs",
     "Browse existing runs",
     "Jump to the Runs tab — open, rebuild, trim, split, sanitize, or "
     "archive any session you already captured."),
)


class OnboardingDialog(tk.Toplevel):
    """Modal welcome dialog routed to the right tab on click."""

    WRAP = 380          # body-text wrap width, in pixels
    WIDTH_HINT = 580    # initial window width

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
        self.minsize(540, 460)
        self.resizable(True, True)
        self._on_choice = on_choice
        self._on_dismiss = on_dismiss
        self.protocol("WM_DELETE_WINDOW", self._dismiss)

        body = ttk.Frame(self, padding=20)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)

        ttk.Label(body, text="What would you like to do?",
                  font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=(0, 4))
        ttk.Label(
            body,
            text="Pick a starting point — you can switch tabs anytime.",
            foreground="#6b7a99",
            wraplength=self.WIDTH_HINT - 40,
        ).pack(anchor="w", pady=(0, 14))

        for tab_id, title, subtitle in _CARDS:
            self._make_card(body, tab_id, title, subtitle)

        # Bottom action row
        btn_row = ttk.Frame(body)
        btn_row.pack(fill="x", pady=(14, 0))
        ttk.Label(btn_row,
                  text=("Tip: this dialog appears once. "
                        "Delete %APPDATA%\\SysSpecter\\config.toml to see it again."),
                  foreground="#6b7a99",
                  wraplength=self.WIDTH_HINT - 160,
                  font=("Segoe UI", 9, "italic")).pack(side="left")
        ttk.Button(btn_row, text="Dismiss",
                   command=self._dismiss).pack(side="right")

        # Size + centre after the widget tree knows its requested dimensions.
        self.update_idletasks()
        self._center_on_parent(master)
        try:
            self.grab_set()
        except tk.TclError:
            pass

    # ------------------------------------------------------------------ UI
    def _make_card(self, parent: tk.Misc, tab_id: str, title: str,
                   subtitle: str) -> None:
        card = ttk.Frame(parent, padding=12, relief="solid", borderwidth=1)
        card.pack(fill="x", pady=4)
        card.columnconfigure(0, weight=1)

        ttk.Label(card, text=title,
                  font=("Segoe UI", 11, "bold")).grid(
            row=0, column=0, sticky="w",
        )
        ttk.Label(card, text=subtitle, foreground="#6b7a99",
                  wraplength=self.WRAP, justify="left").grid(
            row=1, column=0, sticky="ew", pady=(2, 0),
        )
        btn = ttk.Button(card, text="Start", style="Primary.TButton",
                         command=lambda t=tab_id: self._pick(t))
        btn.grid(row=0, column=1, rowspan=2, sticky="e", padx=(14, 0))

    def _center_on_parent(self, master: tk.Misc) -> None:
        try:
            w = max(self.WIDTH_HINT, self.winfo_reqwidth())
            h = self.winfo_reqheight()
            master.update_idletasks()
            mx = master.winfo_rootx()
            my = master.winfo_rooty()
            mw = master.winfo_width()
            mh = master.winfo_height()
            x = mx + (mw - w) // 2
            y = my + (mh - h) // 3
            self.geometry(f"{w}x{h}+{max(x, 20)}+{max(y, 20)}")
        except tk.TclError:
            pass

    # --------------------------------------------------------------- actions
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
