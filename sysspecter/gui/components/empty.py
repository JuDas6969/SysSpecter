"""Empty-state widget for list/table surfaces."""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import ttk

from ...theme import COLORS, TYPOGRAPHY


class EmptyState(ttk.Frame):
    """Placeholder shown when a data view has nothing to display.

    Usage:
        empty = EmptyState(parent,
            headline="No runs yet",
            body="Go to the Monitor tab and start one.",
            action_text="Go to Monitor",
            on_action=lambda: notebook.select(monitor_tab),
        )
        empty.pack(expand=True, fill="both")
    """

    def __init__(
        self,
        master: tk.Misc,
        *,
        headline: str,
        body: str = "",
        action_text: str | None = None,
        on_action=None,
        icon_path: str | None = None,
    ) -> None:
        super().__init__(master, padding=24)
        self._images: list[tk.PhotoImage] = []

        # Optional icon
        if icon_path and os.path.exists(icon_path):
            try:
                img = tk.PhotoImage(file=icon_path)
                # shrink to ~80 px height
                factor = max(1, img.height() // 80)
                img = img.subsample(factor, factor)
                self._images.append(img)
                ttk.Label(self, image=img).pack(pady=(0, 8))
            except tk.TclError:
                pass

        ttk.Label(self, text=headline,
                  font=(TYPOGRAPHY.family, TYPOGRAPHY.size_h2, "bold"),
                  foreground=COLORS.fg_primary).pack(pady=(0, 6))
        if body:
            ttk.Label(self, text=body, foreground=COLORS.fg_muted,
                      wraplength=480, justify="center").pack(pady=(0, 12))
        if action_text and on_action is not None:
            ttk.Button(self, text=action_text, command=on_action).pack()
