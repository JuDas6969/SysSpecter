"""Bottom status bar: version, output root, admin flag, current op.

Shared by every tab. Callers push transient messages with
`set_status("Sanitizing run…")` and clear them back to the default
with `clear_status()`.
"""

from __future__ import annotations

import ctypes
import os
import tkinter as tk
from tkinter import ttk

from ... import __version__ as _SS_VERSION
from ...theme import COLORS, TYPOGRAPHY


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


class StatusBar(ttk.Frame):
    """Thin footer with three slots: version, context, status message."""

    SEP = "  ·  "

    def __init__(self, master: tk.Misc, *, get_output_root) -> None:
        super().__init__(master, padding=(10, 4))
        self._get_output_root = get_output_root
        self._status_var = tk.StringVar(value="ready")
        self._context_var = tk.StringVar(value="")
        self._version_var = tk.StringVar(
            value=f"SysSpecter v{_SS_VERSION}",
        )
        self._admin = _is_admin()

        ttk.Label(self, textvariable=self._version_var,
                  foreground=COLORS.fg_muted,
                  font=(TYPOGRAPHY.family, 8)).pack(side="left")
        ttk.Label(self, text=self.SEP,
                  foreground=COLORS.fg_muted).pack(side="left")
        ttk.Label(self, textvariable=self._context_var,
                  foreground=COLORS.fg_muted,
                  font=(TYPOGRAPHY.family, 8)).pack(side="left")

        # Right side: status message, in brand-cyan while busy
        self._status_label = ttk.Label(
            self, textvariable=self._status_var,
            foreground=COLORS.fg_muted,
            font=(TYPOGRAPHY.family, 8),
        )
        self._status_label.pack(side="right")

        self.refresh_context()

    def refresh_context(self) -> None:
        try:
            root = self._get_output_root() or "?"
        except Exception:
            root = "?"
        parts = [f"output={os.path.basename(root.rstrip(os.sep)) or root}"]
        parts.append("admin" if self._admin else "user")
        self._context_var.set(self.SEP.join(parts))

    def set_status(self, text: str, *, busy: bool = True) -> None:
        self._status_var.set(text)
        color = COLORS.brand_cyan if busy else COLORS.fg_muted
        try:
            self._status_label.configure(foreground=color)
        except tk.TclError:
            pass

    def clear_status(self) -> None:
        self.set_status("ready", busy=False)
