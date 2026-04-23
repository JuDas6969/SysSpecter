"""Tiny toast-notification service.

`ToastService` is attached to the root window once and exposes
`show(text, kind="info" | "success" | "warn" | "error")`. Toasts stack
top-right, auto-dismiss after `ttl_ms`, and can be dismissed by
clicking.
"""

from __future__ import annotations

import tkinter as tk
from typing import Literal

from ...theme import COLORS, TYPOGRAPHY

Kind = Literal["info", "success", "warn", "error"]


_KIND_STYLE: dict[str, tuple[str, str, str]] = {
    # (bg, fg, border)
    "info":    (COLORS.bg_subtle, COLORS.fg_primary, COLORS.bg_divider),
    "success": (COLORS.ok_bg, COLORS.ok_fg, COLORS.ok_border),
    "warn":    (COLORS.warn_bg, COLORS.warn_fg_strong, COLORS.warn_border),
    "error":   (COLORS.danger_bg, COLORS.danger_fg_strong, COLORS.danger_border),
}


class ToastService:
    def __init__(self, root: tk.Misc, *, ttl_ms: int = 3000) -> None:
        self.root = root
        self.ttl_ms = ttl_ms
        self._toasts: list[tk.Toplevel] = []

    def show(self, text: str, kind: Kind = "info") -> None:
        try:
            bg, fg, border = _KIND_STYLE.get(kind, _KIND_STYLE["info"])
            tip = tk.Toplevel(self.root)
            tip.wm_overrideredirect(True)
            tip.configure(background=border)
            # Pack the frame with a 1 px border, label inside
            frame = tk.Frame(tip, background=bg, padx=12, pady=8)
            frame.pack(padx=1, pady=1, fill="both", expand=True)
            tk.Label(frame, text=text, background=bg, foreground=fg,
                     font=(TYPOGRAPHY.family, TYPOGRAPHY.size_body),
                     justify="left", wraplength=360).pack()
            self._position(tip)
            tip.bind("<Button-1>", lambda _e, t=tip: self._dismiss(t))
            self._toasts.append(tip)
            self.root.after(self.ttl_ms, lambda t=tip: self._dismiss(t))
        except tk.TclError:
            # no display or window destroyed — silently drop
            pass

    def _position(self, tip: tk.Toplevel) -> None:
        self.root.update_idletasks()
        try:
            x = self.root.winfo_rootx() + self.root.winfo_width() - 400
            y = self.root.winfo_rooty() + 60 + 70 * len(self._toasts)
            tip.wm_geometry(f"+{max(x, 50)}+{y}")
        except tk.TclError:
            pass

    def _dismiss(self, tip: tk.Toplevel) -> None:
        try:
            tip.destroy()
        except tk.TclError:
            pass
        try:
            self._toasts.remove(tip)
        except ValueError:
            pass
