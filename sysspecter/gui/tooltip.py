"""Lightweight Tkinter tooltip widget (no third-party deps)."""

from __future__ import annotations

import tkinter as tk


class Tooltip:
    """Attach a hover-delayed tooltip to any Tkinter widget."""

    def __init__(self, widget: tk.Widget, text: str, *, delay_ms: int = 500,
                 wraplength: int = 420) -> None:
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self.wraplength = wraplength
        self._after_id: str | None = None
        self._tip: tk.Toplevel | None = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event: tk.Event | None = None) -> None:
        self._cancel()
        self._after_id = self.widget.after(self.delay_ms, self._show)

    def _cancel(self) -> None:
        if self._after_id is not None:
            try:
                self.widget.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None

    def _show(self) -> None:
        if self._tip is not None:
            return
        try:
            x = self.widget.winfo_rootx() + 20
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        except tk.TclError:
            return
        tip = tk.Toplevel(self.widget)
        tip.wm_overrideredirect(True)
        tip.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(
            tip, text=self.text, justify="left", wraplength=self.wraplength,
            background="#fff9c4", relief="solid", borderwidth=1,
            font=("Segoe UI", 9), padx=8, pady=4,
        )
        lbl.pack()
        self._tip = tip

    def _hide(self, _event: tk.Event | None = None) -> None:
        self._cancel()
        if self._tip is not None:
            try:
                self._tip.destroy()
            except Exception:
                pass
            self._tip = None


def attach(widget: tk.Widget, text: str, **kwargs) -> Tooltip:
    """Shorthand: Tooltip(widget, text). Returns the tooltip so you can keep
    it alive if you need to."""
    return Tooltip(widget, text, **kwargs)
