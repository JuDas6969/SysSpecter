"""History tab: per-host overall-score trend across all runs.

Gives the technician an at-a-glance view of how a machine has evolved
over multiple SysSpecter runs. No external chart library — renders
inline SVG via the same `reporter.svg_charts.line_chart` that the
HTML report uses, then embeds the SVG in an HTML view via a simple
Text widget fallback… actually too heavy for Tkinter: instead we
render a native-canvas scatter line, which Tk handles well.
"""

from __future__ import annotations

import datetime as _dt
import tkinter as tk
from collections import defaultdict
from collections.abc import Callable
from tkinter import ttk

from .runs import scan_runs
from .tooltip import attach as tooltip

_HEIGHT = 260
_PAD_L = 60
_PAD_R = 20
_PAD_T = 20
_PAD_B = 40

# Brand palette taken from sysspecter.theme
_PALETTE = [
    "#06b6d4", "#a855f7", "#6366f1", "#52c41a", "#eb2f96",
    "#faad14", "#13c2c2", "#fa541c",
]


class HistoryTab(ttk.Frame):
    def __init__(
        self,
        master: tk.Misc,
        *,
        get_output_root: Callable[[], str],
    ) -> None:
        super().__init__(master, padding=10)
        self._get_output_root = get_output_root
        self._runs_by_host: dict[str, list] = {}
        self._open_run: Callable[[str], None] | None = None
        self._build_ui()
        self.refresh()

    def attach_opener(self, opener: Callable[[str], None]) -> None:
        """Let another tab (Runs) provide a callback for double-click → open."""
        self._open_run = opener

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(top, text="Score trend over time, grouped by hostname.",
                  foreground="#6b7a99").pack(side="left")
        btn_refresh = ttk.Button(top, text="Refresh", command=self.refresh)
        btn_refresh.pack(side="right")
        tooltip(btn_refresh, "Re-scan the output root and rebuild the chart.")

        ttk.Label(self, text="Hosts:").grid(row=1, column=0, sticky="w", pady=(0, 4))

        chart_frame = ttk.Frame(self)
        chart_frame.grid(row=2, column=0, sticky="nsew")
        chart_frame.columnconfigure(0, weight=1)
        chart_frame.rowconfigure(0, weight=1)
        self.canvas = tk.Canvas(chart_frame, height=_HEIGHT, background="#ffffff",
                                highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="nsew")

        self._hosts_var = tk.StringVar(value="")
        ttk.Label(self, textvariable=self._hosts_var,
                  foreground="#6b7a99").grid(row=3, column=0, sticky="w", pady=(4, 0))

    def refresh(self) -> None:
        try:
            rows = scan_runs(self._get_output_root())
        except Exception:
            rows = []
        by_host: dict[str, list] = defaultdict(list)
        for r in rows:
            if r.overall_score is None or not r.started_at:
                continue
            try:
                ts = _dt.datetime.fromisoformat(r.started_at)
            except (TypeError, ValueError):
                continue
            by_host[r.hostname].append((ts, r.overall_score, r))
        # sort each host's series by time
        for h in by_host:
            by_host[h].sort(key=lambda triple: triple[0])
        self._runs_by_host = by_host
        self._draw()

    def _draw(self) -> None:
        c = self.canvas
        c.delete("all")
        w = max(self.winfo_width() or 900, 900)
        h = _HEIGHT
        try:
            c.configure(width=w)
        except tk.TclError:
            pass
        if not self._runs_by_host:
            c.create_text(w / 2, h / 2,
                          text="No runs with a computed overall score yet.",
                          fill="#6b7a99", font=("Segoe UI", 11, "italic"))
            self._hosts_var.set("")
            return

        plot_x0 = _PAD_L
        plot_x1 = w - _PAD_R
        plot_y0 = _PAD_T
        plot_y1 = h - _PAD_B
        plot_w = plot_x1 - plot_x0
        plot_h = plot_y1 - plot_y0

        # Axes: overall score is [0..100]; time axis spans all series
        all_ts = []
        for series in self._runs_by_host.values():
            for ts, _score, _run in series:
                all_ts.append(ts.timestamp())
        if not all_ts:
            return
        t_min, t_max = min(all_ts), max(all_ts)
        if t_max - t_min < 1:
            t_max = t_min + 1  # avoid division-by-zero for a single-sample host

        def _to_x(ts: float) -> float:
            return plot_x0 + plot_w * (ts - t_min) / (t_max - t_min)

        def _to_y(score: float) -> float:
            return plot_y1 - plot_h * (score / 100.0)

        # Y-axis gridlines every 20 pts
        for v in (0, 20, 40, 60, 80, 100):
            y = _to_y(v)
            c.create_line(plot_x0, y, plot_x1, y, fill="#eef0f7")
            c.create_text(plot_x0 - 6, y, text=f"{v}", anchor="e",
                          fill="#6b7a99", font=("Segoe UI", 9))

        # X-axis: 3 ticks
        for frac in (0.0, 0.5, 1.0):
            tx = plot_x0 + plot_w * frac
            ts_epoch = t_min + (t_max - t_min) * frac
            label = _dt.datetime.fromtimestamp(ts_epoch).strftime("%Y-%m-%d")
            c.create_line(tx, plot_y1, tx, plot_y1 + 4, fill="#6b7a99")
            c.create_text(tx, plot_y1 + 18, text=label, fill="#6b7a99",
                          font=("Segoe UI", 9))

        # Draw each host as a polyline + points
        labels: list[str] = []
        for i, (host, series) in enumerate(sorted(self._runs_by_host.items())):
            color = _PALETTE[i % len(_PALETTE)]
            points: list[tuple[float, float, str]] = []
            for ts, score, run in series:
                x = _to_x(ts.timestamp())
                y = _to_y(score)
                points.append((x, y, run.path))
            if len(points) >= 2:
                flat = [coord for (x, y, _p) in points for coord in (x, y)]
                c.create_line(*flat, fill=color, width=2, smooth=False)
            for x, y, path in points:
                tag = f"pt_{path}"
                c.create_oval(x - 4, y - 4, x + 4, y + 4,
                              fill=color, outline="#ffffff", width=1, tags=(tag,))
                c.tag_bind(tag, "<Button-1>",
                           lambda _e, p=path: self._open_run and self._open_run(p))
            labels.append(f"{host} ({len(series)} run{'s' if len(series) != 1 else ''})")
        self._hosts_var.set(" · ".join(labels))
        # Resize listener → redraw on canvas size change
        self.canvas.bind("<Configure>", lambda _e: self.after_idle(self._draw))
