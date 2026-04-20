"""Minimal inline-SVG chart generator. No external deps.

Supports line charts, stacked area, and CPU-per-core heatmap. Output is a
self-contained SVG string suitable for embedding directly in HTML."""

from __future__ import annotations

import html
from typing import Iterable


def _scale(v: float, vmin: float, vmax: float, out_lo: float, out_hi: float) -> float:
    if vmax == vmin:
        return (out_lo + out_hi) / 2
    return out_lo + (out_hi - out_lo) * (v - vmin) / (vmax - vmin)


def _fmt(x: float) -> str:
    if x == 0:
        return "0"
    ax = abs(x)
    if ax >= 1e6:
        return f"{x/1e6:.1f}M"
    if ax >= 1e3:
        return f"{x/1e3:.1f}k"
    if ax >= 10:
        return f"{x:.0f}"
    return f"{x:.1f}"


def line_chart(
    series: list[dict],
    width: int = 900,
    height: int = 260,
    y_min: float | None = None,
    y_max: float | None = None,
    y_label: str = "",
    title: str = "",
) -> str:
    """series = [{name, xs, ys, color}]. Returns SVG string."""
    pad_l, pad_r, pad_t, pad_b = 55, 20, 30, 30
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b

    all_xs: list[float] = []
    all_ys: list[float] = []
    for s in series:
        all_xs.extend(s["xs"])
        all_ys.extend(s["ys"])
    if not all_xs:
        return f'<svg class="pcb-chart" width="{width}" height="{height}"><text x="10" y="20" fill="#888">no data</text></svg>'

    xmin, xmax = min(all_xs), max(all_xs)
    if xmax == xmin:
        xmax = xmin + 1
    if y_min is None:
        y_min = 0.0 if min(all_ys) >= 0 else min(all_ys)
    if y_max is None:
        y_max = max(all_ys) * 1.1 if max(all_ys) > 0 else 1.0
    if y_max == y_min:
        y_max = y_min + 1

    parts: list[str] = []
    parts.append(
        f'<svg class="pcb-chart" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">'
    )
    if title:
        parts.append(f'<text x="{width/2}" y="16" text-anchor="middle" '
                     f'font-size="13" font-weight="600" fill="#222">{html.escape(title)}</text>')

    parts.append(
        f'<rect x="{pad_l}" y="{pad_t}" width="{plot_w}" height="{plot_h}" '
        f'fill="#fafafa" stroke="#ddd"/>'
    )
    for i in range(5):
        y = pad_t + plot_h * i / 4
        v = y_max - (y_max - y_min) * i / 4
        parts.append(
            f'<line x1="{pad_l}" y1="{y:.1f}" x2="{pad_l+plot_w}" y2="{y:.1f}" '
            f'stroke="#eee"/>'
            f'<text x="{pad_l-5}" y="{y+4:.1f}" text-anchor="end" font-size="10" '
            f'fill="#666">{_fmt(v)}</text>'
        )
    for i in range(5):
        x = pad_l + plot_w * i / 4
        xv = xmin + (xmax - xmin) * i / 4
        parts.append(
            f'<text x="{x:.1f}" y="{pad_t+plot_h+14}" text-anchor="middle" '
            f'font-size="10" fill="#666">{_fmt(xv)}</text>'
        )
    if y_label:
        parts.append(
            f'<text transform="rotate(-90 {pad_l-40} {pad_t+plot_h/2})" '
            f'x="{pad_l-40}" y="{pad_t+plot_h/2}" font-size="11" fill="#444" '
            f'text-anchor="middle">{html.escape(y_label)}</text>'
        )

    for s in series:
        color = s.get("color", "#2c7be5")
        xs = s["xs"]
        ys = s["ys"]
        if not xs:
            continue
        pts: list[str] = []
        for xv, yv in zip(xs, ys):
            px = _scale(xv, xmin, xmax, pad_l, pad_l + plot_w)
            py = _scale(yv, y_min, y_max, pad_t + plot_h, pad_t)
            pts.append(f"{px:.1f},{py:.1f}")
        parts.append(
            f'<polyline fill="none" stroke="{color}" stroke-width="1.5" '
            f'points="{" ".join(pts)}"/>'
        )

    if len(series) > 1:
        lx = pad_l + 8
        ly = pad_t + 14
        for i, s in enumerate(series):
            color = s.get("color", "#2c7be5")
            name = s.get("name", f"series{i}")
            parts.append(
                f'<rect x="{lx}" y="{ly-9}" width="10" height="10" fill="{color}"/>'
                f'<text x="{lx+14}" y="{ly}" font-size="10" fill="#333">{html.escape(name)}</text>'
            )
            ly += 14
    parts.append("</svg>")
    return "".join(parts)


def stacked_area_chart(
    xs: list[float],
    series: list[dict],
    width: int = 900,
    height: int = 240,
    y_label: str = "",
    title: str = "",
) -> str:
    """series = [{name, ys (same length as xs), color}]."""
    return line_chart(
        [{"name": s["name"], "xs": xs, "ys": s["ys"], "color": s.get("color", "#2c7be5")}
         for s in series],
        width=width, height=height, y_label=y_label, title=title,
    )


def heatmap(
    values: list[list[float]],
    width: int = 900,
    height: int = 180,
    x_label: str = "time (s)",
    y_label: str = "core",
    title: str = "",
    v_min: float = 0.0,
    v_max: float = 100.0,
) -> str:
    """values[core][sample] = pct. Rendered as a raster of colored cells."""
    pad_l, pad_r, pad_t, pad_b = 50, 20, 30, 30
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    if not values or not values[0]:
        return f'<svg width="{width}" height="{height}"><text x="10" y="20" fill="#888">no data</text></svg>'
    rows = len(values)
    cols = len(values[0])
    cell_w = plot_w / cols
    cell_h = plot_h / rows

    parts = [
        f'<svg class="pcb-heatmap" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">'
    ]
    if title:
        parts.append(f'<text x="{width/2}" y="16" text-anchor="middle" font-size="13" '
                     f'font-weight="600" fill="#222">{html.escape(title)}</text>')
    for r_i, row in enumerate(values):
        for c_i, v in enumerate(row):
            x = pad_l + c_i * cell_w
            y = pad_t + r_i * cell_h
            t = max(0.0, min(1.0, (v - v_min) / (v_max - v_min) if v_max > v_min else 0))
            r = int(255 * t)
            g = int(220 * (1 - t) + 40)
            b = int(240 * (1 - t) + 20)
            parts.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{cell_w+0.5:.2f}" height="{cell_h+0.5:.2f}" '
                f'fill="rgb({r},{g},{b})"/>'
            )
    for i in range(rows):
        y = pad_t + (i + 0.5) * cell_h + 3
        parts.append(
            f'<text x="{pad_l-5}" y="{y:.1f}" text-anchor="end" font-size="9" fill="#444">c{i}</text>'
        )
    parts.append(f'<text x="{width/2}" y="{height-6}" text-anchor="middle" '
                 f'font-size="10" fill="#444">{html.escape(x_label)}</text>')
    parts.append("</svg>")
    return "".join(parts)
