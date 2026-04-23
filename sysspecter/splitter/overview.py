"""Phase overview HTML: intensity chart + colored phase-timeline bar + phase table."""

from __future__ import annotations

import html
import os
from typing import Any

from ..reporter.svg_charts import line_chart
from .detect import ChangePoint, Phase

_CSS = """
body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 0; background: #f7f7f9; color: #222; }
.wrapper { max-width: 1200px; margin: 0 auto; padding: 16px 24px; }
h1, h2, h3 { color: #1b2a4e; }
h2 { border-bottom: 1px solid #e2e6ee; padding-bottom: 4px; margin-top: 28px; }
.card { background: #fff; border: 1px solid #e2e6ee; border-radius: 6px; padding: 14px 18px; margin-bottom: 14px; }
.small { font-size: 12px; color: #777; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { border-bottom: 1px solid #eef0f7; padding: 6px 10px; text-align: left; }
th { background: #f6f8fc; font-weight: 600; color: #445; }
td.num { font-variant-numeric: tabular-nums; }
code { background: #f3f5fa; padding: 1px 5px; border-radius: 3px; font-size: 12px; }
a { color: #2c7be5; text-decoration: none; }
a:hover { text-decoration: underline; }
.tagline { color: #6b7a99; font-size: 12px; letter-spacing: 2px; text-transform: uppercase; margin: 0 0 14px 0; }
"""


_PHASE_COLORS = [
    "#2c7be5", "#52c41a", "#faad14", "#eb2f96", "#722ed1",
    "#13c2c2", "#fa541c", "#a0d911", "#1890ff", "#f5222d",
]


def _phase_bar_svg(
    total_duration: float,
    phases: list[Phase],
    change_points: list[ChangePoint],
    phase_links: list[str | None] | None = None,
    width: int = 900,
    height: int = 70,
) -> str:
    if total_duration <= 0:
        return ""
    pad_l, pad_r = 55, 20
    plot_w = width - pad_l - pad_r
    bar_y = 20
    bar_h = 26

    def _x(rel: float) -> float:
        return pad_l + plot_w * (rel / total_duration)

    parts: list[str] = []
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
                 f'style="font-family:sans-serif; font-size:11px;">')
    # axis line
    parts.append(f'<line x1="{pad_l}" y1="{bar_y + bar_h}" x2="{pad_l + plot_w}" '
                 f'y2="{bar_y + bar_h}" stroke="#bbb" />')

    for i, p in enumerate(phases):
        x0 = _x(p.start_rel)
        x1 = _x(p.end_rel)
        color = _PHASE_COLORS[i % len(_PHASE_COLORS)]
        link = phase_links[i] if (phase_links and i < len(phase_links)) else None
        if link:
            # Anchor-wrap the segment so clicking it jumps to the sub-report.
            parts.append(
                f'<a href="{html.escape(link)}" target="_blank" '
                f'><title>Phase {p.phase_id} — open sub-report</title>'
            )
        else:
            parts.append(f'<g><title>Phase {p.phase_id}</title>')
        parts.append(
            f'<rect x="{x0:.1f}" y="{bar_y}" width="{max(x1-x0,1):.1f}" height="{bar_h}" '
            f'fill="{color}" fill-opacity="0.70" stroke="#fff" stroke-width="1" '
            f'style="cursor: {"pointer" if link else "default"}" />'
        )
        label = f"#{p.phase_id}"
        text_x = (x0 + x1) / 2
        parts.append(
            f'<text x="{text_x:.1f}" y="{bar_y + bar_h / 2 + 4:.1f}" '
            f'text-anchor="middle" fill="#fff" font-weight="bold" '
            f'style="pointer-events: none">{label}</text>'
        )
        parts.append("</a>" if link else "</g>")

    for c in change_points:
        x = _x(c.rel_seconds)
        parts.append(
            f'<line x1="{x:.1f}" y1="{bar_y - 6}" x2="{x:.1f}" y2="{bar_y + bar_h + 6}" '
            f'stroke="#222" stroke-dasharray="2,2" stroke-width="1" />'
        )

    for ticks in (0, total_duration / 2, total_duration):
        x = _x(ticks)
        parts.append(
            f'<text x="{x:.1f}" y="{bar_y + bar_h + 18:.1f}" text-anchor="middle" '
            f'fill="#666">{int(ticks)}s</text>'
        )

    parts.append('</svg>')
    return "".join(parts)


def build_overview_report(
    *,
    run_dir: str,
    manifest: dict[str, Any],
    system_rows: list[dict[str, Any]],
    change_points: list[ChangePoint],
    phases: list[Phase],
    phase_reports: list[dict[str, Any]],
) -> str:
    total_duration = float(system_rows[-1].get("rel_seconds") or 0.0) if system_rows else 0.0

    xs = [float(r.get("rel_seconds") or 0.0) for r in system_rows]
    cpu_y = [float(r.get("cpu_total_pct") or 0.0) for r in system_rows]
    mem_y = [float(r.get("mem_percent") or 0.0) for r in system_rows]
    disk_y = [float(r.get("disk_active_pct_est") or 0.0) for r in system_rows]
    intensity = [0.5*c + 0.3*m + 0.2*d
                 for c, m, d in zip(cpu_y, mem_y, disk_y, strict=False)]

    chart = line_chart(
        [
            {"name": "cpu total %", "xs": xs, "ys": cpu_y, "color": "#2c7be5"},
            {"name": "mem %", "xs": xs, "ys": mem_y, "color": "#722ed1"},
            {"name": "disk active %", "xs": xs, "ys": disk_y, "color": "#eb2f96"},
            {"name": "combined intensity", "xs": xs, "ys": intensity, "color": "#222"},
        ],
        title="Run intensity - full timeline",
        y_label="%", y_min=0, y_max=100,
    )
    # Each SVG phase rectangle becomes a link to its sub-report (if any).
    phase_links = [p.get("subreport_path") for p in phase_reports]
    phase_bar = _phase_bar_svg(total_duration, phases, change_points,
                               phase_links=phase_links)

    rows: list[str] = []
    for i, p in enumerate(phase_reports):
        color = _PHASE_COLORS[i % len(_PHASE_COLORS)]
        link = ""
        if p.get("subreport_path"):
            href = html.escape(p["subreport_path"])
            link = f'<a href="{href}">open phase report &rarr;</a>'
        elif p.get("error"):
            link = f'<span class="small">error: {html.escape(p["error"])}</span>'
        rows.append(
            "<tr>"
            f'<td><span style="display:inline-block;width:10px;height:10px;background:{color};'
            f'border-radius:2px;margin-right:6px"></span>#{p.get("phase_id")}</td>'
            f'<td class="num">{int(p.get("start_rel") or 0)} s</td>'
            f'<td class="num">{int(p.get("end_rel") or 0)} s</td>'
            f'<td class="num">{int(p.get("duration_seconds") or 0)} s</td>'
            f'<td>{html.escape(p.get("reason_at_start") or "run_start")}</td>'
            f'<td class="small">{html.escape(p.get("evidence_at_start") or "-")}</td>'
            f"<td>{link}</td>"
            "</tr>"
        )
    table_html = "\n".join(rows) if rows else '<tr><td colspan="7" class="small">no phases</td></tr>'

    cps_rows: list[str] = []
    for c in change_points:
        cps_rows.append(
            "<tr>"
            f'<td class="num">{int(c.rel_seconds)} s</td>'
            f'<td>{html.escape(c.kind)}</td>'
            f'<td>{html.escape(c.reason)}</td>'
            f'<td class="num">{c.score:.1f}</td>'
            f'<td class="small">{html.escape(c.evidence)}</td>'
            "</tr>"
        )
    cps_html = "\n".join(cps_rows) if cps_rows \
        else '<tr><td colspan="5" class="small">no change points detected</td></tr>'

    host = html.escape(str(manifest.get("hostname") or "?"))
    run_id = html.escape(str(manifest.get("run_id") or "?"))

    html_doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>SysSpecter phases - {run_id}</title>
<style>{_CSS}</style></head><body><div class="wrapper">
<h1>SysSpecter phase split - {host}</h1>
<p class="tagline">See everything. Find the cause.</p>
<div class="card">
  <p><b>Run ID:</b> <code>{run_id}</code></p>
  <p><b>Total duration:</b> {int(total_duration)} s</p>
  <p><b>Change points:</b> {len(change_points)} &nbsp;|&nbsp; <b>Phases:</b> {len(phases)}</p>
</div>

<h2>Timeline</h2>
<div class="card">
  {chart}
  <div class="small" style="margin-top:8px;">Colored segments below mark phases. Dashed lines mark change points.</div>
  {phase_bar}
</div>

<h2>Phases</h2>
<div class="card">
  <table><thead><tr>
    <th>phase</th><th>start</th><th>end</th><th>duration</th>
    <th>reason at start</th><th>evidence</th><th>report</th>
  </tr></thead><tbody>
  {table_html}
  </tbody></table>
</div>

<h2>Change points</h2>
<div class="card">
  <table><thead><tr>
    <th>time</th><th>kind</th><th>reason</th><th>score</th><th>evidence</th>
  </tr></thead><tbody>
  {cps_html}
  </tbody></table>
</div>

</div></body></html>
"""
    out_path = os.path.join(run_dir, "phases_report.html")
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(html_doc)
    os.replace(tmp, out_path)
    return out_path
