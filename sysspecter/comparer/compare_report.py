"""Comparison HTML + Markdown report."""

from __future__ import annotations

import os
from typing import Any

from jinja2 import Environment, BaseLoader, select_autoescape

from ..paths import ComparisonPaths
from ..reporter.svg_charts import line_chart

_CSS = """
body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 0; background: #f7f7f9; color: #222; }
.wrapper { max-width: 1200px; margin: 0 auto; padding: 16px 24px; }
h1, h2, h3 { color: #1b2a4e; }
h2 { border-bottom: 1px solid #e2e6ee; padding-bottom: 4px; margin-top: 32px; }
.card { background: #fff; border: 1px solid #e2e6ee; border-radius: 6px; padding: 14px 18px; margin-bottom: 14px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { border-bottom: 1px solid #eef0f7; padding: 6px 10px; text-align: left; }
th { background: #f6f8fc; font-weight: 600; color: #445; }
td.num { font-variant-numeric: tabular-nums; }
.bar-row { display: flex; align-items: center; gap: 8px; font-size: 12px; margin: 2px 0; }
.bar { background: #eef0f7; height: 8px; border-radius: 4px; overflow: hidden; flex: 1; }
.bar > div { height: 100%; background: linear-gradient(90deg,#91d5ff,#2c7be5); }
.small { font-size: 12px; color: #777; }
ul.obs li { margin-bottom: 6px; }
code { background: #f3f5fa; padding: 1px 5px; border-radius: 3px; font-size: 12px; }
"""

_TEMPLATE = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>SysSpecter comparison — {{ comparison_id }}</title>
<style>{{ css }}</style></head><body><div class="wrapper">
<h1>SysSpecter comparison</h1>
<p style="color:#6b7a99;font-size:12px;letter-spacing:2px;text-transform:uppercase;margin:0 0 14px 0">See everything. Find the cause.</p>
<div class="card">
  <p><b>Comparison ID:</b> {{ comparison_id }}</p>
  <p><b>Inputs:</b></p>
  <ul>{% for r in runs %}<li><code>{{ r.run_id }}</code> — {{ r.hostname }} / {{ r.mode }} / tags: {{ r.tags | join(', ') or '—' }} ({{ r.duration_s }}s)</li>{% endfor %}</ul>
</div>

<h2>Key verdicts</h2>
<div class="card">
  <ul>
  <li><b>Best overall:</b> <code>{{ verdicts.best_overall or '—' }}</code></li>
  <li><b>Most stable:</b> <code>{{ verdicts.most_stable or '—' }}</code></li>
  <li><b>Best efficiency:</b> <code>{{ verdicts.best_efficiency or '—' }}</code></li>
  <li><b>Lowest avg CPU:</b> <code>{{ verdicts.lowest_cpu_avg or '—' }}</code></li>
  <li><b>Lowest p95 latency:</b> <code>{{ verdicts.lowest_latency_p95 or '—' }}</code></li>
  <li><b>Fewest anomalies:</b> <code>{{ verdicts.fewest_anomalies or '—' }}</code></li>
  </ul>
</div>

<h2>Matrix</h2>
<div class="card">
  <table><thead><tr>
    <th>run</th><th>host</th><th>mode</th><th>tags</th><th>dur</th>
    <th>overall</th><th>stab</th><th>eff</th><th>wkl</th><th>sec</th><th>net</th><th>hyg</th>
    <th>cpu avg</th><th>mem avg</th><th>disk avg</th><th>p95 lat</th>
    <th>anom</th><th>slow</th><th>mleaks</th><th>primary</th>
  </tr></thead><tbody>
  {% for r in rows %}
  <tr>
    <td><code>{{ r.run_id }}</code></td>
    <td>{{ r.hostname }}</td><td>{{ r.mode }}</td><td>{{ r.tags }}</td>
    <td class="num">{{ r.duration_s }}</td>
    <td class="num">{{ r.overall }}</td><td class="num">{{ r.stability }}</td>
    <td class="num">{{ r.efficiency }}</td><td class="num">{{ r.workload }}</td>
    <td class="num">{{ r.security }}</td><td class="num">{{ r.network }}</td><td class="num">{{ r.hygiene }}</td>
    <td class="num">{{ r.cpu_avg }}</td><td class="num">{{ r.mem_avg }}</td>
    <td class="num">{{ r.disk_avg }}</td><td class="num">{{ r.latency_p95_ms }}</td>
    <td class="num">{{ r.anomalies }}</td><td class="num">{{ r.slowdowns }}</td>
    <td class="num">{{ r.memory_leaks }}</td>
    <td>{{ r.primary or '—' }}</td>
  </tr>
  {% endfor %}</tbody></table>
</div>

<h2>Overlaid CPU trends</h2>
<div class="card">{{ cpu_chart | safe }}</div>
<h2>Overlaid memory trends</h2>
<div class="card">{{ mem_chart | safe }}</div>

<h2>Pairwise observations</h2>
<div class="card">
{% if pairwise %}
  {% for p in pairwise %}
  <h3><code>{{ p.pair[0] }}</code> ↔ <code>{{ p.pair[1] }}</code></h3>
  <ul class="obs">{% for o in p.observations %}<li>{{ o }}</li>{% endfor %}</ul>
  {% endfor %}
{% else %}
<p class="small">No significant pairwise differences crossed the delta thresholds.</p>
{% endif %}
</div>

<h2>Common and unique problems</h2>
<div class="card">
  <p><b>Common problem kinds across all runs:</b> {{ problems.common_problem_kinds | join(', ') or '—' }}</p>
  {% for rid, tags in problems.unique_per_run.items() %}
  <p><b>Unique to <code>{{ rid }}</code>:</b> {{ tags | join(', ') or '—' }}</p>
  {% endfor %}
</div>

<h2>Rankings</h2>
<div class="card">
  {% for key, pairs in rankings.items() %}
  <h3>{{ key }}</h3>
  <ul>{% for rid, val in pairs %}<li><code>{{ rid }}</code> — {{ val }}</li>{% endfor %}</ul>
  {% endfor %}
</div>
</div></body></html>
"""


def _overlay_chart(runs: list[dict[str, Any]], metric: str, title: str, y_label: str) -> str:
    palette = ["#2c7be5", "#cf1322", "#52c41a", "#faad14", "#722ed1", "#13c2c2", "#eb2f96"]
    series = []
    for i, r in enumerate(runs):
        rd = r["rd"]
        xs = [float(row.get("rel_seconds") or 0.0) for row in rd.system_rows]
        ys = [float(row.get(metric) or 0.0) for row in rd.system_rows]
        if not xs:
            continue
        if len(xs) > 400:
            step = len(xs) // 400
            xs = xs[::step]
            ys = ys[::step]
        rid = r["manifest"].get("run_id") or f"run{i}"
        series.append({"name": rid, "xs": xs, "ys": ys, "color": palette[i % len(palette)]})
    if not series:
        return ""
    return line_chart(series, title=title, y_label=y_label, y_min=0, y_max=100)


def _build_markdown(
    comparison_id: str,
    runs: list[dict[str, Any]],
    matrix: dict[str, Any],
    differences: list[dict[str, Any]],
    problems: dict[str, Any],
    verdicts: dict[str, Any],
) -> str:
    lines = [f"# SysSpecter comparison — {comparison_id}", "_See everything. Find the cause._", ""]
    lines.append("## Runs")
    for r in runs:
        m = r["manifest"]
        lines.append(
            f"- `{m.get('run_id')}` — {m.get('hostname')} / {m.get('mode')} "
            f"/ tags: {', '.join(m.get('tags') or []) or '—'} ({m.get('duration_actual_seconds')}s)"
        )
    lines.append("")

    lines.append("## Verdicts")
    for k, v in verdicts.items():
        lines.append(f"- **{k}**: `{v or '—'}`")
    lines.append("")

    rows = matrix["rows"]
    if rows:
        lines.append("## Matrix")
        fields = ["run_id", "hostname", "mode", "overall", "stability", "efficiency",
                  "workload", "security", "network", "hygiene",
                  "cpu_avg", "mem_avg", "disk_avg", "latency_p95_ms",
                  "anomalies", "slowdowns", "primary"]
        lines.append("| " + " | ".join(fields) + " |")
        lines.append("|" + "|".join(["---"] * len(fields)) + "|")
        for row in rows:
            lines.append("| " + " | ".join(str(row.get(f, "")) for f in fields) + " |")
        lines.append("")

    if differences:
        lines.append("## Pairwise observations")
        for p in differences:
            lines.append(f"### `{p['pair'][0]}` ↔ `{p['pair'][1]}`")
            for o in p["observations"]:
                lines.append(f"- {o}")
            lines.append("")

    lines.append("## Common & unique problems")
    lines.append(f"- Common problem kinds: {', '.join(problems.get('common_problem_kinds') or []) or '—'}")
    for rid, tags in (problems.get("unique_per_run") or {}).items():
        lines.append(f"- Unique to `{rid}`: {', '.join(tags) or '—'}")
    return "\n".join(lines)


def build_comparison_report(
    paths: ComparisonPaths,
    runs: list[dict[str, Any]],
    matrix: dict[str, Any],
    differences: list[dict[str, Any]],
    problems: dict[str, Any],
    verdicts: dict[str, Any],
) -> None:
    env = Environment(loader=BaseLoader(), autoescape=select_autoescape())
    tpl = env.from_string(_TEMPLATE)

    cpu_chart = _overlay_chart(runs, "cpu_total_pct", "CPU total (%) — overlay", "%")
    mem_chart = _overlay_chart(runs, "mem_percent", "Memory used (%) — overlay", "%")

    html_str = tpl.render(
        css=_CSS,
        comparison_id=paths.comparison_id,
        runs=[{
            "run_id": r["manifest"].get("run_id"),
            "hostname": r["manifest"].get("hostname"),
            "mode": r["manifest"].get("mode"),
            "tags": r["manifest"].get("tags") or [],
            "duration_s": r["manifest"].get("duration_actual_seconds"),
        } for r in runs],
        rows=matrix["rows"],
        rankings=matrix["rankings"],
        pairwise=differences,
        problems=problems,
        verdicts=verdicts,
        cpu_chart=cpu_chart,
        mem_chart=mem_chart,
    )
    tmp = paths.html + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(html_str)
    os.replace(tmp, paths.html)

    md = _build_markdown(paths.comparison_id, runs, matrix, differences, problems, verdicts)
    with open(paths.md, "w", encoding="utf-8") as f:
        f.write(md)
