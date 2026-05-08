"""HTML render for the fleet aggregation report.

Uses a small inline Jinja template — the aggregator doesn't share
the per-run template chain, so a separate file keeps the
dependency-graph clean.
"""

from __future__ import annotations

import os
from typing import Any

from jinja2 import BaseLoader, Environment, select_autoescape

_TEMPLATE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>SysSpecter — Fleet aggregation {{ manifest.aggregation_id }}</title>
<style>
  body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
         color:#222; background:#f7f7f9; margin:0; padding:0; }
  .wrapper { max-width:1180px; margin:0 auto; padding:16px 24px; }
  h1 { color:#1b2a4e; margin-bottom:0; }
  h2 { color:#1b2a4e; border-bottom:1px solid #e2e6ee;
       padding-bottom:4px; margin-top:32px; }
  .card { background:#fff; border:1px solid #e2e6ee; border-radius:6px;
          padding:14px 18px; margin-bottom:14px;
          box-shadow:0 1px 2px rgba(0,0,0,.03); }
  .small { font-size:12px; color:#777; }
  table { border-collapse:collapse; width:100%; font-size:13px; }
  th,td { border-bottom:1px solid #eef0f7; padding:6px 10px;
          text-align:left; }
  th { background:#f6f8fc; color:#445; font-weight:600; }
  tbody tr:hover { background:#fafbff; }
  .badge { display:inline-block; padding:2px 8px; border-radius:10px;
           font-size:11px; font-weight:600; }
  .badge.high { background:#fff1f0; color:#cf1322; border:1px solid #ffa39e; }
  .badge.medium { background:#fffbe6; color:#d46b08;
                  border:1px solid #ffe58f; }
  .badge.low { background:#f6ffed; color:#389e0d;
               border:1px solid #b7eb8f; }
</style>
</head><body><div class="wrapper">

<h1>Fleet aggregation</h1>
<p class="small">{{ manifest.aggregation_id }} · generated
{{ manifest.generated_at }} · input <code>{{ manifest.input_root }}</code></p>

<div class="card">
  <p>
    Scanned <b>{{ result.runs_scanned }}</b> run(s) across
    <b>{{ result.distinct_machines }}</b> distinct machines
    (<b>{{ result.machines_with_id }}</b> with stable machine_id;
    <b>{{ result.runs_without_machine_id }}</b> run(s) lacked one).
  </p>
</div>

<h2>Fleet score distribution</h2>
<div class="card">
  <table><thead><tr>
    <th>axis</th><th>samples</th><th>mean</th><th>p50</th>
    <th>p95</th><th>std</th>
  </tr></thead><tbody>
    {% for axis in axes %}
    {% set s = result.fleet_stats[axis] %}
    <tr>
      <td><b>{{ axis }}</b></td>
      <td>{{ s.samples }}</td>
      <td>{{ s.mean if s.mean is not none else '—' }}</td>
      <td>{{ s.p50 if s.p50 is not none else '—' }}</td>
      <td>{{ s.p95 if s.p95 is not none else '—' }}</td>
      <td>{{ s.std if s.std is not none else '—' }}</td>
    </tr>
    {% endfor %}
  </tbody></table>
</div>

{% if result.outliers %}
<h2>Outliers <span class="small">(machines &gt; 2σ off the fleet
mean for that axis, latest run)</span></h2>
<div class="card">
  <table><thead><tr>
    <th>z-score</th><th>direction</th><th>machine_id</th>
    <th>hostname</th><th>axis</th><th>value</th>
    <th>fleet mean</th><th>fleet std</th>
  </tr></thead><tbody>
    {% for o in result.outliers[:50] %}
    <tr>
      <td>
        {% if o.z_score|abs >= 3 %}<span class="badge high">{{ o.z_score }}</span>
        {% elif o.z_score|abs >= 2.5 %}<span class="badge medium">{{ o.z_score }}</span>
        {% else %}<span class="badge low">{{ o.z_score }}</span>{% endif %}
      </td>
      <td>{{ o.direction }}</td>
      <td><code>{{ o.machine_id }}</code></td>
      <td>{{ o.hostname_seen }}</td>
      <td>{{ o.axis }}</td>
      <td>{{ o.value }}</td>
      <td>{{ o.fleet_mean }}</td>
      <td>{{ o.fleet_std }}</td>
    </tr>
    {% endfor %}
  </tbody></table>
</div>
{% endif %}

<h2>Per-machine view <span class="small">(longitudinal trend)</span></h2>
<div class="card">
  <table><thead><tr>
    <th>machine_id</th><th>runs</th><th>first run</th><th>last run</th>
    <th>hostnames</th><th>classes</th>
    <th>overall drift</th><th>stability drift</th>
  </tr></thead><tbody>
    {% for m in result.per_machine.values() %}
    <tr>
      <td><code>{{ m.machine_id }}</code></td>
      <td>{{ m.runs }}</td>
      <td class="small">{{ m.first_run_at or '—' }}</td>
      <td class="small">{{ m.last_run_at or '—' }}</td>
      <td>{{ ', '.join(m.hostnames_seen) }}</td>
      <td>{{ ', '.join(m.machine_classes_seen) or '—' }}</td>
      <td>
        {% set d = m.score_drift.overall %}
        {% if d %}{{ d.first }} → {{ d.last }}
          (Δ {{ '%+g'|format(d.delta) }}){% else %}—{% endif %}
      </td>
      <td>
        {% set d = m.score_drift.stability %}
        {% if d %}{{ d.first }} → {{ d.last }}
          (Δ {{ '%+g'|format(d.delta) }}){% else %}—{% endif %}
      </td>
    </tr>
    {% endfor %}
  </tbody></table>
</div>

{% if result.common_baseline_deviations %}
<h2>Common baseline deviations
  <span class="small">(C3 deviations rolled up across the fleet)</span></h2>
<div class="card">
  <table><thead><tr>
    <th>machine class</th><th>metric</th>
    <th>machines affected</th><th>machines in class</th>
  </tr></thead><tbody>
    {% for d in result.common_baseline_deviations %}
    <tr>
      <td>{{ d.machine_class }}</td>
      <td>{{ d.metric }}</td>
      <td>{{ d.machines_affected }}</td>
      <td>{{ d.machines_in_class or '—' }}</td>
    </tr>
    {% endfor %}
  </tbody></table>
</div>
{% endif %}

<p class="small" style="margin-top:32px;text-align:center;">
  SysSpecter — Fleet aggregation. © 2026 David Juriga.
</p>

</div></body></html>
"""


def build_aggregation_report(
    out_dir: str,
    manifest: dict[str, Any],
    result: dict[str, Any],
) -> None:
    env = Environment(loader=BaseLoader(), autoescape=select_autoescape())
    tpl = env.from_string(_TEMPLATE)
    axes = (
        "overall", "stability", "efficiency", "workload_suitability",
        "security_overhead", "network_impact", "resource_hygiene",
    )
    html_str = tpl.render(manifest=manifest, result=result, axes=axes)
    path = os.path.join(out_dir, "fleet_report.html")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(html_str)
    os.replace(tmp, path)
