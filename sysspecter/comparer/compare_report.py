"""Comparison HTML + Markdown report."""

from __future__ import annotations

import os
from typing import Any

from jinja2 import BaseLoader, Environment, select_autoescape

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
td.diverge { background: #fff8e6; font-weight: 600; }
.bar-row { display: flex; align-items: center; gap: 8px; font-size: 12px; margin: 2px 0; }
.bar { background: #eef0f7; height: 8px; border-radius: 4px; overflow: hidden; flex: 1; }
.bar > div { height: 100%; background: linear-gradient(90deg,#91d5ff,#2c7be5); }
.small { font-size: 12px; color: #777; }
ul.obs li { margin-bottom: 6px; }
code { background: #f3f5fa; padding: 1px 5px; border-radius: 3px; font-size: 12px; }
.mode-banner { background: #e6f4ff; border-left: 4px solid #2c7be5; padding: 10px 14px; border-radius: 4px; margin-bottom: 14px; }
.cadence-banner { padding: 12px 14px; border-radius: 4px; margin-bottom: 14px; border-left: 4px solid #cf1322; background: #fff1f0; }
.cadence-banner.medium { border-left-color: #faad14; background: #fffbe6; }
.cadence-banner.low { border-left-color: #52c41a; background: #f6ffed; }
.cadence-banner h3 { margin: 0 0 6px 0; color: #1b2a4e; }
.cadence-banner ul { margin: 6px 0 0 0; padding-left: 20px; }
.cadence-pill { display: inline-block; padding: 2px 6px; border-radius: 10px; font-size: 11px; font-weight: 600; margin-left: 6px; }
.cadence-pill.good { background: #d9f7be; color: #135200; }
.cadence-pill.degraded { background: #fff1b8; color: #874d00; }
.cadence-pill.broken { background: #ffa39e; color: #5c0011; }
.cadence-pill.unknown { background: #e8e8e8; color: #595959; }
.cadence-pill.no_data { background: #d9d9d9; color: #262626; }
.rec { border-left: 4px solid #cf1322; padding: 8px 12px; margin-bottom: 8px; background: #fff7f6; border-radius: 4px; }
.rec.medium { border-left-color: #faad14; background: #fffbe6; }
.rec.low { border-left-color: #52c41a; background: #f6ffed; }
.rec .sev { display: inline-block; padding: 2px 6px; border-radius: 10px; font-size: 11px; font-weight: 600; margin-right: 6px; background: #cf1322; color: #fff; }
.rec.medium .sev { background: #faad14; color: #fff; }
.rec.low .sev { background: #52c41a; color: #fff; }
details summary { cursor: pointer; font-weight: 600; color: #1b2a4e; }
details { margin-top: 8px; }
"""

_TEMPLATE = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>SysSpecter comparison — {{ comparison_id }}</title>
<style>{{ css }}</style></head><body><div class="wrapper">
<h1>SysSpecter comparison</h1>
<p style="color:#6b7a99;font-size:12px;letter-spacing:2px;text-transform:uppercase;margin:0 0 14px 0">See everything. Find the cause.</p>

<div class="mode-banner">
  <b>Analysis mode:</b> {{ mode_label }}
  <span class="small">&nbsp;(auto-detected from hostnames)</span>
</div>

<div class="card">
  <p><b>Comparison ID:</b> {{ comparison_id }}</p>
  <p><b>Inputs:</b></p>
  <ul>{% for r in runs %}<li><code>{{ r.run_id }}</code> — {{ r.hostname }} / {{ r.mode }} / tags: {{ r.tags | join(', ') or '—' }} ({{ r.duration_s }}s)</li>{% endfor %}</ul>
</div>

{# v3-priority-2: cadence-quality banner. Shown FIRST when any
   participant is broken/mixed so the reader sees the caveat before
   the headline verdicts. Green "all good" card otherwise so the
   absence isn't ambiguous. #}
{% if cadence_warnings %}
{% set worst_sev = "low" %}
{% for w in cadence_warnings %}{% if w.severity == "high" %}{% set worst_sev = "high" %}{% endif %}{% endfor %}
{% if worst_sev != "high" %}
{% for w in cadence_warnings %}{% if w.severity == "medium" and worst_sev != "high" %}{% set worst_sev = "medium" %}{% endif %}{% endfor %}
{% endif %}
<div class="cadence-banner {% if worst_sev == 'medium' %}medium{% elif worst_sev == 'low' %}low{% endif %}">
  <h3>Cadence quality &mdash; comparison caveat</h3>
  <p style="margin:4px 0 8px 0">
    The runs being compared have heterogeneous sample cadence.
    Sample-density-sensitive metrics (cpu_avg, mem_avg, latency_p95, etc.)
    are presented with reduced confidence; cadence-immune metrics
    (anomaly counts, leak detections) are unaffected.
  </p>
  <ul>
    {% for w in cadence_warnings %}
    <li><b>[{{ w.severity }}]</b> {{ w.hypothesis }}</li>
    {% endfor %}
  </ul>
</div>
{% else %}
<div class="cadence-banner low">
  <h3>Cadence quality &mdash; all participants healthy
    <span class="cadence-pill good">good</span></h3>
  <p style="margin:4px 0 0 0" class="small">
    All runs sampled at &le; 1.5&times; their nominal cadence. Cross-run
    metrics are directly comparable.
  </p>
</div>
{% endif %}

{# v3-priority-3: peer-context banner. Same shape as the cadence
   banner — surfaced near the top so the reader sees "these aren't
   apples-to-apples" before forming an opinion from the verdicts. #}
{% if peer_warnings %}
<div class="cadence-banner medium">
  <h3>Peer context &mdash; non-peer comparison</h3>
  <p style="margin:4px 0 8px 0">
    The runs being compared have different declared <code>machine_class</code>
    values, putting them in different workload-profile peer groups.
    Direct comparison of idle CPU, memory pressure, or latency may
    overstate real differences.
  </p>
  <ul>
    {% for w in peer_warnings %}
    <li><b>[{{ w.severity }}]</b> {{ w.hypothesis }}</li>
    {% endfor %}
  </ul>
</div>
{% endif %}

{% if peer_classes %}
<h2>Per-run machine class</h2>
<div class="card">
  <table><thead><tr>
    <th>run</th><th>declared</th><th>normalised</th><th>peer group</th>
  </tr></thead><tbody>
  {% for p in peer_classes %}
  <tr>
    <td><code>{{ p.run_id }}</code></td>
    <td>{{ p.machine_class or '—' }}</td>
    <td>{{ p.machine_class_normalised or '—' }}</td>
    <td>{{ p.peer_group or '—' }}</td>
  </tr>
  {% endfor %}
  </tbody></table>
  <p class="small" style="margin-top:8px">
    <i>Peer groups: <b>workstation</b> (developer / engineering),
    <b>office</b> (general-knowledge-worker), <b>embedded</b>
    (kiosk / factory-floor), <b>terminal-server</b>. Set with
    <code>--machine-class &lt;name&gt;</code> on capture.</i>
  </p>
</div>
{% endif %}

<h2>Per-run cadence</h2>
<div class="card">
  <table><thead><tr>
    <th>run</th><th>health</th><th>nominal</th><th>median gap</th>
    <th>p95 gap</th><th>max gap</th><th>samples</th><th>over 2&times;</th>
    <th>over 5&times;</th><th>priority</th>
  </tr></thead><tbody>
  {% for p in cadence_per_run %}
  <tr>
    <td><code>{{ p.run_id }}</code></td>
    <td><span class="cadence-pill {{ p.cadence_health }}">{{ p.cadence_health }}</span></td>
    <td class="num">{{ p.nominal_interval_seconds or '—' }}s</td>
    <td class="num">{{ p.median_gap_seconds if p.median_gap_seconds is not none else '—' }}s</td>
    <td class="num">{{ p.p95_gap_seconds if p.p95_gap_seconds is not none else '—' }}s</td>
    <td class="num">{{ p.max_gap_seconds if p.max_gap_seconds is not none else '—' }}s</td>
    <td class="num">{{ p.samples_total or '—' }}</td>
    <td class="num">{{ p.gaps_over_2x_nominal if p.gaps_over_2x_nominal is defined else '—' }}</td>
    <td class="num">{{ p.gaps_over_5x_nominal if p.gaps_over_5x_nominal is defined else '—' }}</td>
    <td class="small">{{ p.process_priority_class or '—' }}</td>
  </tr>
  {% endfor %}
  </tbody></table>
</div>

<h2>Key verdicts</h2>
<div class="card">
  <ul>
  <li><b>Best overall:</b> <code>{{ verdicts.best_overall or '—' }}</code></li>
  <li><b>Most stable:</b> <code>{{ verdicts.most_stable or '—' }}</code></li>
  <li><b>Best efficiency:</b> <code>{{ verdicts.best_efficiency or '—' }}</code></li>
  <li><b>Lowest avg CPU:</b> <code>{{ verdicts.lowest_cpu_avg or '—' }}</code>
    {% if rankings_with_confidence and rankings_with_confidence.lowest_cpu_avg and not rankings_with_confidence.lowest_cpu_avg.trusted %}
    <span class="cadence-pill degraded">cadence-degraded ranking</span>{% endif %}
    {% if rankings_with_confidence and rankings_with_confidence.lowest_cpu_avg and rankings_with_confidence.lowest_cpu_avg.excluded %}
    <span class="small">(excluded: {% for rid, reason in rankings_with_confidence.lowest_cpu_avg.excluded %}<code>{{ rid }}</code> {% endfor %})</span>
    {% endif %}
  </li>
  <li><b>Lowest p95 latency:</b> <code>{{ verdicts.lowest_latency_p95 or '—' }}</code>
    {% if rankings_with_confidence and rankings_with_confidence.lowest_latency_p95 and not rankings_with_confidence.lowest_latency_p95.trusted %}
    <span class="cadence-pill degraded">cadence-degraded ranking</span>{% endif %}
  </li>
  <li><b>Fewest anomalies:</b> <code>{{ verdicts.fewest_anomalies or '—' }}</code>
    <span class="small">(cadence-immune)</span>
  </li>
  </ul>
</div>

<h2>Recommendations</h2>
<div class="card">
{% if recommendations %}
  {% for r in recommendations %}
  <div class="rec {{ r.severity }}">
    <span class="sev">{{ r.severity }}</span>
    <span class="cadence-pill {% if r.confidence == 'high' %}good{% elif r.confidence == 'medium' %}degraded{% else %}unknown{% endif %}">conf: {{ r.confidence or 'medium' }}</span>
    <b>{{ r.run_id }}</b> — {{ r.category }}: {{ r.recommendation }}
    <div class="small" style="margin-top:4px;"><i>{{ r.based_on }}</i></div>
    {% if r.evidence %}
    <ul class="small" style="margin:4px 0 0 0;">{% for e in r.evidence %}<li>{{ e }}</li>{% endfor %}</ul>
    {% endif %}
  </div>
  {% endfor %}
{% else %}
<p class="small">No rule-based recommendations triggered. Review the pairwise observations and hardware diff below.</p>
{% endif %}
</div>

<h2>Root-cause hypotheses</h2>
<div class="card">
{% if hypotheses %}
  <table><thead><tr>
    <th>run</th><th>vs peer</th><th>category</th><th>severity</th>
    <th>confidence</th><th>hypothesis</th>
  </tr></thead><tbody>
  {% for h in hypotheses %}
  <tr>
    <td><code>{{ h.run_id }}</code></td>
    <td><code>{{ h.peer_id or '—' }}</code></td>
    <td>{{ h.category }}</td>
    <td>{{ h.severity }}</td>
    <td><span class="cadence-pill {% if h.confidence == 'high' %}good{% elif h.confidence == 'medium' %}degraded{% else %}unknown{% endif %}">{{ h.confidence or 'medium' }}</span></td>
    <td>{{ h.hypothesis }}
      {% if h.evidence %}<details><summary>evidence</summary>
      <ul class="small">{% for e in h.evidence %}<li>{{ e }}</li>{% endfor %}</ul></details>{% endif %}
    </td>
  </tr>
  {% endfor %}
  </tbody></table>
  <p class="small" style="margin-top:8px"><i>
    Confidence: <b>high</b> = direct mechanism observed (disk tier, RAM
    delta with observed memory pressure, declared machine_class
    mismatch); <b>medium</b> = plausible mechanism with partial
    evidence; <b>low</b> = candidate factor, correlation only.
  </i></p>
{% else %}
<p class="small">No hypotheses triggered by the current rule set.</p>
{% endif %}
</div>

<h2>Matrix</h2>
<div class="card">
  <table><thead><tr>
    <th>run</th><th>host</th><th>cpu</th><th>ram</th><th>disk</th><th>mode</th><th>tags</th><th>dur</th>
    <th>overall</th><th>stab</th><th>eff</th><th>wkl</th><th>sec</th><th>net</th><th>hyg</th>
    <th>cpu avg</th><th>mem avg</th><th>disk avg</th><th>p95 lat</th>
    <th>anom</th><th>slow</th><th>mleaks</th><th>primary</th>
  </tr></thead><tbody>
  {% for r in rows %}
  <tr>
    <td><code>{{ r.run_id }}</code></td>
    <td>{{ r.hostname }}</td>
    <td class="small">{{ r.cpu_model or '—' }}</td>
    <td class="num">{{ r.ram_gb or '—' }}</td>
    <td>{{ r.primary_disk_tier or '—' }}</td>
    <td>{{ r.mode }}</td><td>{{ r.tags }}</td>
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

{% if cross_run_view %}
<h2>Cross-run view
  <span class="small">(M5 machine_id, M2 meta, A6 tail-window, C3 baselines)</span></h2>
<div class="card">
  <div class="kvs">
    <div class="kv">
      <div class="k">Same machine?</div>
      <div class="v">
        {% if cross_run_view.same_machine %}
          <span class="badge low">YES — longitudinal trend</span>
        {% else %}
          <span class="badge medium">no</span>
        {% endif %}
      </div>
    </div>
    {% if cross_run_view.shared_machine_class %}
    <div class="kv"><div class="k">Shared machine class</div>
      <div class="v">{{ cross_run_view.shared_machine_class }}</div></div>
    {% endif %}
    {% if cross_run_view.shared_capture_profile %}
    <div class="kv"><div class="k">Shared capture profile</div>
      <div class="v">{{ cross_run_view.shared_capture_profile }}</div></div>
    {% endif %}
  </div>

  <h3>Machine identity</h3>
  <table><thead><tr>
    <th>run</th><th>machine_id</th><th>source</th>
  </tr></thead><tbody>
    {% for m in cross_run_view.machine_ids %}
    <tr>
      <td><code>{{ m.run_id }}</code></td>
      <td><code>{{ m.machine_id or '—' }}</code></td>
      <td class="small">{{ m.machine_id_source or '—' }}</td>
    </tr>
    {% endfor %}
  </tbody></table>

  {% if cross_run_view.shared_meta %}
  <h3>Shared metadata <span class="small">(every run agrees)</span></h3>
  <table><thead><tr><th>key</th><th>value</th></tr></thead><tbody>
    {% for k, v in cross_run_view.shared_meta.items() %}
    <tr><td><code>{{ k }}</code></td><td>{{ v }}</td></tr>
    {% endfor %}
  </tbody></table>
  {% endif %}

  {% if cross_run_view.tail_window_view.common_window_label %}
  <h3>Tail-window-aligned scores
    <span class="small">(comparable across run lengths — A6)</span></h3>
  <p class="small">All runs scored over their <b>{{ cross_run_view.tail_window_view.common_window_label }}</b> tail window.</p>
  <table><thead><tr>
    <th>run</th><th>overall</th>
    <th>stability</th><th>efficiency</th><th>workload</th>
    <th>network</th><th>hygiene</th>
  </tr></thead><tbody>
    {% for r in cross_run_view.tail_window_view.rows %}
    <tr>
      <td><code>{{ r.run_id }}</code></td>
      <td><b>{{ r.overall }}</b></td>
      <td>{{ r.stability }}</td>
      <td>{{ r.efficiency }}</td>
      <td>{{ r.workload_suitability }}</td>
      <td>{{ r.network_impact }}</td>
      <td>{{ r.resource_hygiene }}</td>
    </tr>
    {% endfor %}
  </tbody></table>
  {% endif %}

  {% if cross_run_view.baseline_deviations.common %}
  <h3>Common baseline deviations <span class="small">(every run shows them)</span></h3>
  <table><thead><tr><th>class</th><th>metric</th></tr></thead><tbody>
    {% for d in cross_run_view.baseline_deviations.common %}
    <tr><td>{{ d.machine_class }}</td><td>{{ d.metric }}</td></tr>
    {% endfor %}
  </tbody></table>
  {% endif %}
</div>
{% endif %}

<h2>Hardware</h2>
<div class="card">
{% if hw_profiles %}
<p class="small">Fields highlighted in yellow differ between the compared runs.</p>
<table><thead><tr>
  <th>field</th>
  {% for p in hw_profiles %}<th><code>{{ p.run_id }}</code></th>{% endfor %}
</tr></thead><tbody>
  {% for f in hw_fields %}
  <tr>
    <td>{{ f.label }}</td>
    {% for p in hw_profiles %}
      <td class="{% if f.key in hw_divergent %}diverge{% endif %}">
        {% set v = p[f.key] %}
        {% if v is none %}—
        {% elif v is iterable and v is not string %}{{ v | join(', ') or '—' }}
        {% else %}{{ v }}{% endif %}
      </td>
    {% endfor %}
  </tr>
  {% endfor %}
</tbody></table>
{% else %}<p class="small">No hardware profiles available.</p>{% endif %}
</div>

<h2>Configuration</h2>
<div class="card">
{% if cfg_profiles %}
<table><thead><tr>
  <th>field</th>
  {% for p in cfg_profiles %}<th><code>{{ p.run_id }}</code></th>{% endfor %}
</tr></thead><tbody>
  {% for f in cfg_fields %}
  <tr>
    <td>{{ f.label }}</td>
    {% for p in cfg_profiles %}
      <td class="{% if f.key in cfg_divergent %}diverge{% endif %}">
        {% set v = p[f.key] %}
        {% if v is none %}—
        {% elif v is iterable and v is not string %}{{ v | join(', ') or '—' }}
        {% else %}{{ v }}{% endif %}
      </td>
    {% endfor %}
  </tr>
  {% endfor %}
</tbody></table>
{% else %}<p class="small">No configuration profiles available.</p>{% endif %}
</div>

<h2>Bottleneck profiles</h2>
<div class="card">
{% if bottlenecks.by_primary %}
  <p class="small">Primary bottleneck distribution across runs:</p>
  <ul>
  {% for primary, rids in bottlenecks.by_primary.items() %}
  <li><b>{{ primary }}</b>: {% for rid in rids %}<code>{{ rid }}</code>{% if not loop.last %}, {% endif %}{% endfor %}</li>
  {% endfor %}
  </ul>
{% else %}<p class="small">No primary bottleneck data available.</p>{% endif %}
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

<h2>Software delta</h2>
<div class="card">
{% if sw_pairwise %}
  {% for p in sw_pairwise %}
  <h3><code>{{ p.pair[0] }}</code> ↔ <code>{{ p.pair[1] }}</code></h3>
  <p class="small">Only in <code>{{ p.pair[0] }}</code>: {{ p.only_in_a_total }} programs —
    only in <code>{{ p.pair[1] }}</code>: {{ p.only_in_b_total }} programs —
    version-changed: {{ p.version_changed_total }}</p>
  {% if p.only_in_a %}<details><summary>Only in {{ p.pair[0] }} ({{ p.only_in_a_total }})</summary>
    <ul class="small">{% for name in p.only_in_a %}<li>{{ name }}</li>{% endfor %}</ul></details>{% endif %}
  {% if p.only_in_b %}<details><summary>Only in {{ p.pair[1] }} ({{ p.only_in_b_total }})</summary>
    <ul class="small">{% for name in p.only_in_b %}<li>{{ name }}</li>{% endfor %}</ul></details>{% endif %}
  {% if p.version_changed %}<details><summary>Version changed ({{ p.version_changed_total }})</summary>
    <table><thead><tr><th>program</th><th><code>{{ p.pair[0] }}</code></th><th><code>{{ p.pair[1] }}</code></th></tr></thead><tbody>
    {% for v in p.version_changed %}
    <tr><td>{{ v.name }}</td><td>{{ v[p.pair[0]] }}</td><td>{{ v[p.pair[1]] }}</td></tr>
    {% endfor %}
    </tbody></table></details>{% endif %}
  {% endfor %}
{% else %}<p class="small">No software delta data.</p>{% endif %}
</div>

<h2>Autoruns delta</h2>
<div class="card">
{% if autoruns_pairwise %}
  {% for p in autoruns_pairwise %}
  <h3><code>{{ p.pair[0] }}</code> ↔ <code>{{ p.pair[1] }}</code></h3>
  <p class="small">Only in <code>{{ p.pair[0] }}</code>: {{ p.only_in_a_total }} —
    only in <code>{{ p.pair[1] }}</code>: {{ p.only_in_b_total }}</p>
  {% if p.only_in_a %}<details><summary>Only in {{ p.pair[0] }} ({{ p.only_in_a_total }})</summary>
    <table><thead><tr><th>name</th><th>command</th></tr></thead><tbody>
    {% for e in p.only_in_a %}<tr><td>{{ e.name }}</td><td><code>{{ e.command }}</code></td></tr>{% endfor %}
    </tbody></table></details>{% endif %}
  {% if p.only_in_b %}<details><summary>Only in {{ p.pair[1] }} ({{ p.only_in_b_total }})</summary>
    <table><thead><tr><th>name</th><th>command</th></tr></thead><tbody>
    {% for e in p.only_in_b %}<tr><td>{{ e.name }}</td><td><code>{{ e.command }}</code></td></tr>{% endfor %}
    </tbody></table></details>{% endif %}
  {% endfor %}
{% else %}<p class="small">No autoruns delta data.</p>{% endif %}
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


_HW_FIELDS = [
    ("manufacturer", "Manufacturer"),
    ("model", "Model"),
    ("os_caption", "OS"),
    ("os_build", "OS build"),
    ("cpu_name", "CPU"),
    ("cpu_cores", "CPU cores"),
    ("cpu_threads", "CPU threads"),
    ("cpu_max_mhz", "CPU max MHz"),
    ("ram_gb", "RAM (GB)"),
    ("ram_modules", "RAM modules"),
    ("ram_speed_mhz", "RAM speed (MHz)"),
    ("primary_disk_model", "Primary disk model"),
    ("primary_disk_size_gb", "Primary disk size (GB)"),
    ("primary_disk_media", "Primary disk media"),
    ("primary_disk_interface", "Primary disk interface"),
    ("gpus", "GPUs"),
    ("bios_version", "BIOS version"),
    ("bios_date", "BIOS date"),
]

_CFG_FIELDS = [
    ("power_plan", "Power plan"),
    ("defender_realtime", "Defender real-time"),
    ("defender_av_enabled", "Defender AV enabled"),
    ("defender_signature", "Defender signature"),
    ("av_products", "AV products"),
    ("av_product_count", "AV product count"),
    ("vpn_adapters", "VPN adapters"),
]


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
    mode_lbl: str,
    hw_diff: dict[str, Any],
    cfg_diff: dict[str, Any],
    hypotheses: list[dict[str, Any]],
    recommendations: list[dict[str, Any]],
    *,
    cadence_per_run: list[dict[str, Any]] | None = None,
    cadence_warnings: list[dict[str, Any]] | None = None,
    peer_classes: list[dict[str, Any]] | None = None,
    peer_warnings: list[dict[str, Any]] | None = None,
) -> str:
    cadence_per_run = cadence_per_run or []
    cadence_warnings = cadence_warnings or []
    peer_classes = peer_classes or []
    peer_warnings = peer_warnings or []

    lines = [f"# SysSpecter comparison — {comparison_id}", "_See everything. Find the cause._", ""]
    lines.append(f"**Analysis mode:** {mode_lbl} _(auto-detected from hostnames)_")
    lines.append("")
    lines.append("## Runs")
    for r in runs:
        m = r["manifest"]
        lines.append(
            f"- `{m.get('run_id')}` — {m.get('hostname')} / {m.get('mode')} "
            f"/ tags: {', '.join(m.get('tags') or []) or '—'} ({m.get('duration_actual_seconds')}s)"
        )
    lines.append("")

    # v3-priority-2: cadence-quality block. Shown before the verdicts
    # so a reader sees the caveat first.
    if cadence_warnings:
        lines.append("## Cadence quality — comparison caveat")
        lines.append("")
        lines.append(
            "The runs being compared have heterogeneous sample cadence. "
            "Sample-density-sensitive metrics (cpu_avg, mem_avg, "
            "latency_p95, etc.) carry reduced confidence; cadence-immune "
            "metrics (anomaly counts, leak detections) are unaffected."
        )
        lines.append("")
        for w in cadence_warnings:
            lines.append(f"- **[{w.get('severity')}]** {w.get('hypothesis')}")
        lines.append("")
    elif cadence_per_run:
        lines.append("## Cadence quality")
        lines.append("")
        lines.append("All runs sampled within 1.5× their nominal cadence. "
                     "Cross-run metrics are directly comparable.")
        lines.append("")

    # v3-priority-3: peer-context section, parallel to cadence_quality.
    if peer_warnings:
        lines.append("## Peer context — non-peer comparison")
        lines.append("")
        lines.append(
            "The runs being compared have different declared "
            "`machine_class` values (different workload-profile peer "
            "groups). Direct comparison of idle CPU, memory pressure, "
            "or latency may overstate real differences."
        )
        lines.append("")
        for w in peer_warnings:
            lines.append(f"- **[{w.get('severity')}]** {w.get('hypothesis')}")
        lines.append("")

    if peer_classes:
        lines.append("### Per-run machine class")
        lines.append("| run | declared | normalised | peer group |")
        lines.append("|---|---|---|---|")
        for p in peer_classes:
            lines.append(
                f"| `{p.get('run_id')}` "
                f"| {p.get('machine_class') or '—'} "
                f"| {p.get('machine_class_normalised') or '—'} "
                f"| {p.get('peer_group') or '—'} |"
            )
        lines.append("")

    if cadence_per_run:
        lines.append("### Per-run cadence")
        lines.append("| run | health | nominal | median gap | p95 gap | max gap | samples | priority |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for p in cadence_per_run:
            lines.append(
                f"| `{p.get('run_id')}` "
                f"| {p.get('cadence_health') or '—'} "
                f"| {p.get('nominal_interval_seconds') or '—'}s "
                f"| {p.get('median_gap_seconds') if p.get('median_gap_seconds') is not None else '—'}s "
                f"| {p.get('p95_gap_seconds') if p.get('p95_gap_seconds') is not None else '—'}s "
                f"| {p.get('max_gap_seconds') if p.get('max_gap_seconds') is not None else '—'}s "
                f"| {p.get('samples_total') or '—'} "
                f"| {p.get('process_priority_class') or '—'} |"
            )
        lines.append("")

    lines.append("## Verdicts")
    for k, v in verdicts.items():
        lines.append(f"- **{k}**: `{v or '—'}`")
    lines.append("")

    if recommendations:
        lines.append("## Recommendations")
        for r in recommendations:
            conf = r.get("confidence") or "medium"
            lines.append(
                f"- **[sev={r.get('severity')}, conf={conf}]** "
                f"`{r.get('run_id')}` — {r.get('category')}: "
                f"{r.get('recommendation')}"
            )
            if r.get("based_on"):
                lines.append(f"    - _based on:_ {r['based_on']}")
        lines.append("")

    if hypotheses:
        lines.append("## Root-cause hypotheses")
        lines.append("")
        lines.append(
            "_Confidence: **high** = direct mechanism observed; "
            "**medium** = plausible mechanism with partial evidence; "
            "**low** = candidate factor, correlation only._"
        )
        lines.append("")
        for h in hypotheses:
            conf = h.get("confidence") or "medium"
            lines.append(
                f"- **[sev={h.get('severity')}, conf={conf}]** "
                f"`{h.get('run_id')}` vs `{h.get('peer_id') or '—'}` "
                f"({h.get('category')}): {h.get('hypothesis')}"
            )
            for e in (h.get("evidence") or []):
                lines.append(f"    - {e}")
        lines.append("")

    rows = matrix["rows"]
    if rows:
        lines.append("## Matrix")
        fields = ["run_id", "hostname", "cpu_model", "ram_gb", "primary_disk_tier",
                  "mode", "overall", "stability", "efficiency",
                  "workload", "security", "network", "hygiene",
                  "cpu_avg", "mem_avg", "disk_avg", "latency_p95_ms",
                  "anomalies", "slowdowns", "primary"]
        lines.append("| " + " | ".join(fields) + " |")
        lines.append("|" + "|".join(["---"] * len(fields)) + "|")
        for row in rows:
            lines.append("| " + " | ".join(str(row.get(f, "")) for f in fields) + " |")
        lines.append("")

    hw_profiles = hw_diff.get("profiles") or []
    hw_divergent = set(hw_diff.get("divergent_fields") or [])
    if hw_profiles:
        lines.append("## Hardware")
        lines.append("| field | " + " | ".join(p["run_id"] for p in hw_profiles) + " |")
        lines.append("|" + "|".join(["---"] * (len(hw_profiles) + 1)) + "|")
        for key, label in _HW_FIELDS:
            marker = " *(differs)*" if key in hw_divergent else ""
            vals = []
            for p in hw_profiles:
                v = p.get(key)
                if v is None:
                    vals.append("—")
                elif isinstance(v, list):
                    vals.append(", ".join(str(x) for x in v) or "—")
                else:
                    vals.append(str(v))
            lines.append(f"| {label}{marker} | " + " | ".join(vals) + " |")
        lines.append("")

    cfg_profiles = cfg_diff.get("profiles") or []
    cfg_divergent = set(cfg_diff.get("divergent_fields") or [])
    if cfg_profiles:
        lines.append("## Configuration")
        lines.append("| field | " + " | ".join(p["run_id"] for p in cfg_profiles) + " |")
        lines.append("|" + "|".join(["---"] * (len(cfg_profiles) + 1)) + "|")
        for key, label in _CFG_FIELDS:
            marker = " *(differs)*" if key in cfg_divergent else ""
            vals = []
            for p in cfg_profiles:
                v = p.get(key)
                if v is None:
                    vals.append("—")
                elif isinstance(v, list):
                    vals.append(", ".join(str(x) for x in v) or "—")
                else:
                    vals.append(str(v))
            lines.append(f"| {label}{marker} | " + " | ".join(vals) + " |")
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
    *,
    mode: str = "fleet",
    hw_diff: dict[str, Any] | None = None,
    sw_diff: dict[str, Any] | None = None,
    autoruns_diff: dict[str, Any] | None = None,
    cfg_diff: dict[str, Any] | None = None,
    bottlenecks: dict[str, Any] | None = None,
    hypotheses: list[dict[str, Any]] | None = None,
    recommendations: list[dict[str, Any]] | None = None,
    cross_run_view: dict[str, Any] | None = None,
    cadence_per_run: list[dict[str, Any]] | None = None,
    cadence_warnings: list[dict[str, Any]] | None = None,
    rankings_with_confidence: dict[str, Any] | None = None,
    peer_classes: list[dict[str, Any]] | None = None,
    peer_warnings: list[dict[str, Any]] | None = None,
) -> None:
    env = Environment(loader=BaseLoader(), autoescape=select_autoescape())
    tpl = env.from_string(_TEMPLATE)

    cpu_chart = _overlay_chart(runs, "cpu_total_pct", "CPU total (%) — overlay", "%")
    mem_chart = _overlay_chart(runs, "mem_percent", "Memory used (%) — overlay", "%")

    hw_diff = hw_diff or {"profiles": [], "divergent_fields": []}
    sw_diff = sw_diff or {"pairwise": []}
    autoruns_diff = autoruns_diff or {"pairwise": []}
    cfg_diff = cfg_diff or {"profiles": [], "divergent_fields": []}
    bottlenecks = bottlenecks or {"by_primary": {}}
    hypotheses = hypotheses or []
    recommendations = recommendations or []
    cadence_per_run = cadence_per_run or []
    cadence_warnings = cadence_warnings or []
    rankings_with_confidence = rankings_with_confidence or {}
    peer_classes = peer_classes or []
    peer_warnings = peer_warnings or []

    from .mode import mode_label
    mode_lbl = mode_label(mode)  # type: ignore[arg-type]

    html_str = tpl.render(
        css=_CSS,
        comparison_id=paths.comparison_id,
        mode=mode,
        mode_label=mode_lbl,
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
        hw_profiles=hw_diff.get("profiles") or [],
        hw_divergent=set(hw_diff.get("divergent_fields") or []),
        hw_fields=[{"key": key, "label": label} for key, label in _HW_FIELDS],
        cfg_profiles=cfg_diff.get("profiles") or [],
        cfg_divergent=set(cfg_diff.get("divergent_fields") or []),
        cfg_fields=[{"key": key, "label": label} for key, label in _CFG_FIELDS],
        sw_pairwise=sw_diff.get("pairwise") or [],
        autoruns_pairwise=autoruns_diff.get("pairwise") or [],
        bottlenecks=bottlenecks,
        hypotheses=hypotheses,
        recommendations=recommendations,
        cross_run_view=cross_run_view,
        cadence_per_run=cadence_per_run,
        cadence_warnings=cadence_warnings,
        rankings_with_confidence=rankings_with_confidence,
        peer_classes=peer_classes,
        peer_warnings=peer_warnings,
    )
    tmp = paths.html + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(html_str)
    os.replace(tmp, paths.html)

    md = _build_markdown(
        paths.comparison_id, runs, matrix, differences, problems, verdicts,
        mode_lbl, hw_diff, cfg_diff, hypotheses, recommendations,
        cadence_per_run=cadence_per_run,
        cadence_warnings=cadence_warnings,
        peer_classes=peer_classes,
        peer_warnings=peer_warnings,
    )
    with open(paths.md, "w", encoding="utf-8") as f:
        f.write(md)
