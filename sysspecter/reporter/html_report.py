"""HTML report generator — fully offline, inline SVG charts, no CDN."""

from __future__ import annotations

import html
import os
from typing import Any

from jinja2 import Environment, BaseLoader, select_autoescape

from ..analyzer.loader import load_run
from ..analyzer.pipeline import analyze_run
from ..logging_setup import get_logger
from .json_export import atomic_write_json, load_json
from .markdown_report import generate_markdown_summary
from .svg_charts import heatmap, line_chart, stacked_area_chart


_CSS = """
body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
       color: #222; margin: 0; padding: 0; background: #f7f7f9; }
.wrapper { max-width: 1180px; margin: 0 auto; padding: 16px 24px; }
h1, h2, h3 { color: #1b2a4e; }
h1 { font-size: 24px; margin-top: 8px; margin-bottom: 2px; }
.tagline { color: #6b7a99; font-size: 12px; letter-spacing: 2px; text-transform: uppercase; margin: 0 0 14px 0; }
h2 { border-bottom: 1px solid #e2e6ee; padding-bottom: 4px; margin-top: 32px; }
h3 { margin-top: 24px; font-size: 16px; }
.card { background: #fff; border: 1px solid #e2e6ee; border-radius: 6px;
        padding: 14px 18px; margin-bottom: 14px; box-shadow: 0 1px 2px rgba(0,0,0,.03); }
.kvs { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px,1fr)); gap: 6px 20px; }
.kv { font-size: 13px; }
.kv .k { color: #666; }
.kv .v { color: #111; font-weight: 600; }
.verdict { font-size: 15px; background: #fffbe6; border-left: 4px solid #faad14;
           padding: 10px 14px; border-radius: 4px; }
.score-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px,1fr)); gap: 10px; }
.score { background: #f3f5fa; border-radius: 6px; padding: 10px 12px; }
.score .name { font-size: 12px; color: #555; text-transform: uppercase; letter-spacing: 0.4px; }
.score .val { font-size: 24px; font-weight: 700; margin-top: 4px; }
.score.good .val { color: #389e0d; }
.score.med .val { color: #d48806; }
.score.bad .val { color: #cf1322; }
.bar { background: #eef0f7; height: 6px; border-radius: 3px; overflow: hidden; margin-top: 6px; }
.bar > div { height: 100%; background: linear-gradient(90deg,#91d5ff,#2c7be5); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px;
         font-weight: 600; margin-right: 6px; }
.badge.high { background: #fff1f0; color: #cf1322; border: 1px solid #ffa39e; }
.badge.medium { background: #fffbe6; color: #d46b08; border: 1px solid #ffe58f; }
.badge.low { background: #f6ffed; color: #389e0d; border: 1px solid #b7eb8f; }
.badge.suspicious { background: #fff7e6; color: #ad6800; }
.badge.likely { background: #fff2e8; color: #d4380d; }
.badge.strong.evidence, .badge.strong-evidence { background: #fff1f0; color: #a8071a; }
table { border-collapse: collapse; width: 100%; margin-top: 6px; font-size: 13px; }
th, td { border-bottom: 1px solid #eef0f7; padding: 6px 10px; text-align: left; }
th { background: #f6f8fc; color: #445; font-weight: 600; }
tbody tr:hover { background: #fafbff; }
.finding { margin-bottom: 8px; padding-left: 10px; border-left: 3px solid #2c7be5; }
.finding.high { border-left-color: #cf1322; }
.finding.medium { border-left-color: #faad14; }
.finding.low { border-left-color: #52c41a; }
.small { font-size: 12px; color: #777; }
details > summary { cursor: pointer; font-weight: 600; color: #1b2a4e; }
details { margin-top: 10px; }
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 880px) { .grid-2 { grid-template-columns: 1fr; } }
.footer { color: #999; font-size: 12px; margin: 40px 0 20px; text-align: center; }
code { background: #f3f5fa; padding: 1px 5px; border-radius: 3px; font-size: 12px; }
"""


_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"/>
<title>SysSpecter — {{ manifest.hostname }} — {{ manifest.run_id }}</title>
<style>{{ css }}</style>
</head><body>
<div class="wrapper">

<h1>SysSpecter report — {{ manifest.hostname }}</h1>
<p class="tagline">See everything. Find the cause.</p>
<div class="card">
  <div class="kvs">
    <div class="kv"><div class="k">Run ID</div><div class="v">{{ manifest.run_id }}</div></div>
    <div class="kv"><div class="k">Mode</div><div class="v">{{ manifest.mode }}</div></div>
    <div class="kv"><div class="k">Started</div><div class="v">{{ manifest.started_at }}</div></div>
    <div class="kv"><div class="k">Ended</div><div class="v">{{ manifest.ended_at }}</div></div>
    <div class="kv"><div class="k">Actual duration</div><div class="v">{{ manifest.duration_actual_seconds }} s</div></div>
    <div class="kv"><div class="k">Interval</div><div class="v">{{ manifest.interval_seconds }} s</div></div>
    <div class="kv"><div class="k">Stop reason</div><div class="v">{{ manifest.stop_reason }}</div></div>
    <div class="kv"><div class="k">Privilege</div><div class="v">{{ manifest.privilege_level }}</div></div>
    <div class="kv"><div class="k">Target</div><div class="v">{{ target_text }}</div></div>
    <div class="kv"><div class="k">Tags</div><div class="v">{{ manifest.tags | join(', ') or '—' }}</div></div>
  </div>
</div>

<h2>Executive summary</h2>
<div class="card">
  <div class="verdict">{{ findings.summary.verdict }}</div>
  <h3>Scores</h3>
  <div class="score-grid">
    {% for s in score_cards %}
    <div class="score {{ s.cls }}">
      <div class="name">{{ s.name }}</div>
      <div class="val">{{ s.val }}</div>
      <div class="bar"><div style="width:{{ s.bar_pct }}%"></div></div>
    </div>
    {% endfor %}
  </div>
  <p class="small" style="margin-top:10px;">
    Primary bottleneck:
    <b>{{ scores.primary_bottleneck or 'none clearly dominant' }}</b>.
    Secondary: {{ scores.secondary_bottlenecks | join(', ') or '—' }}.
    Confidence: <b>{{ scores.confidence }}</b> ({{ scores.sample_count }} samples).
  </p>
</div>

<h2>System profile</h2>
<div class="card">
  <div class="kvs">
    <div class="kv"><div class="k">OS</div><div class="v">{{ static.os.caption or '—' }}</div></div>
    <div class="kv"><div class="k">Build</div><div class="v">{{ static.os.version }} ({{ static.os.build }})</div></div>
    <div class="kv"><div class="k">Arch</div><div class="v">{{ static.os.architecture or '—' }}</div></div>
    <div class="kv"><div class="k">Manufacturer</div><div class="v">{{ static.computer_system.Manufacturer or '—' }}</div></div>
    <div class="kv"><div class="k">Model</div><div class="v">{{ static.computer_system.Model or '—' }}</div></div>
    <div class="kv"><div class="k">CPU</div><div class="v">{{ cpu_name }}</div></div>
    <div class="kv"><div class="k">Cores</div><div class="v">{{ static.cpu.physical_cores }} physical / {{ static.cpu.logical_cores }} logical</div></div>
    <div class="kv"><div class="k">RAM</div><div class="v">{{ ram_gb }} GB</div></div>
    <div class="kv"><div class="k">BIOS</div><div class="v">{{ static.bios.SMBIOSBIOSVersion or static.bios.Version or '—' }} ({{ static.bios.ReleaseDate or '—' }})</div></div>
    <div class="kv"><div class="k">Defender</div><div class="v">{{ defender_text }}</div></div>
    <div class="kv"><div class="k">VPN adapters suspected</div><div class="v">{{ static.network.vpn_suspect_adapters | join(', ') or '—' }}</div></div>
    <div class="kv"><div class="k">Power plan</div><div class="v">{{ power_plan }}</div></div>
  </div>
  <details><summary>Installed programs ({{ static.installed_programs | length }})</summary>
    <table><thead><tr><th>Name</th><th>Version</th><th>Publisher</th></tr></thead><tbody>
    {% for p in static.installed_programs[:200] %}
    <tr><td>{{ p.DisplayName }}</td><td>{{ p.DisplayVersion }}</td><td>{{ p.Publisher }}</td></tr>
    {% endfor %}</tbody></table>
    {% if static.installed_programs|length > 200 %}<p class="small">(truncated to 200)</p>{% endif %}
  </details>
  <details><summary>Autoruns ({{ static.autoruns | length }})</summary>
    <table><thead><tr><th>Name</th><th>Command</th><th>Location</th><th>User</th></tr></thead><tbody>
    {% for a in static.autoruns %}<tr><td>{{ a.Name }}</td><td><code>{{ a.Command }}</code></td><td>{{ a.Location }}</td><td>{{ a.User }}</td></tr>{% endfor %}
    </tbody></table>
  </details>
</div>

<h2>Charts</h2>
<div class="card">
  <div>{{ cpu_chart | safe }}</div>
  <div>{{ mem_chart | safe }}</div>
  <div>{{ disk_chart | safe }}</div>
  <div>{{ net_chart | safe }}</div>
  <div>{{ heatmap_svg | safe }}</div>
  {% if disk_stack_chart %}<div>{{ disk_stack_chart | safe }}</div>{% endif %}
  {% if net_stack_chart %}<div>{{ net_stack_chart | safe }}</div>{% endif %}
  {% if app_cpu_stack_chart %}<div>{{ app_cpu_stack_chart | safe }}</div>{% endif %}
  {% if app_rss_stack_chart %}<div>{{ app_rss_stack_chart | safe }}</div>{% endif %}
  {% if latency_chart %}<div>{{ latency_chart | safe }}</div>{% endif %}
  {% if top_processes_chart %}<div>{{ top_processes_chart | safe }}</div>{% endif %}
</div>

<h2>Key findings</h2>
<div class="card">
  {% if findings.anomalies %}
    {% for a in findings.anomalies %}
    <div class="finding {{ a.severity }}"><span class="badge {{ a.severity }}">{{ a.severity }}</span>
      <b>{{ a.kind }}</b> — {{ a.description }}
    </div>
    {% endfor %}
  {% else %}
    <p class="small">No anomalies crossed their thresholds.</p>
  {% endif %}
</div>

<h2>Slowdown windows</h2>
<div class="card">
  {% if findings.slowdowns %}
  <table><thead><tr>
    <th>s=start</th><th>s=end</th><th>dur</th><th>confidence</th>
    <th>reasons</th><th>peak cpu</th><th>peak mem</th><th>peak disk</th><th>top cpu offender</th>
  </tr></thead><tbody>
  {% for s in findings.slowdowns %}
  <tr>
    <td>{{ '%.0f' % s.start_rel }}</td><td>{{ '%.0f' % s.end_rel }}</td>
    <td>{{ s.duration_s }}</td>
    <td><span class="badge {{ s.confidence | replace(' ','-') }}">{{ s.confidence }}</span></td>
    <td>{{ s.reason_tags | join(', ') }}</td>
    <td>{{ s.peak_cpu_pct }}%</td><td>{{ s.peak_mem_pct }}%</td><td>{{ s.peak_disk_pct }}%</td>
    <td>{% if s.offenders.top_cpu %}{{ s.offenders.top_cpu[0].name }} ({{ s.offenders.top_cpu[0].value }}%){% else %}—{% endif %}</td>
  </tr>
  <tr><td colspan="9" class="small">{{ s.description }}</td></tr>
  {% endfor %}</tbody></table>
  {% else %}<p class="small">No slowdown windows detected above the minimum duration threshold.</p>{% endif %}
</div>

<h2>Leak candidates</h2>
<div class="card">
  {% set leaks = findings.leaks %}
  {% for kind in ['memory','handles','threads'] %}
    {% if leaks[kind] %}
    <h3>{{ kind }}</h3>
    <table><thead><tr><th>pid</th><th>name</th><th>confidence</th><th>detail</th></tr></thead><tbody>
    {% for it in leaks[kind] %}
    <tr><td>{{ it.pid }}</td><td>{{ it.process_name }}</td>
        <td><span class="badge {{ it.confidence | replace(' ','-') }}">{{ it.confidence }}</span></td>
        <td>{{ it.description }}</td></tr>
    {% endfor %}</tbody></table>
    {% endif %}
  {% endfor %}
  {% if not leaks.memory and not leaks.handles and not leaks.threads %}
  <p class="small">No resource-leak candidates met the heuristic thresholds.</p>
  {% endif %}
</div>

<h2>Top applications <span class="small">(PIDs grouped)</span></h2>
<div class="card">
{% if findings.apps and findings.apps.top_cpu %}
{% for label, title in app_sections %}
  {% set items = findings.apps[label] %}
  {% if items %}
  <h3>{{ title }}</h3>
  <table><thead><tr>
    <th>application</th><th>PIDs</th><th>cpu avg %</th><th>cpu peak %</th><th>rss peak MB</th>
    <th>handles peak</th><th>threads peak</th><th>io avg B/s</th>
  </tr></thead><tbody>
  {% for i in items %}
  <tr>
    <td>{% if i.is_target %}<b>{{ i.display_name }}</b>{% else %}{{ i.display_name }}{% endif %}
        <span class="small">({{ i.app_key }})</span></td>
    <td>{{ i.pid_count }}</td>
    <td>{{ i.cpu_pct_avg }}</td><td>{{ i.cpu_pct_max }}</td>
    <td>{{ i.rss_mb_max }}</td>
    <td>{{ i.num_handles_max }}</td>
    <td>{{ i.num_threads_max }}</td>
    <td>{{ ((i.io_read_bps_avg or 0) + (i.io_write_bps_avg or 0))|round(0) }}</td>
  </tr>
  {% endfor %}</tbody></table>
  {% endif %}
{% endfor %}
{% else %}
<p class="small">No per-app aggregates available.</p>
{% endif %}
</div>

<h2>Offenders <span class="small">(per-PID)</span></h2>
<div class="card">
{% for label, title in offender_sections %}
  {% set items = findings.offenders[label] %}
  {% if items %}
  <h3>{{ title }}</h3>
  <table><thead><tr>
    <th>pid</th><th>name</th><th>cpu avg %</th><th>cpu max %</th><th>rss MB</th>
    <th>handles</th><th>handle growth</th><th>threads</th><th>thread growth</th><th>io avg</th>
  </tr></thead><tbody>
  {% for i in items %}
  <tr>
    <td>{{ i.pid }}</td>
    <td>{% if i.is_target %}<b>{{ i.name }}</b>{% else %}{{ i.name }}{% endif %}</td>
    <td>{{ i.cpu_pct_avg }}</td><td>{{ i.cpu_pct_max }}</td>
    <td>{{ i.rss_mb_max }}</td>
    <td>{{ i.num_handles_max }}</td><td>{{ i.handle_growth }}</td>
    <td>{{ i.num_threads_max }}</td><td>{{ i.thread_growth }}</td>
    <td>{{ ((i.io_read_bps_avg or 0) + (i.io_write_bps_avg or 0))|round(0) }}</td>
  </tr>
  {% endfor %}</tbody></table>
  {% endif %}
{% endfor %}
</div>

<h2>Network attribution <span class="small">(connection-based)</span></h2>
<div class="card">
{% if findings.network_attribution and findings.network_attribution.by_app %}
<p class="small">Captured {{ findings.network_attribution.samples }} connection snapshot(s).
  Byte-level per-process attribution is not available via psutil on Windows — counts below are
  based on which processes owned TCP/UDP sockets at snapshot time.</p>
<h3>By application</h3>
<table><thead><tr>
  <th>application</th><th>PIDs</th><th>avg conns</th>
  <th>unique remotes</th><th>tcp %</th><th>udp %</th><th>top remote hosts</th>
</tr></thead><tbody>
{% for a in findings.network_attribution.by_app %}
<tr>
  <td>{{ a.display_name }} <span class="small">({{ a.app_key }})</span></td>
  <td>{{ a.pid_count }}</td>
  <td>{{ a.avg_concurrent_conns }}</td>
  <td>{{ a.unique_remote_count }}</td>
  <td>{{ a.tcp_share_pct }}</td>
  <td>{{ a.udp_share_pct }}</td>
  <td class="small">{% for r in a.top_remotes %}{{ r.host }}{% if not loop.last %}, {% endif %}{% endfor %}</td>
</tr>
{% endfor %}
</tbody></table>
<h3>By PID</h3>
<table><thead><tr>
  <th>pid</th><th>name</th><th>avg conns</th>
  <th>unique remotes</th><th>tcp %</th><th>udp %</th><th>top remote hosts</th>
</tr></thead><tbody>
{% for p in findings.network_attribution.by_pid %}
<tr>
  <td>{{ p.pid }}</td>
  <td>{{ p.name }}</td>
  <td>{{ p.avg_concurrent_conns }}</td>
  <td>{{ p.unique_remote_count }}</td>
  <td>{{ p.tcp_share_pct }}</td>
  <td>{{ p.udp_share_pct }}</td>
  <td class="small">{% for r in p.top_remotes %}{{ r.host }}{% if not loop.last %}, {% endif %}{% endfor %}</td>
</tr>
{% endfor %}
</tbody></table>
{% else %}
<p class="small">No connection snapshots captured (run too short, or no privilege to enumerate sockets).</p>
{% endif %}
</div>

<h2>Latency &amp; DNS</h2>
<div class="card">
{% if findings.latency_analysis and findings.latency_analysis.targets %}
<p class="small">Per-target summary of ICMP round-trip time, jitter, packet loss, and
  DNS resolution latency ({{ findings.latency_analysis.samples }} sample rows).</p>
<table><thead><tr>
  <th>target</th><th>resolved</th><th>samples</th>
  <th>loss %</th><th>rtt avg ms</th><th>rtt p95 ms</th><th>rtt max ms</th>
  <th>jitter avg ms</th>
  <th>dns avg ms</th><th>dns p95 ms</th><th>dns max ms</th><th>dns fail %</th>
</tr></thead><tbody>
{% for t in findings.latency_analysis.targets %}
<tr>
  <td>{{ t.target }}</td>
  <td class="small">{{ t.hostname_resolved or '—' }}</td>
  <td>{{ t.samples }}</td>
  <td>{{ t.loss_rate_pct }}</td>
  <td>{{ t.rtt_avg_ms if t.rtt_avg_ms is not none else '—' }}</td>
  <td>{{ t.rtt_p95_ms if t.rtt_p95_ms is not none else '—' }}</td>
  <td>{{ t.rtt_max_ms if t.rtt_max_ms is not none else '—' }}</td>
  <td>{{ t.jitter_avg_ms if t.jitter_avg_ms is not none else '—' }}</td>
  <td>{{ t.resolve_avg_ms if t.resolve_avg_ms is not none else '—' }}</td>
  <td>{{ t.resolve_p95_ms if t.resolve_p95_ms is not none else '—' }}</td>
  <td>{{ t.resolve_max_ms if t.resolve_max_ms is not none else '—' }}</td>
  <td>{{ t.resolve_fail_rate_pct }}</td>
</tr>
{% endfor %}
</tbody></table>
{% if findings.latency_analysis.dns_findings %}
<h3>DNS findings</h3>
<ul>
{% for f in findings.latency_analysis.dns_findings %}
  <li><strong>{{ f.severity }}</strong> — {{ f.target }}: {{ f.detail }}</li>
{% endfor %}
</ul>
{% endif %}
{% else %}
<p class="small">No latency samples captured.</p>
{% endif %}
</div>

<h2>GPU metrics <span class="small">(Phase 3 — optional)</span></h2>
<div class="card">
{% if findings.gpu_analysis and findings.gpu_analysis.enabled %}
  <p class="small">{{ findings.gpu_analysis.samples }} GPU samples captured.</p>
  {% if findings.gpu_analysis.engines %}
  <h3>Engines</h3>
  <table><thead><tr>
    <th>engine</th><th>luid</th><th>avg %</th><th>peak %</th><th>samples</th>
  </tr></thead><tbody>
  {% for e in findings.gpu_analysis.engines %}
  <tr><td>{{ e.engine_type }}</td><td class="small">{{ e.luid }}</td>
      <td>{{ e.avg_pct }}</td><td>{{ e.peak_pct }}</td><td>{{ e.samples }}</td></tr>
  {% endfor %}
  </tbody></table>
  {% endif %}
  {% if findings.gpu_analysis.top_apps %}
  <h3>Top apps by GPU memory</h3>
  <table><thead><tr>
    <th>application</th><th>PIDs</th><th>dedicated peak MB</th>
    <th>dedicated avg MB</th><th>shared peak MB</th>
  </tr></thead><tbody>
  {% for a in findings.gpu_analysis.top_apps %}
  <tr><td>{{ a.display_name }} <span class="small">({{ a.app_key }})</span></td>
      <td>{{ a.pid_count }}</td>
      <td>{{ a.dedicated_peak_mb }}</td>
      <td>{{ a.dedicated_avg_mb }}</td>
      <td>{{ a.shared_peak_mb }}</td></tr>
  {% endfor %}
  </tbody></table>
  {% endif %}
  {% if findings.gpu_analysis.adapters %}
  <h3>Adapter telemetry (nvidia-smi)</h3>
  <table><thead><tr>
    <th>adapter</th><th>temp avg °C</th><th>temp peak °C</th>
    <th>power avg W</th><th>power peak W</th>
    <th>mem used avg MB</th><th>mem used peak MB</th>
    <th>util avg %</th><th>util peak %</th>
  </tr></thead><tbody>
  {% for a in findings.gpu_analysis.adapters %}
  <tr><td>{{ a.adapter }}</td>
      <td>{{ a.temp_avg_c if a.temp_avg_c is not none else '—' }}</td>
      <td>{{ a.temp_peak_c if a.temp_peak_c is not none else '—' }}</td>
      <td>{{ a.power_avg_w if a.power_avg_w is not none else '—' }}</td>
      <td>{{ a.power_peak_w if a.power_peak_w is not none else '—' }}</td>
      <td>{{ a.mem_used_avg_mb if a.mem_used_avg_mb is not none else '—' }}</td>
      <td>{{ a.mem_used_peak_mb if a.mem_used_peak_mb is not none else '—' }}</td>
      <td>{{ a.util_avg_pct if a.util_avg_pct is not none else '—' }}</td>
      <td>{{ a.util_peak_pct if a.util_peak_pct is not none else '—' }}</td></tr>
  {% endfor %}
  </tbody></table>
  {% endif %}
  {% if findings.gpu_analysis.findings %}
  <h3>GPU findings</h3>
  <ul>{% for f in findings.gpu_analysis.findings %}
    <li><strong>{{ f.severity }}</strong> — {{ f.detail }}</li>
  {% endfor %}</ul>
  {% endif %}
{% else %}
  <p class="small">GPU collection was not enabled for this run (use <code>--gpu</code> or <code>--phase3</code>).</p>
{% endif %}
</div>

<h2>Event-log correlation <span class="small">(Phase 3 — optional)</span></h2>
<div class="card">
{% if findings.event_correlation and findings.event_correlation.enabled %}
  <p class="small">{{ findings.event_correlation.count }} relevant events captured.
    {{ findings.event_correlation.correlated_to_slowdowns }} correlated to slowdown windows (±15 s).</p>
  {% if findings.event_correlation.by_bucket %}
  <p class="small">By category:
    {% for b, c in findings.event_correlation.by_bucket.items() %}
      <code>{{ b }}</code>: {{ c }}{% if not loop.last %}, {% endif %}
    {% endfor %}
  </p>
  {% endif %}
  {% if findings.event_correlation.top_events %}
  <h3>Top events</h3>
  <table><thead><tr>
    <th>rel_s</th><th>level</th><th>bucket</th><th>provider</th><th>id</th>
    <th>message</th><th>in slowdown?</th>
  </tr></thead><tbody>
  {% for e in findings.event_correlation.top_events %}
  <tr><td>{{ e.rel_seconds if e.rel_seconds is not none else '—' }}</td>
      <td>{{ e.level }}</td>
      <td>{{ e.bucket }}</td>
      <td class="small">{{ e.provider }}</td>
      <td>{{ e.id }}</td>
      <td class="small">{{ e.message }}</td>
      <td>{% if e.correlated_slowdowns %}yes ({{ e.correlated_slowdowns | length }}){% else %}—{% endif %}</td>
  </tr>
  {% endfor %}
  </tbody></table>
  {% endif %}
{% else %}
  <p class="small">Event-log collection was not enabled for this run (use <code>--event-logs</code> or <code>--phase3</code>).</p>
{% endif %}
</div>

<h2>ETW disk I/O <span class="small">(Phase 3 — optional, admin required)</span></h2>
<div class="card">
{% if findings.etw_disk and findings.etw_disk.enabled %}
  {% if findings.etw_disk.by_pid %}
  <p class="small">Per-process disk bytes attributed from kernel ETW trace.
    This is the only path for true per-process disk-I/O bytes on Windows — psutil cannot provide it.</p>
  <table><thead><tr>
    <th>pid</th><th>name</th><th>read MB</th><th>write MB</th>
    <th>read ops</th><th>write ops</th>
  </tr></thead><tbody>
  {% for p in findings.etw_disk.by_pid %}
  <tr><td>{{ p.pid }}</td><td>{{ p.name }}</td>
      <td>{{ '%.1f' | format(p.read_bytes / 1048576) }}</td>
      <td>{{ '%.1f' | format(p.write_bytes / 1048576) }}</td>
      <td>{{ p.read_ops }}</td><td>{{ p.write_ops }}</td></tr>
  {% endfor %}
  </tbody></table>
  {% if findings.etw_disk.totals %}
  <p class="small">Totals: {{ '%.1f' | format((findings.etw_disk.totals.read_bytes or 0) / 1048576) }} MB read,
    {{ '%.1f' | format((findings.etw_disk.totals.write_bytes or 0) / 1048576) }} MB written,
    {{ findings.etw_disk.totals.events_attributed }}/{{ findings.etw_disk.totals.events_total }} events attributed.</p>
  {% endif %}
  {% else %}
  <p class="small">ETW session ran but no attributable events were parsed
    ({{ findings.etw_disk.reason or 'unknown' }}).</p>
  {% endif %}
{% else %}
  <p class="small">ETW disk capture was not enabled for this run (use <code>--etw</code> or <code>--phase3</code>; admin required).</p>
{% endif %}
</div>

<h2>Bottleneck analysis</h2>
<div class="card">
  {% if findings.bottlenecks.reasons %}
    {% for dim, rs in findings.bottlenecks.reasons.items() %}
      <h3>{{ dim }} (score {{ findings.bottlenecks.scores[dim] }})</h3>
      <ul>{% for r in rs %}<li>{{ r }}</li>{% endfor %}</ul>
    {% endfor %}
  {% else %}
    <p class="small">No dimension accumulated enough evidence to be flagged as a bottleneck.</p>
  {% endif %}
</div>

<h2>Score explanation</h2>
<div class="card">
  {% for s in score_detail_rows %}
    <h3>{{ s.name }} — <span style="color:#2c7be5;">{{ s.val }}</span></h3>
    <pre style="background:#f3f5fa;padding:8px 12px;border-radius:4px;font-size:12px;white-space:pre-wrap;">{{ s.json }}</pre>
  {% endfor %}
  <p class="small">
    Overall is a weighted blend of the individual scores using weights
    {{ scores.weights | tojson }}.
  </p>
</div>

<h2>Test metadata</h2>
<div class="card">
  <div class="kvs">
    <div class="kv"><div class="k">Sampling interval</div><div class="v">{{ manifest.interval_seconds }} s</div></div>
    <div class="kv"><div class="k">Requested duration</div><div class="v">{{ manifest.duration_requested_seconds or 'manual stop' }}</div></div>
    <div class="kv"><div class="k">Latency targets</div><div class="v">{{ manifest.latency_targets | join(', ') }}</div></div>
    <div class="kv"><div class="k">Output root</div><div class="v"><code>{{ manifest.output_root }}</code></div></div>
  </div>
</div>

<h2>Recommendations</h2>
<div class="card">
  {% if recommendations %}
  <ul>{% for r in recommendations %}<li>{{ r }}</li>{% endfor %}</ul>
  <p class="small">These are observations based on collected evidence, not automated changes.</p>
  {% else %}
  <p class="small">No specific recommendations — the run did not trigger enough evidence to suggest changes.</p>
  {% endif %}
</div>

<div class="footer">
  Generated by SysSpecter · artifacts: <code>{{ manifest.run_dir }}</code>
</div>

</div></body></html>
"""


def _score_class(v: float) -> str:
    if v >= 80:
        return "good"
    if v >= 60:
        return "med"
    return "bad"


def _downsample(xs: list[float], ys: list[float], target: int = 500) -> tuple[list[float], list[float]]:
    n = len(xs)
    if n <= target:
        return xs, ys
    step = n / target
    out_x: list[float] = []
    out_y: list[float] = []
    i = 0.0
    while int(i) < n:
        idx = int(i)
        end = min(int(i + step), n)
        chunk = ys[idx:max(end, idx + 1)]
        out_x.append(xs[idx])
        out_y.append(max(chunk) if chunk else ys[idx])
        i += step
    return out_x, out_y


def _build_recommendations(findings: dict[str, Any], scores: dict[str, Any], static: dict[str, Any]) -> list[str]:
    recs: list[str] = []
    pb = findings.get("bottlenecks", {}).get("primary")
    if pb == "cpu":
        recs.append("Investigate top CPU offenders and whether a single-threaded workload is pinning a core.")
    if pb == "memory":
        recs.append("Evaluate RAM capacity vs workload and check leak candidates. Consider reducing background noise.")
    if pb == "disk":
        recs.append("Check disk type and SMART health; confirm whether paging or a scan is driving I/O.")
    if pb == "network":
        recs.append("Compare VPN-on vs VPN-off runs; verify latency targets reflect real usage geography.")
    if pb == "security":
        recs.append("Review Defender/third-party AV CPU cost, configured exclusions, and scan schedules.")
    sec_cpu = sum((o.get("cpu_pct_avg") or 0) for o in (findings.get("offenders", {}).get("security") or [])[:3])
    if sec_cpu > 15:
        recs.append(f"Security stack averaged {sec_cpu:.1f}% CPU across top 3 components — check exclusions.")
    leaks = findings.get("leaks", {})
    for kind, items in leaks.items():
        if any(it.get("confidence") in ("likely", "strong evidence") for it in items):
            names = ", ".join({it.get("process_name") for it in items if it.get("confidence") in ("likely", "strong evidence")})
            recs.append(f"Likely {kind} leak in {names} — reproduce offline and capture an ETW trace.")
    if static.get("security", {}).get("antivirus_products"):
        prods = static["security"]["antivirus_products"]
        if isinstance(prods, list) and len(prods) > 1:
            names = ", ".join(p.get("displayName", "?") for p in prods)
            recs.append(f"Multiple AV products detected ({names}) — overlapping scanners often waste CPU/IO.")
    bg = findings.get("offenders", {}).get("background_noise") or []
    if bg and sum((b.get("cpu_pct_avg") or 0) for b in bg[:3]) > 10:
        recs.append("Background apps (e.g. OneDrive, Teams, browsers) are contributing noticeable idle cost.")
    churn = findings.get("process_churn", {})
    if churn.get("total_process_starts", 0) > 200:
        recs.append(f"High process churn ({churn['total_process_starts']} starts) — investigate frequent spawners.")
    return recs


def _render(
    manifest: dict[str, Any],
    static: dict[str, Any],
    findings: dict[str, Any],
    scores: dict[str, Any],
    system_rows: list[dict[str, Any]],
    latency_rows: list[dict[str, Any]],
    process_rows: list[dict[str, Any]],
) -> str:
    env = Environment(loader=BaseLoader(), autoescape=select_autoescape())
    tpl = env.from_string(_TEMPLATE)

    xs = [float(r.get("rel_seconds") or 0.0) for r in system_rows]
    cpu_y = [float(r.get("cpu_total_pct") or 0.0) for r in system_rows]
    mem_y = [float(r.get("mem_percent") or 0.0) for r in system_rows]
    disk_y = [float(r.get("disk_active_pct_est") or 0.0) for r in system_rows]
    net_send_mb = [(float(r.get("net_sent_bytes_per_sec") or 0.0)) / 1024 / 1024 for r in system_rows]
    net_recv_mb = [(float(r.get("net_recv_bytes_per_sec") or 0.0)) / 1024 / 1024 for r in system_rows]

    xs_ds, cpu_ds = _downsample(xs, cpu_y)
    _, mem_ds = _downsample(xs, mem_y)
    _, disk_ds = _downsample(xs, disk_y)
    _, send_ds = _downsample(xs, net_send_mb)
    _, recv_ds = _downsample(xs, net_recv_mb)

    cpu_chart = line_chart(
        [{"name": "cpu total %", "xs": xs_ds, "ys": cpu_ds, "color": "#2c7be5"}],
        title="CPU total (%)", y_label="%", y_min=0, y_max=100,
    )
    mem_chart = line_chart(
        [{"name": "mem %", "xs": xs_ds, "ys": mem_ds, "color": "#722ed1"}],
        title="Memory used (%)", y_label="%", y_min=0, y_max=100,
    )
    disk_chart = line_chart(
        [{"name": "disk active %", "xs": xs_ds, "ys": disk_ds, "color": "#eb2f96"}],
        title="Disk active time (%)", y_label="%", y_min=0, y_max=100,
    )
    net_chart = line_chart(
        [
            {"name": "sent MB/s", "xs": xs_ds, "ys": send_ds, "color": "#52c41a"},
            {"name": "recv MB/s", "xs": xs_ds, "ys": recv_ds, "color": "#13c2c2"},
        ],
        title="Network throughput (MB/s)", y_label="MB/s",
    )

    core_count = 0
    for r in system_rows:
        c = r.get("cpu_per_core_pct") or []
        core_count = max(core_count, len(c))
    heatmap_svg = ""
    if core_count > 0 and system_rows:
        grid: list[list[float]] = [[] for _ in range(core_count)]
        for r in system_rows:
            c = r.get("cpu_per_core_pct") or []
            for i in range(core_count):
                grid[i].append(c[i] if i < len(c) else 0.0)
        if len(grid[0]) > 400:
            factor = len(grid[0]) // 400 + 1
            grid = [[max(row[j:j+factor]) for j in range(0, len(row), factor)] for row in grid]
        heatmap_svg = heatmap(grid, title="CPU per-core heatmap (%)", x_label="time →")

    latency_chart = None
    if latency_rows:
        by_target: dict[str, tuple[list[float], list[float]]] = {}
        for r in latency_rows:
            t = r.get("target") or "?"
            if r.get("avg_ms") is None:
                continue
            xs_t, ys_t = by_target.setdefault(t, ([], []))
            xs_t.append(float(r.get("rel_seconds") or 0.0))
            ys_t.append(float(r.get("avg_ms")))
        palette = ["#2c7be5", "#52c41a", "#eb2f96", "#faad14", "#722ed1", "#13c2c2"]
        series = []
        for i, (t, (xl, yl)) in enumerate(by_target.items()):
            series.append({"name": t, "xs": xl, "ys": yl, "color": palette[i % len(palette)]})
        if series:
            latency_chart = line_chart(series, title="Latency avg (ms)", y_label="ms")

    # Stacked disk read vs write (MB/s)
    disk_stack_chart = None
    if system_rows:
        disk_read = [(float(r.get("disk_read_bytes_per_sec") or 0.0)) / 1024 / 1024 for r in system_rows]
        disk_write = [(float(r.get("disk_write_bytes_per_sec") or 0.0)) / 1024 / 1024 for r in system_rows]
        xs_dd, read_ds = _downsample(xs, disk_read)
        _, write_ds = _downsample(xs, disk_write)
        if any(read_ds) or any(write_ds):
            disk_stack_chart = stacked_area_chart(
                xs_dd,
                [
                    {"name": "read MB/s", "ys": read_ds, "color": "#2c7be5"},
                    {"name": "write MB/s", "ys": write_ds, "color": "#eb2f96"},
                ],
                title="Disk throughput stacked (MB/s)", y_label="MB/s",
            )

    # Stacked network send vs recv (MB/s)
    net_stack_chart = None
    if system_rows:
        xs_dd2, send_ds2 = _downsample(xs, net_send_mb)
        _, recv_ds2 = _downsample(xs, net_recv_mb)
        if any(send_ds2) or any(recv_ds2):
            net_stack_chart = stacked_area_chart(
                xs_dd2,
                [
                    {"name": "sent MB/s", "ys": send_ds2, "color": "#52c41a"},
                    {"name": "recv MB/s", "ys": recv_ds2, "color": "#13c2c2"},
                ],
                title="Network throughput stacked (MB/s)", y_label="MB/s",
            )

    # Stacked top-N applications by concurrent CPU and RSS
    app_cpu_stack_chart = None
    app_rss_stack_chart = None
    if process_rows:
        from ..analyzer.grouping import _app_key, _display_name  # local import to avoid cycles
        ticks: dict[float, dict[str, tuple[float, float]]] = {}
        for r in process_rows:
            rel = r.get("rel_seconds")
            if rel is None:
                continue
            key = _app_key(r.get("name"))
            cpu = float(r.get("cpu_pct") or 0.0)
            rss = float(r.get("rss_bytes") or 0.0)
            tick = ticks.setdefault(float(rel), {})
            prev_cpu, prev_rss = tick.get(key, (0.0, 0.0))
            tick[key] = (prev_cpu + cpu, prev_rss + rss)
        app_totals_cpu: dict[str, float] = {}
        app_totals_rss: dict[str, float] = {}
        for tick in ticks.values():
            for key, (cpu, rss) in tick.items():
                app_totals_cpu[key] = app_totals_cpu.get(key, 0.0) + cpu
                app_totals_rss[key] = max(app_totals_rss.get(key, 0.0), rss)
        sorted_ticks = sorted(ticks.keys())
        palette = ["#2c7be5", "#cf1322", "#52c41a", "#faad14", "#722ed1",
                   "#eb2f96", "#13c2c2", "#fa541c"]

        def _stack_for(metric_idx: int, totals: dict[str, float], title: str,
                       y_label: str, divisor: float = 1.0) -> str | None:
            top_keys = [k for k, _ in sorted(totals.items(), key=lambda kv: kv[1],
                                              reverse=True) if k != "system idle process"][:6]
            if not top_keys:
                return None
            series_data: list[dict] = []
            for i, key in enumerate(top_keys):
                ys = []
                for t in sorted_ticks:
                    cpu_rss = ticks[t].get(key, (0.0, 0.0))
                    ys.append(cpu_rss[metric_idx] / divisor)
                series_data.append({
                    "name": _display_name(key),
                    "ys": ys,
                    "color": palette[i % len(palette)],
                })
            other_ys = []
            for t in sorted_ticks:
                rest = 0.0
                for key, v in ticks[t].items():
                    if key in top_keys or key == "system idle process":
                        continue
                    rest += v[metric_idx] / divisor
                other_ys.append(rest)
            if any(other_ys):
                series_data.append({"name": "other", "ys": other_ys, "color": "#8c8c8c"})
            xs_full = sorted_ticks
            if len(xs_full) > 400:
                factor = len(xs_full) // 400 + 1
                xs_ds2 = xs_full[::factor]
                for s in series_data:
                    s["ys"] = s["ys"][::factor]
                    # align lengths
                    s["ys"] = s["ys"][: len(xs_ds2)]
                xs_full = xs_ds2
            return stacked_area_chart(xs_full, series_data, title=title, y_label=y_label)

        app_cpu_stack_chart = _stack_for(0, app_totals_cpu,
                                         "Top apps concurrent CPU (%, stacked)", "%")
        app_rss_stack_chart = _stack_for(1, app_totals_rss,
                                         "Top apps concurrent RSS (MB, stacked)", "MB",
                                         divisor=1024 * 1024)

    top_processes_chart = None
    if process_rows:
        by_pid: dict[int, tuple[str, list[float], list[float], float]] = {}
        for r in process_rows:
            pid = r.get("pid")
            if pid is None:
                continue
            name = r.get("name") or "?"
            rel = float(r.get("rel_seconds") or 0.0)
            cpu = float(r.get("cpu_pct") or 0.0)
            entry = by_pid.setdefault(pid, (name, [], [], 0.0))
            entry[1].append(rel)
            entry[2].append(cpu)
            by_pid[pid] = (name, entry[1], entry[2], entry[3] + cpu)
        top = sorted(by_pid.items(), key=lambda kv: kv[1][3], reverse=True)[:6]
        palette = ["#2c7be5", "#cf1322", "#52c41a", "#faad14", "#722ed1", "#eb2f96"]
        series = []
        for i, (pid, (name, xs_p, ys_p, _tot)) in enumerate(top):
            xs_d, ys_d = _downsample(xs_p, ys_p, 300)
            series.append({"name": f"{name}({pid})", "xs": xs_d, "ys": ys_d,
                           "color": palette[i % len(palette)]})
        if series:
            top_processes_chart = line_chart(series, title="Top processes CPU (%)", y_label="%")

    score_cards = []
    for key, label in [
        ("overall", "Overall"),
        ("stability", "Stability"),
        ("efficiency", "Efficiency"),
        ("workload_suitability", "Workload"),
        ("security_overhead", "Security"),
        ("network_impact", "Network"),
        ("resource_hygiene", "Hygiene"),
    ]:
        v = scores.get(key)
        val = v["score"] if isinstance(v, dict) else v
        score_cards.append({
            "name": label,
            "val": f"{val:.0f}" if val is not None else "—",
            "cls": _score_class(val or 0),
            "bar_pct": max(0, min(100, int(val or 0))),
        })

    import json as _json
    score_detail_rows = []
    for key, label in [
        ("stability", "Stability"), ("efficiency", "Efficiency"),
        ("workload_suitability", "Workload suitability"), ("security_overhead", "Security overhead"),
        ("network_impact", "Network impact"), ("resource_hygiene", "Resource hygiene"),
    ]:
        v = scores.get(key)
        if isinstance(v, dict):
            score_detail_rows.append({
                "name": label, "val": v.get("score"),
                "json": _json.dumps(v.get("details") or {}, indent=2, default=str),
            })

    cpu_name = "—"
    cpus = (static.get("cpu") or {}).get("cpus") or []
    if cpus:
        cpu_name = (cpus[0] or {}).get("Name") or "—"
    ram_total = (static.get("memory") or {}).get("total_bytes") or 0
    ram_gb = round(ram_total / (1024 ** 3), 1) if ram_total else "—"

    defender_txt = "—"
    ds = (static.get("security") or {}).get("defender_status") or {}
    if isinstance(ds, dict):
        rt = ds.get("RealTimeProtectionEnabled")
        av = ds.get("AntivirusEnabled")
        ver = ds.get("AntivirusSignatureVersion")
        defender_txt = f"RT={rt} AV={av} sig={ver}"

    power_plan = (static.get("power") or {}).get("active_scheme_raw") or "—"
    if isinstance(power_plan, str):
        power_plan = power_plan.strip().splitlines()[0] if power_plan.strip() else "—"

    target = (manifest.get("target") or {})
    target_bits = []
    if target.get("name"):
        target_bits.append(f"name={target['name']}")
    if target.get("pid"):
        target_bits.append(f"pid={target['pid']}")
    if target.get("path"):
        target_bits.append(f"path={target['path']}")
    target_text = ", ".join(target_bits) or "—"

    offender_sections = [
        ("top_cpu", "Top CPU offenders"),
        ("top_rss", "Top RAM offenders"),
        ("top_io", "Top I/O offenders"),
        ("top_handles", "Top handle holders"),
        ("top_handle_growth", "Top handle growers"),
        ("top_threads", "Top thread holders"),
        ("top_thread_growth", "Top thread growers"),
        ("security", "Security-related offenders"),
        ("background_noise", "Background-noise contributors"),
    ]
    app_sections = [
        ("top_cpu", "Top CPU applications"),
        ("top_rss", "Top RAM applications"),
        ("top_io", "Top I/O applications"),
        ("top_handles", "Top handle-using applications"),
        ("top_threads", "Top thread-using applications"),
    ]

    recommendations = _build_recommendations(findings, scores, static)

    return tpl.render(
        css=_CSS,
        manifest=manifest,
        static=static,
        findings=findings,
        scores=scores,
        score_cards=score_cards,
        score_detail_rows=score_detail_rows,
        cpu_chart=cpu_chart,
        mem_chart=mem_chart,
        disk_chart=disk_chart,
        net_chart=net_chart,
        heatmap_svg=heatmap_svg,
        disk_stack_chart=disk_stack_chart,
        net_stack_chart=net_stack_chart,
        app_cpu_stack_chart=app_cpu_stack_chart,
        app_rss_stack_chart=app_rss_stack_chart,
        latency_chart=latency_chart,
        top_processes_chart=top_processes_chart,
        cpu_name=html.escape(cpu_name),
        ram_gb=ram_gb,
        defender_text=html.escape(str(defender_txt)),
        power_plan=html.escape(str(power_plan)),
        target_text=html.escape(target_text),
        offender_sections=offender_sections,
        app_sections=app_sections,
        recommendations=recommendations,
    )


def build_report(run_dir: str) -> str:
    logger = get_logger("reporter", os.path.join(run_dir, "logs", "reporter.log"))
    logger.info("building HTML report for %s", run_dir)

    findings_path = os.path.join(run_dir, "findings.json")
    scores_path = os.path.join(run_dir, "scores.json")
    if not (os.path.exists(findings_path) and os.path.exists(scores_path)):
        logger.info("findings/scores missing; running analyzer first")
        analyze_run(run_dir)

    rd = load_run(run_dir)
    findings = load_json(findings_path)
    scores = load_json(scores_path)

    html_txt = _render(rd.manifest, rd.static, findings, scores,
                       rd.system_rows, rd.latency_rows, rd.process_rows)

    out_path = os.path.join(run_dir, "final_report.html")
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(html_txt)
    os.replace(tmp, out_path)

    md = generate_markdown_summary(rd.manifest, rd.static, findings, scores)
    md_path = os.path.join(run_dir, "final_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)

    logger.info("report ready: %s", out_path)
    return out_path


def regenerate_report(run_dir: str) -> str:
    analyze_run(run_dir)
    return build_report(run_dir)
