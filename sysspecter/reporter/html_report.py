"""HTML report generator — fully offline, inline SVG charts, no CDN.

The CSS and Jinja template live as sibling files under `styles/` and
`templates/` so they are editable without touching Python. `_CSS` and
`_TEMPLATE` are lazily loaded from those files on first render.
"""

from __future__ import annotations

import html
import os
import sys
from functools import lru_cache
from typing import Any

from jinja2 import BaseLoader, Environment, select_autoescape

from ..analyzer.loader import load_run
from ..analyzer.pipeline import analyze_run
from ..logging_setup import get_logger
from ..manifest import repair_manifest_if_aborted
from .json_export import load_json
from .markdown_report import generate_markdown_summary
from .svg_charts import heatmap, line_chart, stacked_area_chart


def _resource_path(*parts: str) -> str:
    """Locate a bundled resource next to the module.

    In a PyInstaller-frozen EXE the files live under `sys._MEIPASS`; in a
    dev checkout they sit next to this file. Prefer the dev layout, fall
    back to the frozen layout.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(here, *parts)
    if os.path.exists(candidate):
        return candidate
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return os.path.join(meipass, "sysspecter", "reporter", *parts)
    return candidate


@lru_cache(maxsize=1)
def _load_css() -> str:
    with open(_resource_path("styles", "report.css"), encoding="utf-8") as f:
        return f.read()


@lru_cache(maxsize=1)
def _load_template() -> str:
    with open(_resource_path("templates", "final_report.html.j2"),
              encoding="utf-8") as f:
        return f.read()





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
    tpl = env.from_string(_load_template())

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

    # Banners: admin-missing, collector-degraded, low-confidence
    banner_admin = ""
    if (manifest.get("privilege_level") or "user") != "admin":
        deg = []
        phase3 = manifest.get("phase3") or {}
        if phase3.get("etw_disk"):
            deg.append("per-process disk I/O (ETW)")
        deg.append("handle counts on protected processes")
        deg.append("some WMI classes")
        banner_admin = ", ".join(deg)
    deg_map = manifest.get("collector_degraded") or {}
    banner_degraded = ""
    if isinstance(deg_map, dict) and deg_map:
        parts = [f"{k}: {v}" for k, v in deg_map.items()]
        banner_degraded = "; ".join(parts)
    banner_low_confidence = ""
    summary = (findings.get("summary") or {}) if isinstance(findings, dict) else {}
    if summary.get("insufficient_data"):
        banner_low_confidence = summary.get("verdict") or "Not enough samples for confident analysis."
    elif len(system_rows) < 60 and len(system_rows) > 0:
        banner_low_confidence = (
            f"Only {len(system_rows)} system samples captured — findings have low statistical weight."
        )

    return tpl.render(
        css=_load_css(),
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
        banner_admin=banner_admin,
        banner_degraded=banner_degraded,
        banner_low_confidence=banner_low_confidence,
    )


def build_report(
    run_dir: str,
    max_rel_seconds: float | None = None,
    min_rel_seconds: float | None = None,
    output_dir: str | None = None,
) -> str:
    out_dir = output_dir or run_dir
    os.makedirs(os.path.join(out_dir, "logs"), exist_ok=True)
    logger = get_logger("reporter", os.path.join(out_dir, "logs", "reporter.log"))
    logger.info("building HTML report for %s -> %s", run_dir, out_dir)

    findings_path = os.path.join(out_dir, "findings.json")
    scores_path = os.path.join(out_dir, "scores.json")
    windowed = min_rel_seconds is not None or max_rel_seconds is not None
    if windowed or not (os.path.exists(findings_path) and os.path.exists(scores_path)):
        logger.info("running analyzer%s",
                    " (window)" if windowed else "")
        analyze_run(run_dir, max_rel_seconds=max_rel_seconds,
                    min_rel_seconds=min_rel_seconds, output_dir=out_dir)

    rd = load_run(run_dir, max_rel_seconds=max_rel_seconds, min_rel_seconds=min_rel_seconds)
    findings = load_json(findings_path)
    scores = load_json(scores_path)

    html_txt = _render(rd.manifest, rd.static, findings, scores,
                       rd.system_rows, rd.latency_rows, rd.process_rows)

    out_path = os.path.join(out_dir, "final_report.html")
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(html_txt)
    os.replace(tmp, out_path)

    md = generate_markdown_summary(rd.manifest, rd.static, findings, scores)
    md_path = os.path.join(out_dir, "final_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)

    logger.info("report ready: %s", out_path)
    return out_path


def regenerate_report(run_dir: str, max_rel_seconds: float | None = None) -> str:
    logger = get_logger("reporter", os.path.join(run_dir, "logs", "reporter.log"))
    if repair_manifest_if_aborted(run_dir):
        logger.info("manifest was incomplete — repaired with stop_reason=aborted")
        print("  Manifest unvollständig — repariert (stop_reason=aborted).", flush=True)
    if max_rel_seconds is not None:
        print(f"  Trimme Report auf die ersten {max_rel_seconds:.0f}s.", flush=True)
    analyze_run(run_dir, max_rel_seconds=max_rel_seconds)
    return build_report(run_dir, max_rel_seconds=max_rel_seconds)
