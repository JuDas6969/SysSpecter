"""Markdown summary report."""

from __future__ import annotations

from typing import Any


def generate_markdown_summary(
    manifest: dict[str, Any],
    static: dict[str, Any],
    findings: dict[str, Any],
    scores: dict[str, Any],
) -> str:
    lines: list[str] = []
    lines.append(f"# SysSpecter run — {manifest.get('hostname','?')} — {manifest.get('run_id','')}")
    lines.append("_See everything. Find the cause._")
    lines.append("")
    lines.append(f"- Mode: **{manifest.get('mode')}**  ·  Duration: {manifest.get('duration_actual_seconds')}s"
                 f"  ·  Started: {manifest.get('started_at')}  ·  Ended: {manifest.get('ended_at')}")
    if manifest.get("tags"):
        lines.append(f"- Tags: {', '.join(manifest['tags'])}")
    lines.append(f"- Stop reason: {manifest.get('stop_reason')}  ·  Privilege: {manifest.get('privilege_level')}")
    lines.append("")

    summary = findings.get("summary", {})
    lines.append("## Verdict")
    lines.append("")
    lines.append(f"> {summary.get('verdict','(no verdict)')}")
    lines.append("")

    lines.append("## Scores")
    lines.append("")
    lines.append("| Score | Value |")
    lines.append("|---|---|")
    for key in ("overall", "stability", "efficiency", "workload_suitability",
                "security_overhead", "network_impact", "resource_hygiene"):
        v = scores.get(key)
        if isinstance(v, dict):
            v = v.get("score")
        lines.append(f"| {key} | {v} |")
    lines.append(f"| primary bottleneck | {scores.get('primary_bottleneck')} |")
    lines.append(f"| secondary bottlenecks | {', '.join(scores.get('secondary_bottlenecks') or []) or '—'} |")
    lines.append(f"| confidence | {scores.get('confidence')} |")
    lines.append("")

    anoms = findings.get("anomalies") or []
    if anoms:
        lines.append(f"## Anomalies ({len(anoms)})")
        lines.append("")
        for a in anoms[:20]:
            lines.append(f"- **[{a.get('severity','?')}] {a.get('kind')}** — {a.get('description','')}")
        lines.append("")

    slowdowns = findings.get("slowdowns") or []
    if slowdowns:
        lines.append(f"## Slowdown windows ({len(slowdowns)})")
        lines.append("")
        for s in slowdowns[:20]:
            lines.append(f"- **s={s.get('start_rel'):.0f}–{s.get('end_rel'):.0f}** ({s.get('confidence')}): "
                         f"{s.get('description')}")
        lines.append("")

    leaks = findings.get("leaks") or {}
    total_leaks = sum(len(v) for v in leaks.values())
    if total_leaks:
        lines.append(f"## Leak candidates ({total_leaks})")
        lines.append("")
        for kind, items in leaks.items():
            if not items:
                continue
            lines.append(f"### {kind}")
            for it in items[:10]:
                lines.append(f"- **[{it.get('confidence')}]** {it.get('description')}")
            lines.append("")

    off = findings.get("offenders") or {}
    lines.append("## Top offenders")
    lines.append("")
    for label in ("top_cpu", "top_rss", "top_handles", "top_io", "security", "background_noise"):
        items = off.get(label) or []
        if not items:
            continue
        lines.append(f"### {label}")
        lines.append("")
        lines.append("| pid | name | cpu avg | cpu max | rss MB | handles | threads | io avg |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for i in items[:8]:
            io = (i.get("io_read_bps_avg") or 0) + (i.get("io_write_bps_avg") or 0)
            lines.append(
                f"| {i.get('pid')} | {i.get('name')} | {i.get('cpu_pct_avg')} | {i.get('cpu_pct_max')} "
                f"| {i.get('rss_mb_max')} | {i.get('num_handles_max')} | {i.get('num_threads_max')} "
                f"| {io:.0f} |"
            )
        lines.append("")

    bottlenecks = findings.get("bottlenecks") or {}
    if bottlenecks.get("reasons"):
        lines.append("## Bottleneck reasoning")
        lines.append("")
        for dim, rs in bottlenecks["reasons"].items():
            lines.append(f"### {dim}")
            for r in rs:
                lines.append(f"- {r}")
            lines.append("")

    return "\n".join(lines)
