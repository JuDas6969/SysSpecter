"""Phase 2: per-target latency + DNS resolution analysis.

Takes the sampled `timeline_latency.csv` rows and produces per-target aggregates
so the report can answer: "how slow is DNS for google.com?", "is packet loss
isolated to one target?", "is jitter abnormal?".

DNS timing is measured by the collector via socket.gethostbyaddr (for IP
literals) or socket.getaddrinfo (for hostnames). This module just summarizes."""

from __future__ import annotations

from typing import Any


def _percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    xs = sorted(values)
    k = (len(xs) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    frac = k - lo
    return xs[lo] + (xs[hi] - xs[lo]) * frac


def _avg(values: list[float]) -> float | None:
    if not values:
        return None
    return sum(values) / len(values)


def analyze_latency(latency_rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not latency_rows:
        return {"samples": 0, "targets": [], "dns_findings": []}

    by_target: dict[str, list[dict[str, Any]]] = {}
    for r in latency_rows:
        t = r.get("target") or ""
        if not t:
            continue
        by_target.setdefault(t, []).append(r)

    targets: list[dict[str, Any]] = []
    dns_findings: list[dict[str, Any]] = []

    for target, rows in by_target.items():
        rtt_avgs = [r["avg_ms"] for r in rows if r.get("avg_ms") is not None]
        rtt_maxs = [r["max_ms"] for r in rows if r.get("max_ms") is not None]
        jitters = [r["jitter_ms"] for r in rows if r.get("jitter_ms") is not None]
        losses = [r["loss_pct"] for r in rows if r.get("loss_pct") is not None]
        resolves = [r["resolve_ms"] for r in rows if r.get("resolve_ms") is not None]

        n = len(rows)
        lost = sum(1 for r in rows if (r.get("loss_pct") or 0) >= 100.0)
        resolve_fails = sum(
            1 for r in rows
            if r.get("resolve_ms") is None or r.get("resolve_ms") == ""
        )

        hostname_resolved = ""
        for r in rows:
            hn = r.get("hostname_resolved")
            if hn:
                hostname_resolved = hn
                break

        resolve_avg = _avg(resolves)
        resolve_p95 = _percentile(resolves, 0.95)
        resolve_max = max(resolves) if resolves else None

        entry = {
            "target": target,
            "hostname_resolved": hostname_resolved,
            "samples": n,
            "fully_lost_samples": lost,
            "loss_rate_pct": round(100 * lost / n, 1) if n else 0.0,
            "rtt_avg_ms": round(_avg(rtt_avgs), 2) if rtt_avgs else None,
            "rtt_p95_ms": round(_percentile(rtt_avgs, 0.95), 2) if rtt_avgs else None,
            "rtt_max_ms": round(max(rtt_maxs), 2) if rtt_maxs else None,
            "jitter_avg_ms": round(_avg(jitters), 2) if jitters else None,
            "avg_loss_pct": round(_avg(losses), 1) if losses else 0.0,
            "resolve_avg_ms": round(resolve_avg, 2) if resolve_avg is not None else None,
            "resolve_p95_ms": round(resolve_p95, 2) if resolve_p95 is not None else None,
            "resolve_max_ms": round(resolve_max, 2) if resolve_max is not None else None,
            "resolve_fail_samples": resolve_fails,
            "resolve_fail_rate_pct": round(100 * resolve_fails / n, 1) if n else 0.0,
        }
        targets.append(entry)

        if resolve_avg is not None and resolve_avg >= 100.0:
            dns_findings.append({
                "target": target,
                "severity": "high" if resolve_avg >= 300.0 else "medium",
                "kind": "slow_dns",
                "detail": f"Average DNS resolve time {resolve_avg:.0f} ms "
                          f"(p95 {resolve_p95:.0f} ms)" if resolve_p95 else
                          f"Average DNS resolve time {resolve_avg:.0f} ms",
            })
        if n > 0 and resolve_fails / n >= 0.25:
            dns_findings.append({
                "target": target,
                "severity": "high",
                "kind": "dns_failures",
                "detail": f"{resolve_fails}/{n} DNS lookups failed "
                          f"({round(100 * resolve_fails / n, 1)}%)",
            })

    targets.sort(key=lambda e: (e["loss_rate_pct"], e["rtt_avg_ms"] or 0), reverse=True)

    return {
        "samples": len(latency_rows),
        "targets": targets,
        "dns_findings": dns_findings,
    }
