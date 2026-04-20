"""Phase 2: per-process / per-app network attribution.

Reads `timeline_connections.csv` (sampled on the expensive-tier interval) and
reports which processes/applications own which connections. We cannot get
per-process byte counters via psutil on Windows, so attribution is
connection-count / unique-remote based — still a strong signal for
"who is talking to the network" questions."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .grouping import _app_key, _display_name


def _strip_port(addr: str) -> str:
    if not addr:
        return ""
    # IPv6 uses [::1]:port — keep brackets stripped
    if addr.startswith("["):
        end = addr.find("]")
        return addr[1:end] if end > 0 else addr
    if ":" in addr:
        return addr.rsplit(":", 1)[0]
    return addr


def _port_of(addr: str) -> str:
    if not addr or ":" not in addr:
        return ""
    return addr.rsplit(":", 1)[1]


def attribute_connections(
    connection_rows: list[dict[str, Any]], top_n: int = 10
) -> dict[str, Any]:
    if not connection_rows:
        return {"by_pid": [], "by_app": [], "samples": 0, "note": "no connection snapshots"}

    # one connection row = one (ts, pid, laddr, raddr, status, type)
    # snapshot count = distinct timestamps
    snapshots = {r.get("rel_seconds") for r in connection_rows}
    n_snapshots = len(snapshots)

    # Per-PID aggregates
    by_pid: dict[int, dict[str, Any]] = {}
    by_app: dict[str, dict[str, Any]] = {}

    # Collect remote (host, port) for top-remotes ranking
    pid_remotes: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    app_remotes: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for r in connection_rows:
        try:
            pid = int(r.get("pid") or 0)
        except (TypeError, ValueError):
            pid = 0
        if pid <= 0:
            continue
        name = r.get("name") or "?"
        app_key = _app_key(name)
        raddr = r.get("raddr") or ""
        status = r.get("status") or ""
        kind = r.get("type") or ""
        remote_host = _strip_port(raddr)

        pid_entry = by_pid.setdefault(pid, {
            "pid": pid, "name": name, "app_key": app_key,
            "display_name": _display_name(app_key),
            "snapshots_seen": set(),
            "total_conn_samples": 0,
            "tcp_samples": 0, "udp_samples": 0,
            "status_counts": defaultdict(int),
            "unique_remotes": set(),
            "unique_laddrs": set(),
        })
        pid_entry["snapshots_seen"].add(r.get("rel_seconds"))
        pid_entry["total_conn_samples"] += 1
        if kind == "tcp":
            pid_entry["tcp_samples"] += 1
        elif kind == "udp":
            pid_entry["udp_samples"] += 1
        if status:
            pid_entry["status_counts"][status] += 1
        if remote_host and remote_host not in ("0.0.0.0", "::", "127.0.0.1", "::1", ""):
            pid_entry["unique_remotes"].add(remote_host)
            pid_remotes[pid][remote_host] += 1
            app_remotes[app_key][remote_host] += 1
        if r.get("laddr"):
            pid_entry["unique_laddrs"].add(r["laddr"])

        app_entry = by_app.setdefault(app_key, {
            "app_key": app_key,
            "display_name": _display_name(app_key),
            "pids": set(),
            "snapshots_seen": set(),
            "total_conn_samples": 0,
            "tcp_samples": 0, "udp_samples": 0,
            "status_counts": defaultdict(int),
            "unique_remotes": set(),
        })
        app_entry["pids"].add(pid)
        app_entry["snapshots_seen"].add(r.get("rel_seconds"))
        app_entry["total_conn_samples"] += 1
        if kind == "tcp":
            app_entry["tcp_samples"] += 1
        elif kind == "udp":
            app_entry["udp_samples"] += 1
        if status:
            app_entry["status_counts"][status] += 1
        if remote_host and remote_host not in ("0.0.0.0", "::", "127.0.0.1", "::1", ""):
            app_entry["unique_remotes"].add(remote_host)

    def _finalize_pid(e: dict[str, Any]) -> dict[str, Any]:
        snaps = max(len(e["snapshots_seen"]), 1)
        top_remotes = sorted(pid_remotes.get(e["pid"], {}).items(),
                             key=lambda kv: kv[1], reverse=True)[:5]
        return {
            "pid": e["pid"], "name": e["name"],
            "app_key": e["app_key"], "display_name": e["display_name"],
            "snapshots_with_conns": snaps,
            "avg_concurrent_conns": round(e["total_conn_samples"] / snaps, 1),
            "tcp_share_pct": round(100 * e["tcp_samples"] / max(e["total_conn_samples"], 1), 1),
            "udp_share_pct": round(100 * e["udp_samples"] / max(e["total_conn_samples"], 1), 1),
            "unique_remote_count": len(e["unique_remotes"]),
            "unique_remotes": sorted(e["unique_remotes"])[:25],
            "top_remotes": [{"host": h, "samples": c} for h, c in top_remotes],
            "status_counts": dict(e["status_counts"]),
        }

    def _finalize_app(e: dict[str, Any]) -> dict[str, Any]:
        snaps = max(len(e["snapshots_seen"]), 1)
        top_remotes = sorted(app_remotes.get(e["app_key"], {}).items(),
                             key=lambda kv: kv[1], reverse=True)[:10]
        return {
            "app_key": e["app_key"], "display_name": e["display_name"],
            "pid_count": len(e["pids"]),
            "snapshots_with_conns": snaps,
            "avg_concurrent_conns": round(e["total_conn_samples"] / snaps, 1),
            "tcp_share_pct": round(100 * e["tcp_samples"] / max(e["total_conn_samples"], 1), 1),
            "udp_share_pct": round(100 * e["udp_samples"] / max(e["total_conn_samples"], 1), 1),
            "unique_remote_count": len(e["unique_remotes"]),
            "top_remotes": [{"host": h, "samples": c} for h, c in top_remotes],
            "status_counts": dict(e["status_counts"]),
        }

    pid_rows = [_finalize_pid(e) for e in by_pid.values()]
    pid_rows.sort(key=lambda e: (e["avg_concurrent_conns"], e["unique_remote_count"]), reverse=True)

    app_rows = [_finalize_app(e) for e in by_app.values()]
    app_rows.sort(key=lambda e: (e["avg_concurrent_conns"], e["unique_remote_count"]), reverse=True)

    return {
        "samples": n_snapshots,
        "by_pid": pid_rows[:top_n],
        "by_app": app_rows[:top_n],
    }
