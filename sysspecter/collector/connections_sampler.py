"""Phase 2: per-process TCP/UDP connection snapshot.

psutil exposes the connection table with `pid` for each socket. This sampler
takes a snapshot on the expensive-tier interval (every 30s by default) and
emits one CSV row per (pid, connection). The analyzer aggregates these into
"which app holds which connections" without needing ETW.

Byte-level per-process attribution is not available via psutil on Windows
(Phase 3 territory — needs ETW Kernel-Network provider). Connection-count
attribution is still a strong signal for "which process is talking to the
internet" questions."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import psutil


@dataclass
class ConnectionSample:
    timestamp: float
    rel_seconds: float
    pid: int
    name: str
    laddr: str
    raddr: str
    status: str
    type: str  # tcp or udp


def _fmt_addr(addr: Any) -> str:
    if not addr:
        return ""
    try:
        if isinstance(addr, tuple):
            return f"{addr[0]}:{addr[1]}" if len(addr) >= 2 else str(addr[0])
        # psutil Addr namedtuple
        ip = getattr(addr, "ip", None)
        port = getattr(addr, "port", None)
        if ip is not None and port is not None:
            return f"{ip}:{port}"
        if ip is not None:
            return str(ip)
    except Exception:
        pass
    return str(addr)


def _resolve_names(pids: set[int]) -> dict[int, str]:
    out: dict[int, str] = {}
    for pid in pids:
        if pid <= 0:
            continue
        try:
            out[pid] = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
            out[pid] = "?"
    return out


def collect_connection_snapshot(started_mono: float) -> list[ConnectionSample]:
    now_wall = time.time()
    rel = time.monotonic() - started_mono

    out: list[ConnectionSample] = []
    for kind, label in (("tcp", "tcp"), ("udp", "udp")):
        try:
            conns = psutil.net_connections(kind=kind)
        except (psutil.AccessDenied, PermissionError):
            continue
        except Exception:
            continue
        pids = {c.pid for c in conns if c.pid}
        names = _resolve_names(pids)
        for c in conns:
            if not c.pid:
                continue
            out.append(ConnectionSample(
                timestamp=now_wall,
                rel_seconds=round(rel, 3),
                pid=int(c.pid),
                name=names.get(c.pid, "?"),
                laddr=_fmt_addr(c.laddr),
                raddr=_fmt_addr(c.raddr),
                status=str(c.status) if c.status else "",
                type=label,
            ))
    return out


def sample_to_dict(s: ConnectionSample) -> dict[str, Any]:
    return {
        "timestamp": s.timestamp,
        "rel_seconds": s.rel_seconds,
        "pid": s.pid,
        "name": s.name,
        "laddr": s.laddr,
        "raddr": s.raddr,
        "status": s.status,
        "type": s.type,
    }
