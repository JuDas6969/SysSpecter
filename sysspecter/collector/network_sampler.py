"""Per-adapter network sampling and connection count."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import psutil

_last_per_nic: dict[str, Any] = {}
_last_mono: float | None = None


@dataclass
class NetworkSample:
    timestamp: float
    rel_seconds: float
    adapter: str
    bytes_sent_per_sec: float
    bytes_recv_per_sec: float
    packets_sent_per_sec: float
    packets_recv_per_sec: float
    errin_per_sec: float
    errout_per_sec: float
    dropin_per_sec: float
    dropout_per_sec: float
    is_up: bool
    speed_mbps: int
    connections_established: int


def collect_network_sample(started_mono: float) -> list[NetworkSample]:
    global _last_per_nic, _last_mono

    now_wall = time.time()
    now_mono = time.monotonic()
    rel = now_mono - started_mono

    try:
        per_nic = psutil.net_io_counters(pernic=True)
    except Exception:
        per_nic = {}
    try:
        stats = psutil.net_if_stats()
    except Exception:
        stats = {}

    try:
        conns = psutil.net_connections(kind="tcp")
        established_count = sum(1 for c in conns if c.status == psutil.CONN_ESTABLISHED)
    except (psutil.AccessDenied, PermissionError, Exception):
        established_count = -1

    dt = max(now_mono - _last_mono, 1e-3) if _last_mono else 1.0

    out: list[NetworkSample] = []
    for name, io in per_nic.items():
        st = stats.get(name)
        prev = _last_per_nic.get(name)
        if prev is None:
            bs = br = ps = pr = ei = eo = di = do = 0.0
        else:
            bs = max(0.0, (io.bytes_sent - prev.bytes_sent) / dt)
            br = max(0.0, (io.bytes_recv - prev.bytes_recv) / dt)
            ps = max(0.0, (io.packets_sent - prev.packets_sent) / dt)
            pr = max(0.0, (io.packets_recv - prev.packets_recv) / dt)
            ei = max(0.0, (io.errin - prev.errin) / dt)
            eo = max(0.0, (io.errout - prev.errout) / dt)
            di = max(0.0, (io.dropin - prev.dropin) / dt)
            do = max(0.0, (io.dropout - prev.dropout) / dt)

        out.append(NetworkSample(
            timestamp=now_wall,
            rel_seconds=round(rel, 3),
            adapter=name,
            bytes_sent_per_sec=round(bs, 1),
            bytes_recv_per_sec=round(br, 1),
            packets_sent_per_sec=round(ps, 2),
            packets_recv_per_sec=round(pr, 2),
            errin_per_sec=round(ei, 2),
            errout_per_sec=round(eo, 2),
            dropin_per_sec=round(di, 2),
            dropout_per_sec=round(do, 2),
            is_up=bool(st.isup) if st else False,
            speed_mbps=int(st.speed) if st else 0,
            connections_established=established_count,
        ))

    _last_per_nic = per_nic
    _last_mono = now_mono
    return out


def sample_to_dict(s: NetworkSample) -> dict[str, Any]:
    return {
        "timestamp": s.timestamp,
        "rel_seconds": s.rel_seconds,
        "adapter": s.adapter,
        "bytes_sent_per_sec": s.bytes_sent_per_sec,
        "bytes_recv_per_sec": s.bytes_recv_per_sec,
        "packets_sent_per_sec": s.packets_sent_per_sec,
        "packets_recv_per_sec": s.packets_recv_per_sec,
        "errin_per_sec": s.errin_per_sec,
        "errout_per_sec": s.errout_per_sec,
        "dropin_per_sec": s.dropin_per_sec,
        "dropout_per_sec": s.dropout_per_sec,
        "is_up": 1 if s.is_up else 0,
        "speed_mbps": s.speed_mbps,
        "connections_established": s.connections_established,
    }
