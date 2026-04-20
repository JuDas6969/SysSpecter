"""Phase 3: correlate Windows event-log entries with slowdown windows.

Given the event_log.json produced by the eventlog collector and the slowdown
windows produced by the slowdown detector, mark which events fall inside or
near a slowdown window (±15 s). Also classify events by provider into useful
buckets (power, disk, storage, service, WER, Defender)."""

from __future__ import annotations

from typing import Any


_PROVIDER_BUCKETS: dict[str, str] = {
    "Microsoft-Windows-Kernel-Power": "power",
    "Microsoft-Windows-Power-Troubleshooter": "power",
    "disk": "storage",
    "Disk": "storage",
    "Ntfs": "storage",
    "volmgr": "storage",
    "volsnap": "storage",
    "Microsoft-Windows-Ntfs": "storage",
    "Service Control Manager": "service",
    "DistributedCOM": "com",
    "Application Error": "app_crash",
    "Windows Error Reporting": "app_crash",
    ".NET Runtime": "app_crash",
    "Microsoft-Windows-Windows Defender": "defender",
    "Microsoft-Windows-WindowsUpdateClient": "update",
    "Microsoft-Windows-WMI-Activity": "wmi",
    "Microsoft-Windows-DNS-Client": "dns",
}


def _bucket_for(provider: str | None) -> str:
    if not provider:
        return "other"
    return _PROVIDER_BUCKETS.get(provider, "other")


def correlate_events(
    event_log: dict[str, Any],
    slowdowns: list[dict[str, Any]],
    window_pad_seconds: float = 15.0,
) -> dict[str, Any]:
    if not event_log or not event_log.get("events"):
        return {"enabled": False, "count": 0}

    events: list[dict[str, Any]] = list(event_log["events"])
    for e in events:
        e["bucket"] = _bucket_for(e.get("provider"))

    # Build windowed intervals
    intervals = []
    for s in slowdowns:
        try:
            rs = float(s.get("start_rel") or 0.0)
            re = float(s.get("end_rel") or rs)
        except (TypeError, ValueError):
            continue
        intervals.append((max(0.0, rs - window_pad_seconds),
                          re + window_pad_seconds, s))

    for e in events:
        rel = e.get("rel_seconds")
        matches = []
        if rel is not None and intervals:
            for lo, hi, s in intervals:
                if lo <= rel <= hi:
                    matches.append({
                        "start_rel": s.get("start_rel"),
                        "end_rel": s.get("end_rel"),
                        "kind": (s.get("reason_tags") or ["slowdown"])[0],
                    })
        e["correlated_slowdowns"] = matches

    # Counts by bucket + severity
    by_bucket: dict[str, int] = {}
    correlated = 0
    for e in events:
        by_bucket[e["bucket"]] = by_bucket.get(e["bucket"], 0) + 1
        if e.get("correlated_slowdowns"):
            correlated += 1

    # Top events: sort by numeric level code (1=Critical, 2=Error, 3=Warning)
    # which is locale-independent, then whether it correlated to a slowdown.
    def _key(e: dict[str, Any]):
        lc = e.get("level_code")
        try:
            lvl = int(lc) if lc is not None else 9
        except (TypeError, ValueError):
            lvl = 9
        return (
            lvl,
            0 if e.get("correlated_slowdowns") else 1,
            e.get("bucket") or "",
            -(e.get("rel_seconds") or 0),
        )

    ranked = sorted(events, key=_key)
    return {
        "enabled": True,
        "count": len(events),
        "correlated_to_slowdowns": correlated,
        "by_bucket": by_bucket,
        "top_events": ranked[:15],
        "events": events,
    }
