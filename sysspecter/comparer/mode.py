"""Auto-detect comparison mode from the input runs' hostnames.

- All runs share the same hostname -> "before_after" (same machine over time)
- Exactly two distinct hostnames among the runs -> "pair_diagnosis"
- Three or more distinct hostnames -> "fleet"
"""

from __future__ import annotations

from typing import Any, Literal

Mode = Literal["before_after", "pair_diagnosis", "fleet"]


def _hostnames(runs: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for r in runs:
        m = r.get("manifest") or {}
        h = m.get("hostname")
        if isinstance(h, str) and h:
            out.append(h.strip().upper())
    return out


def detect_mode(runs: list[dict[str, Any]]) -> Mode:
    hosts = _hostnames(runs)
    distinct = set(hosts)
    if len(runs) >= 2 and len(distinct) == 1:
        return "before_after"
    if len(distinct) == 2:
        return "pair_diagnosis"
    return "fleet"


def mode_label(mode: Mode) -> str:
    return {
        "before_after": "Before/after (same host)",
        "pair_diagnosis": "Pair diagnosis (A vs B)",
        "fleet": "Fleet overview",
    }.get(mode, mode)
