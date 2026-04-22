"""Parse human-friendly duration strings into seconds.

Accepts inputs such as:
    "1800"          -> 1800 s
    "30"            -> 30 s (but prefers whatever unit the spinner picked)
    "30 min"        -> 1800
    "1.5h"          -> 5400
    "1,5 min"       -> 90      (German decimal comma)
    "2 hrs"         -> 7200
    "1 day"         -> 86400
    "45s"           -> 45
    "2h 30min"      -> 9000
    "90s"           -> 90

Used by the Monitor tab's duration field so the user can type free text
instead of doing unit arithmetic in their head.
"""

from __future__ import annotations

import re


_UNIT_SECONDS = {
    # seconds
    "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
    "sekunde": 1, "sekunden": 1,
    # minutes
    "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
    "minuten": 60,
    # hours
    "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600,
    "stunde": 3600, "stunden": 3600, "std": 3600,
    # days
    "d": 86400, "day": 86400, "days": 86400, "tag": 86400, "tage": 86400,
}

_TOKEN_RE = re.compile(r"(?P<num>\d+(?:[.,]\d+)?)\s*(?P<unit>[a-zA-Z]*)")


class DurationParseError(ValueError):
    pass


def parse_duration(text: str, default_unit: str = "s") -> float:
    """Parse `text` into seconds.

    If `text` has no unit, `default_unit` is applied (so a spinner-only
    value stays meaningful). Commas are treated as decimal separators.
    Multiple tokens sum (e.g. "2h 30min").
    """
    if text is None:
        raise DurationParseError("empty input")
    s = text.strip().lower()
    if not s:
        raise DurationParseError("empty input")

    total = 0.0
    matched_any = False
    pos = 0
    for m in _TOKEN_RE.finditer(s):
        if m.start() != pos and s[pos:m.start()].strip():
            raise DurationParseError(f"could not parse segment near {s[pos:m.start()]!r}")
        pos = m.end()
        raw_num = m.group("num").replace(",", ".")
        try:
            num = float(raw_num)
        except ValueError:
            raise DurationParseError(f"bad number {raw_num!r}")
        unit = (m.group("unit") or "").strip().rstrip(".")
        if not unit:
            unit = default_unit
        factor = _UNIT_SECONDS.get(unit)
        if factor is None:
            raise DurationParseError(f"unknown unit {unit!r}")
        total += num * factor
        matched_any = True
    if not matched_any:
        raise DurationParseError(f"could not parse {text!r}")
    if pos != len(s) and s[pos:].strip():
        raise DurationParseError(f"trailing garbage {s[pos:]!r}")
    return total


def format_duration(seconds: float) -> str:
    """Turn a raw seconds value back into a human sentence (for display)."""
    if seconds <= 0:
        return "0s"
    d, rem = divmod(int(seconds), 86400)
    h, rem = divmod(rem, 3600)
    m, sec = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    if sec or not parts:
        parts.append(f"{sec}s")
    return " ".join(parts)
