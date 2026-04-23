"""Write unhandled exceptions to disk so they can be shipped for support.

A crash dump is a plain UTF-8 text file under
`<output_root>/crash_reports/crash_<timestamp>.txt` containing:
- A short header (timestamp, SysSpecter version, Python version, admin)
- The full traceback
- `sys.argv` and selected environment variables (`OS`, `COMPUTERNAME` —
  opt-in for redaction via the sanitizer later)

Nothing is uploaded. Nothing leaves the host. The GUI shows the path
and opens the containing folder on user request.
"""

from __future__ import annotations

import datetime as _dt
import os
import platform
import sys
import traceback
from types import TracebackType
from typing import Any


def _crash_dir(output_root: str) -> str:
    crash_dir = os.path.join(output_root, "crash_reports")
    os.makedirs(crash_dir, exist_ok=True)
    return crash_dir


def write_crash_report(
    output_root: str,
    exc_type: type[BaseException],
    exc_value: BaseException,
    exc_tb: TracebackType | None,
    *,
    extra: dict[str, Any] | None = None,
) -> str:
    """Write a crash dump and return its absolute path.

    `extra` is a free-form dict that ends up in the dump (e.g. which
    tab the user was on). Silent-best-effort: on I/O error we fall
    back to `%TEMP%`.
    """
    try:
        base = _crash_dir(output_root)
    except OSError:
        base = _crash_dir(os.environ.get("TEMP", "."))

    ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(base, f"crash_{ts}.txt")

    from .. import __version__ as _SS_VERSION
    lines: list[str] = []
    lines.append("SysSpecter crash report")
    lines.append("=" * 40)
    lines.append(f"timestamp: {_dt.datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"version:   {_SS_VERSION}")
    lines.append(f"python:    {sys.version.splitlines()[0]}")
    lines.append(f"platform:  {platform.platform()}")
    lines.append(f"argv:      {' '.join(sys.argv)}")
    if extra:
        for k, v in extra.items():
            lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("Traceback")
    lines.append("-" * 40)
    lines.extend(traceback.format_exception(exc_type, exc_value, exc_tb))
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
    except OSError:
        pass
    return path
