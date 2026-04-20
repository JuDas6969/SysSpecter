"""Thin subprocess helpers for PowerShell / native Windows CLI calls.

All calls degrade soft: on failure they log and return None so callers can continue."""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Any

_PS_FLAGS = [
    "powershell.exe",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-Command",
]

CREATE_NO_WINDOW = 0x08000000


def run_ps(command: str, timeout: float = 20.0, logger: logging.Logger | None = None) -> str | None:
    try:
        proc = subprocess.run(
            _PS_FLAGS + [command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired:
        if logger:
            logger.warning("powershell timed out (%.1fs): %s", timeout, command[:80])
        return None
    except Exception as e:
        if logger:
            logger.warning("powershell failed: %s (%s)", e, command[:80])
        return None
    if proc.returncode != 0:
        if logger:
            logger.warning(
                "powershell exit %d: %s stderr=%s",
                proc.returncode, command[:80], proc.stderr[:200]
            )
        return None
    return proc.stdout


def run_ps_json(
    command: str, timeout: float = 20.0, logger: logging.Logger | None = None
) -> Any:
    """Run a PowerShell command that ends in ConvertTo-Json and parse the result."""
    wrapped = f"{command} | ConvertTo-Json -Depth 5 -Compress"
    out = run_ps(wrapped, timeout=timeout, logger=logger)
    if not out:
        return None
    out = out.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        if logger:
            logger.warning("powershell json parse failed: %s", out[:200])
        return None


def run_cmd(argv: list[str], timeout: float = 15.0, logger: logging.Logger | None = None) -> str | None:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired:
        if logger:
            logger.warning("cmd timed out (%.1fs): %s", timeout, " ".join(argv)[:100])
        return None
    except FileNotFoundError:
        if logger:
            logger.warning("cmd not found: %s", argv[0])
        return None
    except Exception as e:
        if logger:
            logger.warning("cmd failed: %s (%s)", e, " ".join(argv)[:100])
        return None
    if proc.returncode != 0:
        if logger:
            logger.debug(
                "cmd exit %d: %s stderr=%s",
                proc.returncode, " ".join(argv)[:100], proc.stderr[:200]
            )
    return proc.stdout
