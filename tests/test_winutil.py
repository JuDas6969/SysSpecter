"""Tests for the PowerShell / cmd subprocess helpers.

These wrappers are the ONLY way SysSpecter talks to Windows WMI, event
logs, Test-Connection, and so on. If they silently return bad data the
whole static snapshot is compromised. We stub out subprocess.run and
verify that:

- Timeouts yield None (not an exception).
- Non-zero exit codes yield None (not a partial string).
- JSON-parse failures yield None (never a half-parsed dict).
- Successful runs return the expected payload shape.
"""

from __future__ import annotations

import json
import logging
import subprocess
from unittest.mock import MagicMock, patch

from sysspecter.winutil import run_cmd, run_ps, run_ps_json


def _fake_run(stdout: str, returncode: int = 0) -> MagicMock:
    m = MagicMock()
    m.stdout = stdout
    m.stderr = ""
    m.returncode = returncode
    return m


def test_run_ps_success_returns_stdout() -> None:
    with patch("sysspecter.winutil.subprocess.run",
               return_value=_fake_run("hello")):
        assert run_ps("Write-Output 'hello'") == "hello"


def test_run_ps_timeout_returns_none() -> None:
    with patch("sysspecter.winutil.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="ps", timeout=5)):
        assert run_ps("Start-Sleep 9999", timeout=5.0) is None


def test_run_ps_non_zero_exit_returns_none() -> None:
    with patch("sysspecter.winutil.subprocess.run",
               return_value=_fake_run("partial", returncode=1)):
        assert run_ps("bad-command") is None


def test_run_ps_generic_exception_returns_none() -> None:
    with patch("sysspecter.winutil.subprocess.run",
               side_effect=OSError("PS missing")):
        assert run_ps("Get-Anything") is None


def test_run_ps_json_parses_object() -> None:
    payload = json.dumps({"Caption": "Windows 11", "Build": 26100})
    with patch("sysspecter.winutil.subprocess.run",
               return_value=_fake_run(payload)):
        assert run_ps_json("Get-CimInstance Win32_OperatingSystem")["Build"] == 26100


def test_run_ps_json_parses_array() -> None:
    payload = json.dumps([{"Name": "svchost"}, {"Name": "lsass"}])
    with patch("sysspecter.winutil.subprocess.run",
               return_value=_fake_run(payload)):
        result = run_ps_json("Get-Process")
        assert isinstance(result, list) and len(result) == 2


def test_run_ps_json_bad_json_returns_none() -> None:
    with patch("sysspecter.winutil.subprocess.run",
               return_value=_fake_run("not-json {}}")):
        assert run_ps_json("Get-Garbage") is None


def test_run_ps_json_empty_stdout_returns_none() -> None:
    with patch("sysspecter.winutil.subprocess.run",
               return_value=_fake_run("")):
        assert run_ps_json("Get-Nothing") is None


def test_run_cmd_file_not_found_returns_none() -> None:
    with patch("sysspecter.winutil.subprocess.run",
               side_effect=FileNotFoundError("logman.exe missing")):
        assert run_cmd(["logman.exe", "query"]) is None


def test_run_cmd_non_zero_still_returns_stdout() -> None:
    """run_cmd intentionally returns stdout even on non-zero exit — some
    CLIs (like certutil) write useful output plus a non-zero code. The
    caller is expected to verify the payload shape."""
    with patch("sysspecter.winutil.subprocess.run",
               return_value=_fake_run("useful-output", returncode=1)):
        assert run_cmd(["certutil", "/hashfile"]) == "useful-output"


def test_logger_gets_called_on_timeout() -> None:
    log = logging.getLogger("test_winutil")
    calls: list[str] = []
    log.warning = lambda *a, **k: calls.append(str(a))  # type: ignore[method-assign]

    with patch("sysspecter.winutil.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="ps", timeout=5)):
        run_ps("Start-Sleep 9999", timeout=5.0, logger=log)

    assert any("timed out" in c for c in calls), \
        f"expected 'timed out' warning, got {calls}"
