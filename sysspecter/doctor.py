"""Self-check routines for `sysspecter doctor`.

Each check returns a `CheckResult`. The CLI entry aggregates them and
prints a report. rc=0 when every required check passes; rc=1 when any
required check fails (optional checks never break rc).
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    required: bool
    detail: str


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def _version(cmd: list[str], timeout: float = 5.0) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, creationflags=0x08000000,  # CREATE_NO_WINDOW
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    out = (proc.stdout + proc.stderr).splitlines()
    head = out[0].strip() if out else f"rc={proc.returncode}"
    return proc.returncode == 0, head[:120]


def check_python() -> CheckResult:
    return CheckResult(
        name="Python",
        ok=sys.version_info >= (3, 12),
        required=True,
        detail=sys.version.splitlines()[0],
    )


def check_runtime_deps() -> CheckResult:
    missing: list[str] = []
    for mod in ("psutil", "jinja2", "pydantic"):
        try:
            __import__(mod)
        except Exception:
            missing.append(mod)
    return CheckResult(
        name="Runtime deps (psutil / jinja2 / pydantic)",
        ok=not missing,
        required=True,
        detail="all present" if not missing else f"missing: {', '.join(missing)}",
    )


def check_powershell() -> CheckResult:
    ok, head = _version(["powershell.exe", "-NoProfile", "-NonInteractive",
                         "-Command", "$PSVersionTable.PSVersion"])
    return CheckResult(
        name="PowerShell available",
        ok=ok, required=True, detail=head or "ok",
    )


def check_logman() -> CheckResult:
    found = shutil.which("logman.exe") is not None
    return CheckResult(
        name="logman.exe (Phase 3 ETW)",
        ok=found, required=False,
        detail="on PATH" if found else "not found — ETW collector will no-op",
    )


def check_tracerpt() -> CheckResult:
    found = shutil.which("tracerpt.exe") is not None
    return CheckResult(
        name="tracerpt.exe (Phase 3 ETW summary)",
        ok=found, required=False,
        detail="on PATH" if found else "not found — ETW finalize will no-op",
    )


def check_output_root_writable(output_root: str) -> CheckResult:
    try:
        os.makedirs(output_root, exist_ok=True)
        probe = os.path.join(output_root, ".sysspecter_doctor_probe")
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe)
        return CheckResult(
            name=f"Output root writable ({output_root})",
            ok=True, required=True, detail="can write",
        )
    except OSError as e:
        return CheckResult(
            name=f"Output root writable ({output_root})",
            ok=False, required=True, detail=str(e),
        )


def check_admin() -> CheckResult:
    admin = _is_admin()
    return CheckResult(
        name="Administrator",
        ok=admin, required=False,
        detail="elevated" if admin
            else "running as standard user — ETW / some WMI unavailable",
    )


def run_all(output_root: str) -> list[CheckResult]:
    return [
        check_python(),
        check_runtime_deps(),
        check_powershell(),
        check_admin(),
        check_output_root_writable(output_root),
        check_logman(),
        check_tracerpt(),
    ]


def print_report(results: list[CheckResult]) -> int:
    """Pretty-print and return the recommended exit code."""
    print("=" * 60)
    print(" SysSpecter doctor")
    print("=" * 60)
    failures_required = 0
    failures_optional = 0
    for r in results:
        mark = "OK " if r.ok else ("FAIL" if r.required else "WARN")
        print(f"  [{mark}] {r.name}")
        if r.detail:
            print(f"         {r.detail}")
        if not r.ok:
            if r.required:
                failures_required += 1
            else:
                failures_optional += 1
    print("-" * 60)
    if failures_required == 0 and failures_optional == 0:
        print(" Healthy.")
    elif failures_required == 0:
        print(f" {failures_optional} optional check(s) failed — core features are OK.")
    else:
        print(f" {failures_required} required check(s) failed "
              f"(+ {failures_optional} optional).")
    print("=" * 60)
    return 1 if failures_required else 0
