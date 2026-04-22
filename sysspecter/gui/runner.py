"""Subprocess runner that pipes stdout/stderr into a Tkinter-safe queue.

The worker thread reads the child process's output line-by-line and pushes
each line onto a queue. The Tkinter main loop polls the queue via `after()`,
so we never touch Tk widgets from the worker thread.
"""

from __future__ import annotations

import os
import queue
import signal
import subprocess
import sys
import threading
from pathlib import Path
from typing import Callable


EXIT_MARKER = "__SYSSPECTER_GUI_EXIT__"


def main_script_path() -> Path:
    """Return the path to sysspecter.py (CLI entry) relative to this package."""
    here = Path(__file__).resolve()
    # sysspecter/gui/runner.py  ->  <repo_root>/sysspecter.py
    repo_root = here.parent.parent.parent
    candidate = repo_root / "sysspecter.py"
    if candidate.exists():
        return candidate
    # When packaged as a single-file executable, fall back to sys.argv[0].
    argv0 = Path(sys.argv[0]).resolve()
    if argv0.exists():
        return argv0
    return candidate


def _build_invocation(args: list[str]) -> list[str]:
    """Return the full argv to launch a sysspecter subcommand.

    When running as a PyInstaller-frozen EXE, sys.executable IS the
    sysspecter CLI -- the subcommand is passed directly. Otherwise we
    spawn the interpreter pointed at the sysspecter.py entry script.
    """
    if getattr(sys, "frozen", False):
        return [sys.executable] + args
    return [sys.executable, str(main_script_path())] + args


class SubprocessRunner:
    """Run a sysspecter subcommand and feed its output to a queue."""

    def __init__(self, args: list[str], env: dict[str, str] | None = None) -> None:
        self.args: list[str] = _build_invocation(args)
        self.env = env or dict(os.environ)
        self.env.setdefault("PYTHONIOENCODING", "utf-8")
        self.env.setdefault("PYTHONUTF8", "1")
        self.output_queue: "queue.Queue[str]" = queue.Queue()
        self.proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._exit_code: int | None = None
        self._on_exit: Callable[[int], None] | None = None

    def start(self, on_exit: Callable[[int], None] | None = None) -> None:
        self._on_exit = on_exit
        creationflags = 0
        if sys.platform == "win32":
            # Puts the child in its own process group so CTRL_BREAK signals
            # reach it without hitting us.
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        self.proc = subprocess.Popen(
            self.args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=creationflags,
            env=self.env,
        )
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def _reader(self) -> None:
        assert self.proc is not None
        try:
            if self.proc.stdout is not None:
                for line in self.proc.stdout:
                    self.output_queue.put(line.rstrip("\n"))
        finally:
            self._exit_code = self.proc.wait()
            self.output_queue.put(f"{EXIT_MARKER}{self._exit_code}")
            if self._on_exit:
                try:
                    self._on_exit(self._exit_code)
                except Exception:
                    pass

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def send_ctrl_break(self) -> None:
        """Windows-friendly graceful stop. On non-Windows sends SIGINT."""
        if not self.is_running():
            return
        assert self.proc is not None
        try:
            if sys.platform == "win32":
                self.proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                self.proc.send_signal(signal.SIGINT)
        except Exception:
            pass

    def kill(self) -> None:
        if not self.is_running():
            return
        assert self.proc is not None
        try:
            self.proc.kill()
        except Exception:
            pass

    def exit_code(self) -> int | None:
        return self._exit_code
