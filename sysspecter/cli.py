"""pip-installable entry points for SysSpecter.

The CLI lives in the top-level `sysspecter.py` script so PyInstaller can
build from it directly. For pip installs we expose the same entry here
via `runpy`, so `pyproject.toml` can register `sysspecter = sysspecter.cli:main`.
"""

from __future__ import annotations

import os
import runpy
import sys


def _script_path() -> str:
    # sysspecter/cli.py -> sysspecter/../sysspecter.py
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", "sysspecter.py"))


def main() -> int:
    """Replay the top-level sysspecter.py script as __main__."""
    script = _script_path()
    if not os.path.exists(script):
        sys.stderr.write(f"sysspecter: cannot find entry script at {script}\n")
        return 2
    try:
        runpy.run_path(script, run_name="__main__")
        return 0
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 0
