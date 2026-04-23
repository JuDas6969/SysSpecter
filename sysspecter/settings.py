"""User-preferences persistence for the GUI.

Preferences live at `%APPDATA%\\SysSpecter\\config.toml` so they survive
install.bat re-runs and travel with the user's Windows profile. On a
portable EXE run (no APPDATA or write failure), we fall back to
`<exe_dir>\\SysSpecter\\config.toml` so the stick keeps its own
settings next to the EXE.

The module is deliberately small:
- `UserPrefs` dataclass with defaults that match the monitor tab's
  current behaviour, so existing users see no change.
- `load_prefs()` returns the user's saved prefs merged over the
  defaults; missing or malformed files silently fall back to defaults.
- `save_prefs(prefs)` writes the current state atomically.
- `push_output_root(path)` maintains a 5-entry MRU.

No pydantic — tomllib is enough for read, and we write a plain TOML by
hand for a predictable layout diff.
"""

from __future__ import annotations

import logging
import os
import sys
import tempfile
import tomllib
from dataclasses import asdict, dataclass, field
from typing import Any

_log = logging.getLogger(__name__)

CONFIG_FILENAME = "config.toml"
MAX_MRU = 5


@dataclass
class UserPrefs:
    # Output-root most-recently-used, newest first. The current one is [0].
    output_root_mru: list[str] = field(default_factory=list)

    default_mode: str = "support"           # support / baseline / workload
    default_duration_seconds: int = 1800    # 30 minutes
    default_manual_stop: bool = True

    default_latency_targets: list[str] = field(
        default_factory=lambda: ["127.0.0.1", "8.8.8.8", "1.1.1.1"]
    )

    # Phase 3 collectors — stored defaults
    default_phase3_gpu: bool = False
    default_phase3_event_logs: bool = False
    default_phase3_etw_disk: bool = False

    theme: str = "light"                    # "light" | "dark" (dark is W3)
    show_admin_banner: bool = True
    check_updates_on_start: bool = True


# ---------------------------------------------------------------- storage path


def _preferred_config_dir() -> str:
    """Return the folder under which config.toml lives."""
    appdata = os.environ.get("APPDATA")
    if appdata:
        return os.path.join(appdata, "SysSpecter")
    # Fallback for unusual setups (portable EXE on a stick with no APPDATA)
    if getattr(sys, "frozen", False):
        return os.path.join(os.path.dirname(os.path.abspath(sys.executable)),
                            "SysSpecter")
    return os.path.join(os.path.expanduser("~"), ".sysspecter")


def config_path() -> str:
    return os.path.join(_preferred_config_dir(), CONFIG_FILENAME)


# ---------------------------------------------------------------- IO


def load_prefs(path: str | None = None) -> UserPrefs:
    path = path or config_path()
    if not os.path.exists(path):
        return UserPrefs()
    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        _log.warning("failed to read %s: %s — falling back to defaults", path, e)
        return UserPrefs()
    defaults = asdict(UserPrefs())
    merged: dict[str, Any] = {**defaults, **raw}
    try:
        return UserPrefs(**{k: merged[k] for k in defaults})
    except TypeError as e:
        _log.warning("config.toml has unexpected keys: %s — using defaults", e)
        return UserPrefs()


def save_prefs(prefs: UserPrefs, path: str | None = None) -> str:
    path = path or config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    body = _dump_toml(asdict(prefs))
    # Atomic write via temp file + rename
    tmp_fd, tmp_path = tempfile.mkstemp(
        prefix="sysspecter_cfg_", suffix=".toml",
        dir=os.path.dirname(path) or ".",
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            f.write(body)
        os.replace(tmp_path, path)
    except OSError:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise
    return path


def push_output_root(prefs: UserPrefs, path: str) -> UserPrefs:
    """Return a new UserPrefs with `path` at the head of the MRU."""
    norm = os.path.abspath(path)
    remaining = [p for p in prefs.output_root_mru if os.path.abspath(p) != norm]
    mru = [norm, *remaining][:MAX_MRU]
    return UserPrefs(
        **{**asdict(prefs), "output_root_mru": mru},
    )


# ---------------------------------------------------------------- TOML writer


def _dump_toml(data: dict[str, Any]) -> str:
    """Very small TOML emitter for our flat schema. Handles the value
    types that actually appear in UserPrefs: str / int / bool / list[str]."""
    lines: list[str] = []
    for key, value in data.items():
        lines.append(f"{key} = {_toml_value(value)}")
    return "\n".join(lines) + "\n"


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    if isinstance(value, str):
        return _quote_string(value)
    # fall through to quoted repr
    return _quote_string(str(value))


def _quote_string(s: str) -> str:
    # TOML basic strings; escape \ and " and drop control chars.
    escaped = (
        s.replace("\\", "\\\\")
         .replace('"', '\\"')
         .replace("\n", "\\n")
         .replace("\r", "\\r")
         .replace("\t", "\\t")
    )
    return f'"{escaped}"'


__all__ = [
    "UserPrefs",
    "CONFIG_FILENAME",
    "MAX_MRU",
    "config_path",
    "load_prefs",
    "save_prefs",
    "push_output_root",
]
