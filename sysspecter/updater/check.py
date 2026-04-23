"""Check GitHub Releases for a newer SysSpecter build.

Uses stdlib `urllib` so nothing has to be bundled. The check is
best-effort: any network failure returns `None` and the caller keeps
showing the current version.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

from .. import __version__ as _CURRENT

_log = logging.getLogger(__name__)

_RELEASES_URL = "https://api.github.com/repos/JuDas6969/SysSpecter/releases/latest"
_TIMEOUT_S = 4.0


@dataclass(frozen=True)
class UpdateInfo:
    current: str
    latest: str
    update_available: bool
    release_url: str | None


_SEM_VER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def _parse(version: str) -> tuple[int, int, int] | None:
    m = _SEM_VER_RE.search(version)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def check_for_updates(*, timeout: float = _TIMEOUT_S) -> UpdateInfo | None:
    """Return update info, or None when the check fails (offline etc.)."""
    try:
        req = urllib.request.Request(
            _RELEASES_URL,
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": f"sysspecter/{_CURRENT}"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            data = json.load(resp)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        _log.debug("update check failed: %s", e)
        return None
    except Exception as e:  # noqa: BLE001 — best-effort network call
        _log.debug("update check failed: %s", e)
        return None

    latest_tag = str(data.get("tag_name") or "")
    release_url = data.get("html_url")
    current = _parse(_CURRENT)
    latest = _parse(latest_tag)
    if current is None or latest is None:
        return UpdateInfo(current=_CURRENT, latest=latest_tag or "unknown",
                          update_available=False, release_url=release_url)
    return UpdateInfo(
        current=_CURRENT,
        latest=latest_tag,
        update_available=latest > current,
        release_url=release_url,
    )
