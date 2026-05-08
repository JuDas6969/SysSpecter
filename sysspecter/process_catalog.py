"""Process classification catalog (Field-review C2).

Replaces the hardcoded "MsSense.exe / msmpeng.exe / smartscreen.exe"
sets that lived inline in `analyzer/grouping.py`, `analyzer/offenders.py`
and `analyzer/bottlenecks.py` with a JSON-driven catalog.

Why this matters: any KTM customer running CrowdStrike, SentinelOne,
Sophos, Cortex XDR or another non-Microsoft EDR previously got a
report that said "no security overhead detected" because the analyzer
only knew about Defender. With the catalog, EDR / AV / VPN / MDM /
DLP attribution works regardless of vendor.

The catalog ships under `assets/process_catalog.json` and is also
discoverable from a per-user override at
`%APPDATA%\\SysSpecter\\process_catalog.json`. User entries replace
shipped entries with the same `name`, so site-specific tools (an
internal compliance agent, a custom helpdesk client, …) can be added
without forking the project.

Public API:

    catalog()                       -> Catalog
    Catalog.lookup(name)            -> Entry | None     (case-insensitive)
    Catalog.category(name)          -> str | None
    Catalog.vendor(name)            -> str | None
    Catalog.display_name(name)      -> str              (always returns something)
    Catalog.is_in_category(name, c) -> bool
    Catalog.names_in_category(c)    -> set[str]         (all known names; lowercase)

The Catalog is loaded once per process and cached. Call `reload()` for
tests that need a clean state.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from threading import Lock

from .logging_setup import get_logger

_log = get_logger(__name__)


@dataclass(frozen=True)
class CatalogEntry:
    name: str          # canonical form (lowercased; matches the executable filename)
    category: str
    vendor: str | None
    display_name: str
    # Field-review C1: language / runtime stack the process belongs to.
    # Drives stack-aware leak thresholds in `analyzer/leak_thresholds.py`
    # so JVM heap-at-Xmx / .NET server-GC saw-tooth / Chromium GC cycles
    # don't get flagged as leaks. None = unknown / "native".
    stack: str | None = None


# Sentinel for "we have looked but found nothing" — distinct from None so
# we don't keep re-trying the lookup for unknown names.
_NOT_FOUND = CatalogEntry(name="?", category="?", vendor=None, display_name="?")


class Catalog:
    """Immutable, threadsafe-after-load process catalog."""

    def __init__(self, entries: list[CatalogEntry]) -> None:
        self._entries: dict[str, CatalogEntry] = {}
        self._by_category: dict[str, set[str]] = {}
        for e in entries:
            key = e.name.lower()
            self._entries[key] = e
            self._by_category.setdefault(e.category, set()).add(key)

    # -- Lookup ----------------------------------------------------------

    def lookup(self, name: str | None) -> CatalogEntry | None:
        if not name:
            return None
        return self._entries.get(name.lower().strip())

    def category(self, name: str | None) -> str | None:
        e = self.lookup(name)
        return e.category if e else None

    def vendor(self, name: str | None) -> str | None:
        e = self.lookup(name)
        return e.vendor if e else None

    def stack(self, name: str | None) -> str | None:
        """Return the language / runtime stack tag (chromium / jvm /
        dotnet / cpython / nodejs / native …), or None if unknown."""
        e = self.lookup(name)
        return e.stack if e else None

    def display_name(self, name: str | None) -> str:
        """Return the catalog's pretty name, or a sensible fallback."""
        e = self.lookup(name)
        if e:
            return e.display_name
        if not name:
            return "?"
        base = name[:-4] if name.lower().endswith(".exe") else name
        return base if base.isupper() else base.title()

    def is_in_category(self, name: str | None, category: str) -> bool:
        e = self.lookup(name)
        return e is not None and e.category == category

    def names_in_category(self, category: str) -> set[str]:
        """Return all KNOWN executable names (lowercased) for the given
        category. Caller is responsible for case-folding the test value
        before checking membership."""
        return set(self._by_category.get(category, set()))

    # -- Convenience for the security-overhead report -------------------

    def is_security_tool(self, name: str | None) -> bool:
        """True for any process the user installed for security reasons —
        EDR, AV, DLP, or SmartScreen-style URL-reputation guards."""
        e = self.lookup(name)
        return e is not None and e.category in ("edr", "av", "dlp")


# ---------------------------------------------------------------------------
# Loading / search-path
# ---------------------------------------------------------------------------


def _candidate_paths() -> list[str]:
    """Return the catalog file paths to consult, in priority order:

    1. user override under %APPDATA%\\SysSpecter
    2. portable EXE: file next to the running EXE
    3. PyInstaller-frozen bundle: sys._MEIPASS/assets
    4. development checkout: <repo>/assets
    """
    paths: list[str] = []

    appdata = os.environ.get("APPDATA")
    if appdata:
        paths.append(os.path.join(appdata, "SysSpecter", "process_catalog.json"))

    if getattr(sys, "frozen", False):
        try:
            exe_dir = os.path.dirname(os.path.abspath(sys.executable))
            paths.append(os.path.join(exe_dir, "assets", "process_catalog.json"))
        except Exception:
            pass
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            paths.append(os.path.join(meipass, "assets", "process_catalog.json"))

    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.abspath(os.path.join(here, ".."))
    paths.append(os.path.join(repo, "assets", "process_catalog.json"))

    return paths


def _parse_entries(payload: object) -> list[CatalogEntry]:
    """Tolerantly parse a catalog payload. A malformed entry is logged
    and skipped, but does not abort the whole load."""
    if not isinstance(payload, dict):
        _log.warning("catalog payload is not a JSON object — using empty catalog")
        return []
    raw_entries = payload.get("entries") or []
    if not isinstance(raw_entries, list):
        _log.warning("catalog 'entries' must be a list — using empty catalog")
        return []
    out: list[CatalogEntry] = []
    for i, raw in enumerate(raw_entries):
        if not isinstance(raw, dict):
            _log.warning("catalog entry %d is not an object", i)
            continue
        name = raw.get("name")
        category = raw.get("category")
        if not isinstance(name, str) or not name.strip():
            _log.warning("catalog entry %d: missing/empty 'name'", i)
            continue
        if not isinstance(category, str) or not category.strip():
            _log.warning("catalog entry %d (%s): missing 'category'", i, name)
            continue
        vendor = raw.get("vendor") if isinstance(raw.get("vendor"), str) else None
        display_name = (
            raw.get("display_name") if isinstance(raw.get("display_name"), str)
            else name
        )
        stack = raw.get("stack") if isinstance(raw.get("stack"), str) else None
        out.append(CatalogEntry(
            name=name.strip(),
            category=category.strip(),
            vendor=vendor,
            display_name=display_name,
            stack=stack.strip() if stack else None,
        ))
    return out


def _load_from_path(path: str) -> list[CatalogEntry]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        _log.warning("could not read catalog %s: %s", path, e)
        return []
    return _parse_entries(payload)


# Cache + lock so concurrent threads don't double-load.
_cache: Catalog | None = None
_cache_lock = Lock()


def reload() -> Catalog:
    """Force-reload the catalog. Useful for tests."""
    global _cache
    merged: dict[str, CatalogEntry] = {}
    # Walk in priority order; overrides come FIRST so we keep the first
    # entry we see for each name. (Reverse order would let bundled
    # entries shadow user overrides, which is wrong.)
    for path in _candidate_paths():
        for entry in _load_from_path(path):
            merged.setdefault(entry.name.lower(), entry)
    cat = Catalog(list(merged.values()))
    with _cache_lock:
        _cache = cat
    _log.info("process catalog loaded: %d entries", len(merged))
    return cat


def catalog() -> Catalog:
    """Return the cached catalog, loading it on first access."""
    global _cache
    if _cache is not None:
        return _cache
    with _cache_lock:
        if _cache is None:
            _cache = reload()
    return _cache
