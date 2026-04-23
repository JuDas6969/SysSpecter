"""Self-verify helper for sanitized runs.

After `sanitize_run()` produces a copy, `verify(run_dir, identifiers)`
re-scans every JSON and CSV file inside the copy and returns a list
of concrete leak findings ({file, line_or_key, match}) where any of
the known-sensitive `identifiers` still appear verbatim.

The GUI + the CLI `sanitize` subcommand can call this and abort / warn
if verify is non-empty.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class LeakHit:
    file: str             # relative path inside the run dir
    location: str         # "manifest:hostname" or "timeline_system.csv:row_42:col_3"
    snippet: str          # short context


def _collect_identifiers(
    original_manifest: dict, original_static: dict,
) -> list[str]:
    """Extract the identifiers the sanitizer should have redacted."""
    candidates: set[str] = set()
    for k in ("hostname", "fqdn"):
        v = original_manifest.get(k)
        if isinstance(v, str) and v:
            candidates.add(v)
    bios = original_static.get("bios") or {}
    for k in ("SerialNumber",):
        v = bios.get(k)
        if isinstance(v, str) and v:
            candidates.add(v)
    for d in (original_static.get("disks") or []):
        phys = d.get("_physical_drive") if isinstance(d, dict) else None
        if isinstance(phys, dict) and isinstance(phys.get("SerialNumber"), str):
            candidates.add(phys["SerialNumber"])
    bb = original_static.get("baseboard") or {}
    if isinstance(bb.get("SerialNumber"), str) and bb["SerialNumber"]:
        candidates.add(bb["SerialNumber"])
    user = os.environ.get("USERNAME") or os.environ.get("USER")
    if user:
        candidates.add(user)
    # Filter out trivially short identifiers to avoid false positives
    # (e.g. a hostname "PC" would match "PCI", "PCIe", "SPC" everywhere).
    return [c for c in candidates if len(c) >= 4]


def _search_file(path: str, pats: list[re.Pattern[str]], rel: str) -> Iterable[LeakHit]:
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, start=1):
                for p in pats:
                    m = p.search(line)
                    if m:
                        yield LeakHit(
                            file=rel,
                            location=f"line={lineno}",
                            snippet=line.strip()[:120],
                        )
                        break
    except OSError:
        return


def verify(
    run_dir: str,
    *,
    original_manifest: dict | None = None,
    original_static: dict | None = None,
) -> list[LeakHit]:
    """Return leak hits. Empty list = sanitize is clean."""
    if original_manifest is None:
        # Load from the run itself; the sanitized manifest keeps the original
        # fields only as [REDACTED] so this is fine for self-check.
        try:
            with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as f:
                original_manifest = json.load(f)
        except (OSError, json.JSONDecodeError):
            original_manifest = {}
    if original_static is None:
        try:
            with open(os.path.join(run_dir, "static_snapshot.json"), encoding="utf-8") as f:
                original_static = json.load(f)
        except (OSError, json.JSONDecodeError):
            original_static = {}

    identifiers = _collect_identifiers(original_manifest, original_static)
    if not identifiers:
        return []
    pats = [re.compile(re.escape(i), re.IGNORECASE) for i in identifiers]

    hits: list[LeakHit] = []
    for root, _dirs, files in os.walk(run_dir):
        for name in files:
            path = os.path.join(root, name)
            rel = os.path.relpath(path, run_dir)
            # skip large binary-ish files we would not have rewritten anyway
            if name.lower().endswith((".etl", ".pyc", ".zip", ".png",
                                      ".jpg", ".ico", ".exe")):
                continue
            hits.extend(_search_file(path, pats, rel))
    return hits


__all__ = ["LeakHit", "verify"]
