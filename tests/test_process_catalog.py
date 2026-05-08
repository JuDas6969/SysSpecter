"""Field-review C2: process classification catalog.

Pins the contract for the JSON-driven process classification dictionary
that replaces the inline `{"msmpeng.exe", "mssense.exe", ...}` sets in
the analyzer. These tests cover:

- shipped catalog covers every major EDR vendor (no Microsoft-only blind spot)
- lookups are case-insensitive
- user override at %APPDATA% takes priority over the bundled catalog
- malformed entries don't abort the load
- display-name fallback for unknown processes is human-readable
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from sysspecter import process_catalog as pc


def _reload_with_only(path: Path) -> pc.Catalog:
    """Force the catalog to load only from `path`, ignoring all other
    discovery candidates. Used to test isolated payloads."""
    with patch.object(pc, "_candidate_paths", return_value=[str(path)]):
        return pc.reload()


def test_shipped_catalog_covers_every_major_edr() -> None:
    cat = pc.reload()
    # The exact reason this work exists: a customer running CrowdStrike
    # / SentinelOne / Sophos / Cortex XDR must NOT get a "no security
    # overhead detected" report just because we only knew Defender.
    edr_vendors_required = {
        "microsoft-defender-for-endpoint",
        "crowdstrike-falcon",
        "sentinelone",
        "sophos-intercept-x",
        "palo-alto-cortex-xdr",
        "vmware-carbon-black",
        "trend-micro",
    }
    found = {
        cat.lookup(name).vendor
        for name in cat.names_in_category("edr")
        if cat.lookup(name) and cat.lookup(name).vendor
    }
    missing = edr_vendors_required - found
    assert not missing, (
        f"shipped catalog missing EDR vendors: {missing}. "
        "Without these, customers running the matching agent get a "
        "report that under-reports their security overhead."
    )


def test_lookup_is_case_insensitive() -> None:
    cat = pc.reload()
    assert cat.lookup("MsSense.exe") is not None
    assert cat.lookup("mssense.exe") is not None
    assert cat.lookup("MSSENSE.EXE") is not None
    assert cat.lookup("MsSense.exe") == cat.lookup("MSSENSE.EXE")


def test_unknown_process_returns_none_but_display_name_falls_back() -> None:
    cat = pc.reload()
    assert cat.lookup("not-in-catalog.exe") is None
    assert cat.category("not-in-catalog.exe") is None
    # Fallback should still produce something usable in the UI.
    assert cat.display_name("foobar.exe") == "Foobar"
    assert cat.display_name("FOOBAR.EXE") == "FOOBAR"  # ALL-CAPS preserved
    assert cat.display_name("") == "?"
    assert cat.display_name(None) == "?"


def test_is_security_tool_covers_edr_av_dlp(tmp_path: Path) -> None:
    catalog_file = tmp_path / "process_catalog.json"
    catalog_file.write_text(json.dumps({
        "version": 1,
        "entries": [
            {"name": "edr.exe", "category": "edr", "vendor": "x", "display_name": "EDR"},
            {"name": "av.exe",  "category": "av",  "vendor": "x", "display_name": "AV"},
            {"name": "dlp.exe", "category": "dlp", "vendor": "x", "display_name": "DLP"},
            {"name": "vpn.exe", "category": "vpn", "vendor": "x", "display_name": "VPN"},
        ],
    }))
    cat = _reload_with_only(catalog_file)
    assert cat.is_security_tool("edr.exe") is True
    assert cat.is_security_tool("av.exe") is True
    assert cat.is_security_tool("dlp.exe") is True
    assert cat.is_security_tool("vpn.exe") is False  # VPN is not security
    assert cat.is_security_tool("unknown.exe") is False


def test_user_override_replaces_shipped_entry(tmp_path: Path) -> None:
    """User-override in %APPDATA% must shadow the shipped catalog —
    so a site running a custom build of MsSense or a relabelled EDR
    can correct the classification without forking SysSpecter."""
    user_override = tmp_path / "user.json"
    user_override.write_text(json.dumps({
        "version": 1,
        "entries": [
            {"name": "MsSense.exe", "category": "av",
             "vendor": "site-fork", "display_name": "Custom Sense"},
        ],
    }))
    shipped = tmp_path / "shipped.json"
    shipped.write_text(json.dumps({
        "version": 1,
        "entries": [
            {"name": "MsSense.exe", "category": "edr",
             "vendor": "microsoft", "display_name": "Defender Sense"},
        ],
    }))
    # User override comes first in priority
    with patch.object(pc, "_candidate_paths",
                      return_value=[str(user_override), str(shipped)]):
        cat = pc.reload()
    e = cat.lookup("MsSense.exe")
    assert e is not None
    assert e.vendor == "site-fork", "user override must beat shipped entry"
    assert e.display_name == "Custom Sense"


def test_malformed_entry_does_not_abort_load(tmp_path: Path) -> None:
    catalog_file = tmp_path / "process_catalog.json"
    catalog_file.write_text(json.dumps({
        "version": 1,
        "entries": [
            {"name": "good.exe", "category": "av", "vendor": "x"},
            {"category": "edr"},                     # missing name
            "this is not even a dict",
            {"name": "", "category": "av"},          # empty name
            {"name": "ok.exe", "category": "edr"},   # ok
        ],
    }))
    cat = _reload_with_only(catalog_file)
    assert cat.lookup("good.exe") is not None
    assert cat.lookup("ok.exe") is not None
    # Bad entries dropped, didn't poison the others.
    assert cat.category("good.exe") == "av"
    assert cat.category("ok.exe") == "edr"


def test_missing_catalog_file_returns_empty(tmp_path: Path) -> None:
    """Misconfigured install (no catalog at all) must not crash the
    analyzer. We get an empty catalog and life goes on."""
    nonexistent = tmp_path / "nope.json"
    with patch.object(pc, "_candidate_paths", return_value=[str(nonexistent)]):
        cat = pc.reload()
    assert cat.lookup("anything.exe") is None
    assert cat.is_security_tool("MsSense.exe") is False
    # display_name still falls back gracefully.
    assert cat.display_name("foo.exe") == "Foo"


def test_catalog_first_call_does_not_deadlock() -> None:
    """Regression: catalog() acquired _cache_lock and then called reload()
    which also tried to acquire the same lock. With a plain Lock this
    deadlocked the entire analyzer pipeline on the first cold call. The
    fix is to use RLock so the same thread can re-enter.

    Detected during the v1.1.0 release audit — the full pytest suite
    hung on test_analysis_window because analyze_run -> rank_offenders
    -> catalog() never returned.
    """
    import threading

    # Force a cold start so catalog() must call reload() while holding the lock.
    pc._cache = None
    done = threading.Event()
    result: list[pc.Catalog] = []

    def _call() -> None:
        result.append(pc.catalog())
        done.set()

    t = threading.Thread(target=_call, daemon=True)
    t.start()
    # 5 s is generous; on a working build this returns in ~50 ms.
    assert done.wait(timeout=5.0), "catalog() deadlocked on cold start"
    assert isinstance(result[0], pc.Catalog)


def test_names_in_category_returns_lowercased(tmp_path: Path) -> None:
    catalog_file = tmp_path / "process_catalog.json"
    catalog_file.write_text(json.dumps({
        "version": 1,
        "entries": [
            {"name": "MsSense.exe",  "category": "edr"},
            {"name": "CSAgent.sys",  "category": "edr"},
            {"name": "chrome.exe",   "category": "browser"},
        ],
    }))
    cat = _reload_with_only(catalog_file)
    assert cat.names_in_category("edr") == {"mssense.exe", "csagent.sys"}
    assert cat.names_in_category("browser") == {"chrome.exe"}
    assert cat.names_in_category("nonexistent") == set()
