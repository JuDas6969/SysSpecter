"""Produce a shippable, de-identified copy of a finished run.

The raw run captures the hostname, FQDN, BIOS / disk serial numbers, running
process command lines, installed-program publishers, and the user's home-path
fragments. Any of those can be sensitive when a customer forwards the
report to a vendor.

`sanitize_run()` writes a full copy of the run to a sibling folder with
`<run_id>_sanitized/` as its name, redacts manifest / static-snapshot /
event JSON, rewrites CSV columns that contain hostnames or usernames, and
re-renders `findings.json`, `scores.json`, `final_report.html`,
`final_report.md` from the redacted data.
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
from typing import Any


_REDACTED = "[REDACTED]"


def _redact_text(text: str, replacements: dict[str, str]) -> str:
    for needle, rep in replacements.items():
        if not needle:
            continue
        try:
            text = re.sub(re.escape(needle), rep, text, flags=re.IGNORECASE)
        except re.error:
            text = text.replace(needle, rep)
    return text


def _walk_redact(obj: Any, replacements: dict[str, str], drop_keys: set[str]) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in drop_keys:
                out[k] = _REDACTED
                continue
            out[k] = _walk_redact(v, replacements, drop_keys)
        return out
    if isinstance(obj, list):
        return [_walk_redact(v, replacements, drop_keys) for v in obj]
    if isinstance(obj, str):
        return _redact_text(obj, replacements)
    return obj


def _collect_replacements(manifest: dict[str, Any], static: dict[str, Any]) -> dict[str, str]:
    """Build the search-and-replace table from identifying values."""
    repl: dict[str, str] = {}
    for k in ("hostname", "fqdn"):
        v = manifest.get(k)
        if isinstance(v, str) and v:
            repl[v] = f"HOST_{_REDACTED}"
    # BIOS + disk serials hide inside static
    bios = static.get("bios") or {}
    for k in ("SerialNumber", "SMBIOSBIOSVersion"):
        v = bios.get(k)
        if isinstance(v, str) and v:
            repl[v] = _REDACTED
    for d in (static.get("disks") or []):
        phys = d.get("_physical_drive") if isinstance(d, dict) else None
        if isinstance(phys, dict):
            ser = phys.get("SerialNumber")
            if isinstance(ser, str) and ser:
                repl[ser] = _REDACTED
    bb = static.get("baseboard") or {}
    if isinstance(bb.get("SerialNumber"), str) and bb["SerialNumber"]:
        repl[bb["SerialNumber"]] = _REDACTED
    # strip C:\Users\<name>\ style paths
    user = os.environ.get("USERNAME") or os.environ.get("USER")
    if user:
        repl[user] = _REDACTED
    return repl


def _rewrite_json(path: str, replacements: dict[str, str],
                  drop_keys: set[str]) -> None:
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return
    redacted = _walk_redact(data, replacements, drop_keys)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(redacted, f, indent=2)


def _rewrite_csv(path: str, replacements: dict[str, str],
                 redact_columns: set[str]) -> None:
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            rows = list(reader)
    except OSError:
        return
    if not rows:
        return
    header = rows[0]
    idx_redact = {i for i, c in enumerate(header) if c in redact_columns}
    out_rows = [header]
    for row in rows[1:]:
        new_row = list(row)
        for i, cell in enumerate(new_row):
            if i in idx_redact:
                new_row[i] = _REDACTED
                continue
            if isinstance(cell, str) and cell:
                new_row[i] = _redact_text(cell, replacements)
        out_rows.append(new_row)
    with open(path, "w", encoding="utf-8", newline="") as f:
        csv.writer(f).writerows(out_rows)


# JSON keys whose values are dropped outright
_MANIFEST_DROP = {"python_executable", "output_root", "run_dir"}

# Keys inside static_snapshot.json to drop outright (they are not useful
# for diagnosis once de-identified)
_STATIC_DROP = {
    "network.ipconfig_all", "network.route_print",
    "computer_system.Name", "computer_system.DNSHostName",
}

# CSV columns to fully redact in timeline_processes.csv (cmdline if we ever add it)
_CSV_REDACT_COLUMNS = {"cmdline", "image_path", "exe"}


def sanitize_run(run_dir: str, out_dir: str | None = None) -> str:
    """Produce a sanitized copy of `run_dir`. Returns the new folder path."""
    run_dir = os.path.abspath(run_dir)
    if not os.path.isdir(run_dir):
        raise FileNotFoundError(run_dir)
    if out_dir is None:
        parent = os.path.dirname(run_dir)
        base = os.path.basename(run_dir)
        out_dir = os.path.join(parent, f"{base}_sanitized")
    out_dir = os.path.abspath(out_dir)

    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    shutil.copytree(run_dir, out_dir, dirs_exist_ok=False)

    # Load manifest + static from the COPY so we can build replacement map.
    manifest_path = os.path.join(out_dir, "manifest.json")
    static_path = os.path.join(out_dir, "static_snapshot.json")
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, json.JSONDecodeError):
        manifest = {}
    try:
        with open(static_path, "r", encoding="utf-8") as f:
            static = json.load(f)
    except (OSError, json.JSONDecodeError):
        static = {}

    replacements = _collect_replacements(manifest, static)

    # Rewrite manifest + static + event JSONs, and all timeline CSVs.
    _rewrite_json(manifest_path, replacements, drop_keys=_MANIFEST_DROP)
    _rewrite_json(static_path, replacements, drop_keys={"ipconfig_all", "route_print"})
    for name in (
        "findings.json", "scores.json",
        "process_events.json", "service_events.json",
        "process_start_snapshot.json", "service_start_snapshot.json",
        "event_log.json", "etw_disk_summary.json", "phases.json",
    ):
        _rewrite_json(os.path.join(out_dir, name), replacements, drop_keys=set())

    for name in (
        "timeline_system.csv", "timeline_processes.csv",
        "timeline_network.csv", "timeline_latency.csv",
        "timeline_connections.csv", "timeline_gpu_engine.csv",
        "timeline_gpu_process.csv", "timeline_gpu_adapter.csv",
    ):
        _rewrite_csv(os.path.join(out_dir, name), replacements, _CSV_REDACT_COLUMNS)

    # Mark that this is a sanitized copy.
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            m = json.load(f)
        m["sanitized"] = True
        m["sanitized_source"] = os.path.basename(run_dir)
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(m, f, indent=2)
    except (OSError, json.JSONDecodeError):
        pass

    # Rebuild the report so the HTML/MD reflect the redacted data.
    try:
        from .reporter.html_report import build_report
        build_report(out_dir)
    except Exception:
        # If the re-render fails, the caller still has a redacted folder.
        pass

    return out_dir
