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

Field-review M1: identifiers are replaced by *stable hashes* of the form
`HOST-7f3a`, `USER-bb9c`, `BIOS-3e2d` instead of a literal `[REDACTED]`
token. Same input → same output across every column and file, so
cross-process attribution still works after redaction (you can still see
that PIDs 1234 and 5678 belong to the same user, you just don't know
which user). Hashes are blake2b(lowercased value, 2 bytes) → 4 hex chars,
which is plenty of unicity at the per-run scale and doesn't survive a
rainbow-table attack on personal data.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
from typing import Any

from .logging_setup import get_logger

_log = get_logger(__name__)

_REDACTED = "[REDACTED]"


def _stable_hash(value: str, label: str) -> str:
    """Return a deterministic 4-hex-char token, e.g. ``USER-7f3a``.

    Same input → same output across processes, columns, and files,
    so a redacted run still carries the cross-process correlation
    structure the analyzer relies on. Non-reversible at any
    practical scale.
    """
    digest = hashlib.blake2b(value.lower().encode("utf-8"), digest_size=2).hexdigest()
    return f"{label}-{digest}"


# Pre-pass patterns applied to every string before the identifier
# substitution. Catches credentials baked into command lines / config
# fragments (cmdline capture is currently a no-op, but the safe_collect
# scaffolding in process_sampler will surface cmdlines in a future
# release — better to redact them by default than to retrofit later).
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # `--password=...`, `--token=...`, `--api-key=...`, etc.
    (re.compile(
        r"(?i)(-{1,2}(?:password|passwd|pwd|secret|token|api[-_]?key|"
        r"access[-_]?key|client[-_]?secret|auth[-_]?token)"
        r"\s*[=: ]\s*)\S+"
    ), r"\1<SECRET>"),
    # `Authorization: Bearer ...` style
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"), "Bearer <SECRET>"),
    # raw JWTs (3 base64-ish parts joined by dots)
    (re.compile(
        r"\beyJ[A-Za-z0-9_\-]{4,}"
        r"\.[A-Za-z0-9_\-]{4,}"
        r"\.[A-Za-z0-9_\-]{4,}"
    ), "<JWT>"),
    # AWS access key IDs
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<AWS_KEY>"),
    # GitHub tokens (ghp_, github_pat_, gho_, ghs_, ghr_, ghu_)
    (re.compile(r"\bgh[opsru]_[A-Za-z0-9_]{36,}\b"), "<GITHUB_TOKEN>"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "<GITHUB_TOKEN>"),
]


def _scrub_secrets(text: str) -> str:
    """Strip credential-looking substrings before the identifier pass."""
    for pat, repl in _SECRET_PATTERNS:
        text = pat.sub(repl, text)
    return text


def _redact_text(text: str, replacements: dict[str, str]) -> str:
    text = _scrub_secrets(text)
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
                # Dropped values stay as the literal sentinel — these
                # are paths / serial numbers we explicitly do NOT want
                # to preserve correlation on (path-to-Python interpreter,
                # output-root with absolute path, etc.).
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
    """Build the search-and-replace table from identifying values.

    Every identifier maps to a stable hash token so downstream
    correlations (same-user-across-PIDs, same-host-across-runs) survive
    redaction. Field-review M1.
    """
    repl: dict[str, str] = {}

    # Hostname + FQDN map to the SAME hash so `BOX1` and `BOX1.corp.local`
    # collapse onto one consistent token in the report.
    host = manifest.get("hostname")
    if isinstance(host, str) and host:
        host_token = _stable_hash(host, "HOST")
        repl[host] = host_token
        fqdn = manifest.get("fqdn")
        if isinstance(fqdn, str) and fqdn and fqdn != host:
            repl[fqdn] = host_token
    else:
        fqdn = manifest.get("fqdn")
        if isinstance(fqdn, str) and fqdn:
            repl[fqdn] = _stable_hash(fqdn, "HOST")

    # BIOS + disk serials hide inside static_snapshot.
    bios = static.get("bios") or {}
    for k in ("SerialNumber", "SMBIOSBIOSVersion"):
        v = bios.get(k)
        if isinstance(v, str) and v:
            repl[v] = _stable_hash(v, "BIOS")
    for d in (static.get("disks") or []):
        phys = d.get("_physical_drive") if isinstance(d, dict) else None
        if isinstance(phys, dict):
            ser = phys.get("SerialNumber")
            if isinstance(ser, str) and ser:
                repl[ser] = _stable_hash(ser, "DISK")
    bb = static.get("baseboard") or {}
    if isinstance(bb.get("SerialNumber"), str) and bb["SerialNumber"]:
        repl[bb["SerialNumber"]] = _stable_hash(bb["SerialNumber"], "BB")

    # Username — appears in process owners (`KTM\ankenbrand`) and as the
    # home-dir component of paths (`C:\Users\ankenbrand\...`).
    user = os.environ.get("USERNAME") or os.environ.get("USER")
    if user:
        repl[user] = _stable_hash(user, "USER")
    return repl


def _rewrite_json(path: str, replacements: dict[str, str],
                  drop_keys: set[str]) -> None:
    if not os.path.exists(path):
        return
    try:
        with open(path, encoding="utf-8") as f:
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
        with open(path, encoding="utf-8", newline="") as f:
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
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, json.JSONDecodeError):
        manifest = {}
    try:
        with open(static_path, encoding="utf-8") as f:
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

    # Mark that this is a sanitized copy. The source folder name itself
    # carries the original hostname (e.g. HOSTNAME_20260423_010000), so
    # run the replacement table over it before storing.
    try:
        with open(manifest_path, encoding="utf-8") as f:
            m = json.load(f)
        m["sanitized"] = True
        source_name = os.path.basename(run_dir)
        m["sanitized_source"] = _redact_text(source_name, replacements)
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(m, f, indent=2)
    except (OSError, json.JSONDecodeError):
        _log.warning("could not rewrite manifest during sanitize", exc_info=True)

    # Rebuild the report so the HTML/MD reflect the redacted data.
    try:
        from .reporter.html_report import build_report
        build_report(out_dir)
    except Exception:
        # If the re-render fails, the caller still has a redacted folder.
        _log.warning("post-sanitize report rebuild failed — "
                     "redacted folder still usable", exc_info=True)

    return out_dir
