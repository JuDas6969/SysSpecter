"""Diff the static snapshots (hardware, software, autoruns, config) across runs.

All functions are pure and return plain dicts/lists that are JSON-serializable
and friendly to the Jinja templates in compare_report.py. No run data is
modified.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _run_id(run: dict[str, Any]) -> str:
    return (run.get("manifest") or {}).get("run_id") or "?"


def _static(run: dict[str, Any]) -> dict[str, Any]:
    return (run.get("rd").static or {}) if run.get("rd") is not None else {}


def _first(items: list[Any]) -> Any:
    return items[0] if items else None


def _normalise_str(v: Any) -> str:
    if v is None:
        return ""
    return str(v).strip()


# ---------------------------------------------------------------------------
# Hardware
# ---------------------------------------------------------------------------

def _disk_record(disk_entry: dict[str, Any]) -> dict[str, Any] | None:
    """Return the underlying physical-drive dict if this entry is one."""
    if not isinstance(disk_entry, dict):
        return None
    if "_physical_drive" in disk_entry and isinstance(disk_entry["_physical_drive"], dict):
        return disk_entry["_physical_drive"]
    return None


def _physical_disks(static: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for d in (static.get("disks") or []):
        phys = _disk_record(d)
        if phys:
            out.append(phys)
    return out


def _primary_disk(static: dict[str, Any]) -> dict[str, Any] | None:
    disks = _physical_disks(static)
    if not disks:
        return None
    # pick the largest by Size as a proxy for "system disk"
    def _size(d: dict[str, Any]) -> int:
        try:
            return int(d.get("Size") or 0)
        except (TypeError, ValueError):
            return 0
    return max(disks, key=_size)


def hardware_profile(run: dict[str, Any]) -> dict[str, Any]:
    """Extract a compact hardware profile dict for one run."""
    s = _static(run)
    cpu_list = ((s.get("cpu") or {}).get("cpus") or [])
    cpu = _first(cpu_list) or {}
    mem = s.get("memory") or {}
    modules = mem.get("modules") or []
    speeds = [m.get("Speed") or m.get("ConfiguredClockSpeed") for m in modules if m]
    speeds = [int(sp) for sp in speeds if sp]
    gpu_list = s.get("gpus") or []
    bios = s.get("bios") or {}
    comp = s.get("computer_system") or {}
    osinfo = s.get("os") or {}
    total_ram_gb = None
    try:
        total_ram_gb = round(int(mem.get("total_bytes") or 0) / (1024 ** 3), 1) or None
    except (TypeError, ValueError):
        total_ram_gb = None
    primary_disk = _primary_disk(s) or {}
    return {
        "run_id": _run_id(run),
        "hostname": (run.get("manifest") or {}).get("hostname"),
        "manufacturer": comp.get("Manufacturer"),
        "model": comp.get("Model"),
        "os_caption": osinfo.get("caption"),
        "os_build": osinfo.get("build"),
        "cpu_name": cpu.get("Name"),
        "cpu_cores": cpu.get("NumberOfCores"),
        "cpu_threads": cpu.get("NumberOfLogicalProcessors"),
        "cpu_max_mhz": cpu.get("MaxClockSpeed"),
        "ram_gb": total_ram_gb,
        "ram_modules": len(modules),
        "ram_speed_mhz": max(speeds) if speeds else None,
        "primary_disk_model": primary_disk.get("Model"),
        "primary_disk_size_gb": round(int(primary_disk.get("Size") or 0) / (1024 ** 3), 0)
            if primary_disk.get("Size") else None,
        "primary_disk_media": primary_disk.get("MediaType"),
        "primary_disk_interface": primary_disk.get("InterfaceType"),
        "gpus": [g.get("Name") for g in gpu_list if g.get("Name")],
        "bios_version": bios.get("SMBIOSBIOSVersion") or bios.get("Version"),
        "bios_date": bios.get("ReleaseDate"),
    }


def diff_hardware(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Return per-run hardware profile plus a list of fields where runs diverge."""
    profiles = [hardware_profile(r) for r in runs]
    if not profiles:
        return {"profiles": [], "divergent_fields": []}
    ignore = {"run_id", "hostname"}
    divergent: list[str] = []
    fields = [k for k in profiles[0].keys() if k not in ignore]
    for f in fields:
        values = {str(p.get(f)) for p in profiles}
        if len(values) > 1:
            divergent.append(f)
    return {"profiles": profiles, "divergent_fields": divergent}


# ---------------------------------------------------------------------------
# Software (installed programs)
# ---------------------------------------------------------------------------

def _programs_map(static: dict[str, Any]) -> dict[str, str]:
    """Map program DisplayName -> DisplayVersion (string, "" if missing)."""
    out: dict[str, str] = {}
    for p in (static.get("installed_programs") or []):
        name = _normalise_str(p.get("DisplayName"))
        if not name:
            continue
        out[name] = _normalise_str(p.get("DisplayVersion"))
    return out


def diff_software(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Return per-run-pair software diffs, plus a presence matrix for fleet view.

    For every pair (A, B): programs only in A, only in B, and version-changed.
    For fleet view: programs present in >= 1 but not all runs, with mapping
    run_id -> version.
    """
    per_run: dict[str, dict[str, str]] = {
        _run_id(r): _programs_map(_static(r)) for r in runs
    }

    pairwise: list[dict[str, Any]] = []
    ids = list(per_run.keys())
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            a, b = ids[i], ids[j]
            mp_a, mp_b = per_run[a], per_run[b]
            only_a = sorted(set(mp_a) - set(mp_b))
            only_b = sorted(set(mp_b) - set(mp_a))
            version_diffs = []
            for name in sorted(set(mp_a) & set(mp_b)):
                if mp_a[name] != mp_b[name] and (mp_a[name] or mp_b[name]):
                    version_diffs.append({
                        "name": name,
                        a: mp_a[name] or "—",
                        b: mp_b[name] or "—",
                    })
            pairwise.append({
                "pair": [a, b],
                "only_in_a": only_a[:200],
                "only_in_a_total": len(only_a),
                "only_in_b": only_b[:200],
                "only_in_b_total": len(only_b),
                "version_changed": version_diffs[:200],
                "version_changed_total": len(version_diffs),
            })

    all_names: set[str] = set()
    for mp in per_run.values():
        all_names.update(mp.keys())
    not_in_all: list[dict[str, Any]] = []
    n_runs = len(per_run)
    for name in sorted(all_names):
        presence = {rid: mp.get(name) for rid, mp in per_run.items() if name in mp}
        if len(presence) < n_runs:
            not_in_all.append({"name": name, "present_in": presence})
    return {
        "per_run_counts": {rid: len(mp) for rid, mp in per_run.items()},
        "pairwise": pairwise,
        "not_in_all": not_in_all[:500],
        "not_in_all_total": len(not_in_all),
    }


# ---------------------------------------------------------------------------
# Autoruns
# ---------------------------------------------------------------------------

def _autoruns_set(static: dict[str, Any]) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for a in (static.get("autoruns") or []):
        name = _normalise_str(a.get("Name"))
        cmd = _normalise_str(a.get("Command"))
        if name or cmd:
            out.add((name, cmd))
    return out


def diff_autoruns(runs: list[dict[str, Any]]) -> dict[str, Any]:
    per_run = {_run_id(r): _autoruns_set(_static(r)) for r in runs}
    pairwise: list[dict[str, Any]] = []
    ids = list(per_run.keys())
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            a, b = ids[i], ids[j]
            sa, sb = per_run[a], per_run[b]
            only_a = sorted(sa - sb)
            only_b = sorted(sb - sa)
            pairwise.append({
                "pair": [a, b],
                "only_in_a": [{"name": n, "command": c} for n, c in only_a[:100]],
                "only_in_a_total": len(only_a),
                "only_in_b": [{"name": n, "command": c} for n, c in only_b[:100]],
                "only_in_b_total": len(only_b),
            })
    return {
        "per_run_counts": {rid: len(s) for rid, s in per_run.items()},
        "pairwise": pairwise,
    }


# ---------------------------------------------------------------------------
# Config (power plan, defender, AV, VPN)
# ---------------------------------------------------------------------------

def config_profile(run: dict[str, Any]) -> dict[str, Any]:
    s = _static(run)
    sec = s.get("security") or {}
    defender = sec.get("defender_status") or {}
    av_products = sec.get("antivirus_products") or []
    if isinstance(av_products, dict):
        av_products = [av_products]
    power = s.get("power") or {}
    net = s.get("network") or {}
    plan_line = _normalise_str(power.get("active_scheme_raw")).splitlines()
    plan_line = plan_line[0] if plan_line else ""
    return {
        "run_id": _run_id(run),
        "power_plan": plan_line,
        "defender_realtime": defender.get("RealTimeProtectionEnabled"),
        "defender_av_enabled": defender.get("AntivirusEnabled"),
        "defender_signature": defender.get("AntivirusSignatureVersion"),
        "av_products": [
            _normalise_str(p.get("displayName")) for p in av_products if p.get("displayName")
        ],
        "av_product_count": len(av_products),
        "vpn_adapters": net.get("vpn_suspect_adapters") or [],
    }


def diff_config(runs: list[dict[str, Any]]) -> dict[str, Any]:
    profiles = [config_profile(r) for r in runs]
    if not profiles:
        return {"profiles": [], "divergent_fields": []}
    ignore = {"run_id"}
    divergent: list[str] = []
    for f in [k for k in profiles[0].keys() if k not in ignore]:
        values = {str(p.get(f)) for p in profiles}
        if len(values) > 1:
            divergent.append(f)
    return {"profiles": profiles, "divergent_fields": divergent}
