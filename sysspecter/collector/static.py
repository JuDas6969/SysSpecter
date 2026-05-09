"""Static system snapshot at run start.

Collects hardware/OS/BIOS/security/network context once. Subprocess-based —
each call wrapped so a single failure does not abort the full snapshot."""

from __future__ import annotations

import logging
import platform
import socket
from typing import Any

import psutil

from ..winutil import run_cmd, run_ps_json


def _wmi_query(query: str, props: list[str], logger: logging.Logger | None) -> list[dict[str, Any]]:
    props_expr = ", ".join(props)
    cmd = f"Get-CimInstance -ClassName {query} | Select-Object {props_expr}"
    result = run_ps_json(cmd, timeout=15.0, logger=logger)
    if result is None:
        return []
    if isinstance(result, dict):
        return [result]
    return list(result)


def _os_info(logger: logging.Logger | None) -> dict[str, Any]:
    data = _wmi_query(
        "Win32_OperatingSystem",
        ["Caption", "Version", "BuildNumber", "OSArchitecture", "InstallDate", "LastBootUpTime"],
        logger,
    )
    base = data[0] if data else {}
    return {
        "caption": base.get("Caption"),
        "version": base.get("Version"),
        "build": base.get("BuildNumber"),
        "architecture": base.get("OSArchitecture"),
        "install_date": base.get("InstallDate"),
        "last_boot_up_time": base.get("LastBootUpTime"),
        "platform": platform.platform(),
        "boot_time_epoch": int(psutil.boot_time()),
        "uptime_seconds": int(psutil.time.time() - psutil.boot_time()) if hasattr(psutil, "time") else None,
    }


def _computer_system(logger: logging.Logger | None) -> dict[str, Any]:
    data = _wmi_query(
        "Win32_ComputerSystem",
        ["Manufacturer", "Model", "SystemType", "TotalPhysicalMemory", "NumberOfLogicalProcessors",
         "NumberOfProcessors", "DomainRole", "PartOfDomain"],
        logger,
    )
    return data[0] if data else {}


def _bios(logger: logging.Logger | None) -> dict[str, Any]:
    data = _wmi_query(
        "Win32_BIOS",
        ["Manufacturer", "SMBIOSBIOSVersion", "Version", "ReleaseDate", "SerialNumber"],
        logger,
    )
    return data[0] if data else {}


def _baseboard(logger: logging.Logger | None) -> dict[str, Any]:
    data = _wmi_query(
        "Win32_BaseBoard",
        ["Manufacturer", "Product", "Version", "SerialNumber"],
        logger,
    )
    return data[0] if data else {}


def _cpu(logger: logging.Logger | None) -> dict[str, Any]:
    data = _wmi_query(
        "Win32_Processor",
        ["Name", "NumberOfCores", "NumberOfLogicalProcessors", "MaxClockSpeed", "CurrentClockSpeed",
         "Architecture", "Manufacturer", "L2CacheSize", "L3CacheSize"],
        logger,
    )
    try:
        freq = psutil.cpu_freq()
        freq_info = {"current_mhz": freq.current, "min_mhz": freq.min, "max_mhz": freq.max} if freq else {}
    except Exception:
        if logger:
            logger.debug("cpu_freq unavailable", exc_info=True)
        freq_info = {}
    return {
        "cpus": data,
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "frequency": freq_info,
    }


def _memory(logger: logging.Logger | None) -> dict[str, Any]:
    vm = psutil.virtual_memory()
    sm = psutil.swap_memory()
    modules = _wmi_query(
        "Win32_PhysicalMemory",
        ["Capacity", "Speed", "ConfiguredClockSpeed", "Manufacturer", "PartNumber", "FormFactor",
         "MemoryType", "DeviceLocator"],
        logger,
    )
    return {
        "total_bytes": vm.total,
        "available_bytes": vm.available,
        "used_bytes": vm.used,
        "percent": vm.percent,
        "swap_total_bytes": sm.total,
        "swap_used_bytes": sm.used,
        "swap_percent": sm.percent,
        "modules": modules,
    }


def _physical_disks_storage_namespace(
    logger: logging.Logger | None,
) -> list[dict[str, Any]]:
    """v1.3.0 B.4: query the modern Storage WMI namespace
    (`Get-PhysicalDisk`) for ground-truth `MediaType` (SSD / HDD /
    Unspecified) and `BusType` (NVMe / SATA / SAS / USB / …). The
    legacy `Win32_DiskDrive.MediaType` returns "Fixed hard disk" for
    every internal disk including NVMes — useless for tier
    classification. The new namespace correctly distinguishes 4
    (HDD) / 3 (SSD), and BusType=17 (NVMe) is unambiguous.

    Returns a list of dicts with the raw values; the classifier
    (`comparer/diagnosis.classify_disk_tier`) consumes them. Empty
    list when PowerShell / WMI is unreachable; the caller falls back
    to the legacy classification path.
    """
    cmd = (
        "Get-PhysicalDisk | "
        "Select-Object DeviceId, FriendlyName, MediaType, BusType, "
        "Size, SerialNumber"
    )
    result = run_ps_json(cmd, timeout=15.0, logger=logger)
    if result is None:
        return []
    if isinstance(result, dict):
        result = [result]
    out: list[dict[str, Any]] = []
    # Numeric -> string mappings for the values PowerShell sometimes
    # returns as enums and sometimes as ints depending on host build.
    media_type_map = {
        0: "Unspecified", 3: "HDD", 4: "SSD", 5: "SCM",
    }
    bus_type_map = {
        0: "Unknown", 1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "1394",
        5: "SSA", 6: "Fibre Channel", 7: "USB", 8: "RAID", 9: "iSCSI",
        10: "SAS", 11: "SATA", 12: "SD", 13: "MMC", 14: "Virtual",
        15: "FileBackedVirtual", 16: "Storage Spaces", 17: "NVMe",
        18: "Microsoft Reserved",
    }
    for r in result:
        mt = r.get("MediaType")
        bt = r.get("BusType")
        # PowerShell returns these as int-like or already-string;
        # canonicalise to strings.
        if isinstance(mt, int):
            mt = media_type_map.get(mt, str(mt))
        if isinstance(bt, int):
            bt = bus_type_map.get(bt, str(bt))
        out.append({
            "DeviceId": r.get("DeviceId"),
            "FriendlyName": r.get("FriendlyName"),
            "MediaType": mt,
            "BusType": bt,
            "Size": r.get("Size"),
            "SerialNumber": r.get("SerialNumber"),
        })
    return out


def _disks(logger: logging.Logger | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for part in psutil.disk_partitions(all=False):
        usage = None
        try:
            u = psutil.disk_usage(part.mountpoint)
            usage = {"total": u.total, "used": u.used, "free": u.free, "percent": u.percent}
        except Exception:
            pass
        out.append({
            "device": part.device,
            "mountpoint": part.mountpoint,
            "fstype": part.fstype,
            "opts": part.opts,
            "usage": usage,
        })
    # Legacy Win32_DiskDrive — kept for back-compat; the classifier
    # consults the storage-namespace fields first.
    physical = _wmi_query(
        "Win32_DiskDrive",
        ["Model", "Size", "MediaType", "InterfaceType", "SerialNumber"],
        logger,
    )
    # v1.3.0 B.4: enrich each physical-drive record with ground-truth
    # MediaType + BusType from the modern Storage namespace. We match
    # by Model name when possible — Win32_DiskDrive's model is the
    # same string Get-PhysicalDisk returns as FriendlyName.
    storage_disks = _physical_disks_storage_namespace(logger)
    by_friendly = {
        (d.get("FriendlyName") or "").strip(): d
        for d in storage_disks
        if d.get("FriendlyName")
    }
    for p in physical:
        rec: dict[str, Any] = dict(p)
        model = (p.get("Model") or "").strip()
        match = by_friendly.get(model)
        if match:
            rec["StorageMediaType"] = match.get("MediaType")
            rec["StorageBusType"] = match.get("BusType")
        out.append({"_physical_drive": rec})
    # If WMI Win32_DiskDrive failed but Get-PhysicalDisk worked,
    # surface the storage-namespace records on their own so we still
    # have something to classify on.
    if not physical and storage_disks:
        for d in storage_disks:
            out.append({"_physical_drive": {
                "Model": d.get("FriendlyName"),
                "Size": d.get("Size"),
                "SerialNumber": d.get("SerialNumber"),
                "StorageMediaType": d.get("MediaType"),
                "StorageBusType": d.get("BusType"),
            }})
    return out


def _gpus(logger: logging.Logger | None) -> list[dict[str, Any]]:
    return _wmi_query(
        "Win32_VideoController",
        ["Name", "DriverVersion", "AdapterRAM", "VideoProcessor", "CurrentHorizontalResolution",
         "CurrentVerticalResolution", "Status"],
        logger,
    )


def _network(logger: logging.Logger | None) -> dict[str, Any]:
    adapters: list[dict[str, Any]] = []
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
    except Exception as e:
        if logger:
            logger.warning("psutil net_if failed: %s", e)
        stats, addrs = {}, {}
    for name, st in stats.items():
        addr_list = [{"family": str(a.family), "address": a.address, "netmask": a.netmask}
                     for a in addrs.get(name, [])]
        adapters.append({
            "name": name,
            "isup": st.isup,
            "speed_mbps": st.speed,
            "mtu": st.mtu,
            "duplex": str(st.duplex),
            "addresses": addr_list,
        })

    wmi_adapters = _wmi_query(
        "Win32_NetworkAdapter",
        ["Name", "NetConnectionID", "MACAddress", "AdapterType", "PhysicalAdapter", "Speed",
         "NetEnabled", "Manufacturer", "ServiceName"],
        logger,
    )

    vpn_hits: list[str] = []
    vpn_markers = ("vpn", "tap-", "tap0901", "wintun", "anyconnect", "globalprotect",
                   "zscaler", "openvpn", "wireguard", "netextender", "pulse", "checkpoint")
    for a in wmi_adapters:
        name = (a.get("Name") or "").lower()
        if any(m in name for m in vpn_markers):
            vpn_hits.append(a.get("Name"))
    for a in adapters:
        name = (a["name"] or "").lower()
        if any(m in name for m in vpn_markers):
            vpn_hits.append(a["name"])

    ipconfig = run_cmd(["ipconfig", "/all"], timeout=10.0, logger=logger)
    route = run_cmd(["route", "print"], timeout=10.0, logger=logger)
    return {
        "adapters_psutil": adapters,
        "adapters_wmi": wmi_adapters,
        "vpn_suspect_adapters": sorted(set(vpn_hits)),
        "ipconfig_all": ipconfig,
        "route_print": route,
    }


def _security(logger: logging.Logger | None) -> dict[str, Any]:
    defender = run_ps_json(
        "Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, "
        "AntispywareEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, "
        "IoavProtectionEnabled, NISEnabled, OnAccessProtectionEnabled, "
        "AMEngineVersion, AMProductVersion, AntivirusSignatureVersion, "
        "QuickScanStartTime, FullScanStartTime",
        timeout=20.0, logger=logger,
    )
    prefs = run_ps_json(
        "Get-MpPreference | Select-Object DisableRealtimeMonitoring, ExclusionPath, ExclusionProcess",
        timeout=20.0, logger=logger,
    )
    av_product = run_ps_json(
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
        "Select-Object displayName, productState, pathToSignedReportingExe",
        timeout=15.0, logger=logger,
    )
    firewall = run_ps_json(
        "Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction",
        timeout=15.0, logger=logger,
    )
    return {
        "defender_status": defender,
        "defender_preferences": prefs,
        "antivirus_products": av_product,
        "firewall_profiles": firewall,
    }


def _power(logger: logging.Logger | None) -> dict[str, Any]:
    plan = run_cmd(["powercfg", "/getactivescheme"], timeout=10.0, logger=logger)
    return {"active_scheme_raw": plan.strip() if plan else None}


def collect_static_snapshot(logger: logging.Logger | None = None) -> dict[str, Any]:
    snap: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "os": _os_info(logger),
        "computer_system": _computer_system(logger),
        "bios": _bios(logger),
        "baseboard": _baseboard(logger),
        "cpu": _cpu(logger),
        "memory": _memory(logger),
        "disks": _disks(logger),
        "gpus": _gpus(logger),
        "network": _network(logger),
        "security": _security(logger),
        "power": _power(logger),
    }
    return snap


def collect_installed_programs(logger: logging.Logger | None = None) -> list[dict[str, Any]]:
    cmd = (
        "$paths = @('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', "
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', "
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); "
        "Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName } | "
        "Select-Object DisplayName, DisplayVersion, Publisher, InstallDate"
    )
    result = run_ps_json(cmd, timeout=30.0, logger=logger)
    if result is None:
        return []
    if isinstance(result, dict):
        return [result]
    return list(result)


def collect_autoruns(logger: logging.Logger | None = None) -> list[dict[str, Any]]:
    cmd = (
        "Get-CimInstance Win32_StartupCommand | "
        "Select-Object Name, Command, Location, User"
    )
    result = run_ps_json(cmd, timeout=20.0, logger=logger)
    if result is None:
        return []
    if isinstance(result, dict):
        return [result]
    return list(result)


def collect_scheduled_tasks_summary(logger: logging.Logger | None = None) -> dict[str, Any]:
    cmd = (
        "$t = Get-ScheduledTask -ErrorAction SilentlyContinue; "
        "$grouped = $t | Group-Object -Property State | Select-Object Name, Count; "
        "[pscustomobject]@{Total=@($t).Count; ByState=$grouped}"
    )
    result = run_ps_json(cmd, timeout=30.0, logger=logger)
    return result or {}


def collect_process_tree_snapshot() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    attrs = ["pid", "ppid", "name", "username", "create_time", "exe", "cmdline",
             "num_threads", "num_handles"]
    for p in psutil.process_iter(attrs=attrs):
        try:
            info = p.info
            out.append({
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "username": info.get("username"),
                "create_time": info.get("create_time"),
                "exe": info.get("exe"),
                "cmdline": " ".join(info.get("cmdline") or []),
                "num_threads": info.get("num_threads"),
                "num_handles": info.get("num_handles"),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return out


def collect_service_snapshot(logger: logging.Logger | None = None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        for s in psutil.win_service_iter():
            try:
                info = s.as_dict()
                out.append({
                    "name": info.get("name"),
                    "display_name": info.get("display_name"),
                    "status": info.get("status"),
                    "start_type": info.get("start_type"),
                    "pid": info.get("pid"),
                    "binpath": info.get("binpath"),
                    "username": info.get("username"),
                })
            except Exception:
                continue
    except Exception as e:
        if logger:
            logger.warning("win_service_iter failed: %s", e)
    return out
