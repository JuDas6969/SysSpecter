"""Tests for the compare-tool diff functions + rule engine."""

from __future__ import annotations

from types import SimpleNamespace

from sysspecter.comparer.diagnosis import (
    bottleneck_comparison,
    classify_disk_tier,
    generate_hypotheses,
    generate_recommendations,
)
from sysspecter.comparer.mode import detect_mode, mode_label
from sysspecter.comparer.static_diff import (
    diff_autoruns,
    diff_config,
    diff_hardware,
    diff_software,
)


def _run(rid: str, host: str, static: dict | None = None) -> dict:
    return {
        "manifest": {"run_id": rid, "hostname": host},
        "rd": SimpleNamespace(static=static or {}),
    }


# ---------------------------------------------------------------- mode detection


def test_mode_all_same_host_is_before_after() -> None:
    runs = [_run("A", "PC1"), _run("B", "PC1"), _run("C", "PC1")]
    assert detect_mode(runs) == "before_after"


def test_mode_two_distinct_hosts_is_pair() -> None:
    runs = [_run("A", "PC1"), _run("B", "PC2")]
    assert detect_mode(runs) == "pair_diagnosis"


def test_mode_three_hosts_is_fleet() -> None:
    runs = [_run("A", "PC1"), _run("B", "PC2"), _run("C", "PC3")]
    assert detect_mode(runs) == "fleet"


def test_mode_is_case_insensitive() -> None:
    runs = [_run("A", "pc1"), _run("B", "PC1")]
    assert detect_mode(runs) == "before_after"


def test_mode_label_present_for_every_mode() -> None:
    assert mode_label("before_after")
    assert mode_label("pair_diagnosis")
    assert mode_label("fleet")


# ---------------------------------------------------------------- disk tier


def test_classify_disk_tier_nvme_samsung_980_pro() -> None:
    """v1.3.0 B.4: tier values are lowercase. NVMe model heuristic
    still works (the legacy fallback path)."""
    disk = {"Model": "Samsung 980 Pro 1TB", "MediaType": "SSD", "InterfaceType": "SCSI"}
    assert classify_disk_tier(disk) == "nvme"


def test_classify_disk_tier_hdd() -> None:
    """v1.3.0 B.4: HDD media-type still classifies via the legacy path
    when StorageMediaType isn't supplied."""
    disk = {"Model": "ST1000LM035", "MediaType": "Fixed hard disk media",
            "InterfaceType": "SCSI"}
    assert classify_disk_tier(disk) == "hdd"


def test_classify_disk_tier_ssd() -> None:
    disk = {"Model": "Samsung SSD 870 EVO 500GB", "MediaType": "SSD", "InterfaceType": "SCSI"}
    assert classify_disk_tier(disk) == "ssd"


def test_classify_disk_tier_storage_namespace_nvme() -> None:
    """v1.3.0 B.4: when Get-PhysicalDisk supplies BusType=NVMe, that's
    ground truth — overrides any model-name heuristic guess."""
    disk = {
        "Model": "GenericModel SSD 1TB",
        "MediaType": "SSD",
        "StorageMediaType": "SSD",
        "StorageBusType": "NVMe",
    }
    assert classify_disk_tier(disk) == "nvme"


def test_classify_disk_tier_storage_namespace_unspecified_does_not_default_to_hdd() -> None:
    """v1.3.0 B.4: when StorageMediaType is Unspecified AND the model
    has no markers, return `unknown` — never silently default to HDD.
    This is the v1.2 MORGANA bug the plan called out."""
    disk = {
        "Model": "Some Generic Disk",
        "MediaType": "Unspecified",
        "StorageMediaType": "Unspecified",
        "StorageBusType": "SATA",
    }
    assert classify_disk_tier(disk) == "unknown"


def test_classify_disk_tier_unknown_on_empty() -> None:
    assert classify_disk_tier(None) == "unknown"
    assert classify_disk_tier({"Model": "", "MediaType": ""}) == "unknown"


# ---------------------------------------------------------------- static diffs


def _hw_run(rid: str, host: str, **hw) -> dict:
    static = {
        "cpu": {"cpus": [{"Name": hw.get("cpu_name", "i5"),
                          "NumberOfCores": hw.get("cores", 4),
                          "NumberOfLogicalProcessors": hw.get("threads", 8),
                          "MaxClockSpeed": hw.get("mhz", 2400)}]},
        "memory": {"total_bytes": hw.get("ram_bytes", 8 * 1024**3),
                   "modules": []},
        "disks": [{"_physical_drive": {
            "Model": hw.get("disk_model", "ST1000"),
            "MediaType": hw.get("disk_media", "HDD"),
            "Size": hw.get("disk_size", 1000 * 1024**3),
            "SerialNumber": hw.get("disk_serial", "SN001"),
        }}],
        "gpus": [], "bios": {"SMBIOSBIOSVersion": hw.get("bios", "1.0"),
                             "ReleaseDate": "2024-01-01"},
        "baseboard": {"SerialNumber": "BB001"},
        "computer_system": {"Manufacturer": "Dell", "Model": "Latitude"},
        "os": {"caption": "Windows 10", "build": "19044"},
        "security": {"defender_status": {
            "RealTimeProtectionEnabled": True,
            "AntivirusEnabled": True,
            "AntivirusSignatureVersion": hw.get("sig", "1.0"),
        }, "antivirus_products": [{"displayName": "Defender"}]},
        "power": {"active_scheme_raw": hw.get("power", "(Balanced) *")},
        "network": {"vpn_suspect_adapters": []},
        "installed_programs": hw.get("programs", []),
        "autoruns": hw.get("autoruns", []),
    }
    return {"manifest": {"run_id": rid, "hostname": host},
            "rd": SimpleNamespace(static=static)}


def test_diff_hardware_flags_ram_difference() -> None:
    a = _hw_run("A", "PC1", ram_bytes=8 * 1024**3)
    b = _hw_run("B", "PC2", ram_bytes=32 * 1024**3)
    diff = diff_hardware([a, b])
    assert "ram_gb" in diff["divergent_fields"]
    profiles = diff["profiles"]
    assert profiles[0]["ram_gb"] == 8.0
    assert profiles[1]["ram_gb"] == 32.0


def test_diff_software_detects_only_in_a() -> None:
    a = _hw_run("A", "PC1",
                programs=[{"DisplayName": "Chrome", "DisplayVersion": "120"},
                          {"DisplayName": "OnlyOnA"}])
    b = _hw_run("B", "PC2",
                programs=[{"DisplayName": "Chrome", "DisplayVersion": "120"}])
    diff = diff_software([a, b])
    pair = diff["pairwise"][0]
    assert pair["only_in_a_total"] == 1
    assert "OnlyOnA" in pair["only_in_a"]


def test_diff_software_detects_version_change() -> None:
    a = _hw_run("A", "PC1",
                programs=[{"DisplayName": "Chrome", "DisplayVersion": "120"}])
    b = _hw_run("B", "PC2",
                programs=[{"DisplayName": "Chrome", "DisplayVersion": "121"}])
    diff = diff_software([a, b])
    pair = diff["pairwise"][0]
    assert pair["version_changed_total"] == 1
    assert pair["version_changed"][0]["name"] == "Chrome"


def test_diff_autoruns_only_in_a() -> None:
    a = _hw_run("A", "PC1", autoruns=[{"Name": "Steam", "Command": "s.exe"},
                                       {"Name": "OnlyA", "Command": "a.exe"}])
    b = _hw_run("B", "PC2", autoruns=[{"Name": "Steam", "Command": "s.exe"}])
    diff = diff_autoruns([a, b])
    assert diff["pairwise"][0]["only_in_a_total"] == 1


def test_diff_config_flags_divergent_power_plan() -> None:
    a = _hw_run("A", "PC1", power="(Balanced) *")
    b = _hw_run("B", "PC2", power="(High performance) *")
    diff = diff_config([a, b])
    assert "power_plan" in diff["divergent_fields"]


# ---------------------------------------------------------------- diagnosis rules


def test_disk_tier_rule_fires_hdd_vs_nvme() -> None:
    a = _hw_run("A", "PC1", disk_model="ST1000LM035", disk_media="Fixed hard disk")
    b = _hw_run("B", "PC2", disk_model="Samsung 980 Pro", disk_media="SSD")
    matrix = {"rows": [
        {"run_id": "A", "primary": "disk", "overall": 50, "disk_avg": 85,
         "efficiency": 40, "cpu_avg": 20, "mem_avg": 30, "security": 70},
        {"run_id": "B", "primary": "cpu", "overall": 80, "disk_avg": 10,
         "efficiency": 70, "cpu_avg": 30, "mem_avg": 30, "security": 80},
    ]}
    hd = diff_hardware([a, b])
    sd = diff_software([a, b])
    cd = diff_config([a, b])
    hyps = generate_hypotheses([a, b], matrix, hd, sd, cd)
    categories = {h["category"] for h in hyps}
    assert "disk" in categories


def test_ram_rule_fires_when_a_has_less_ram_and_mem_pressure() -> None:
    a = _hw_run("A", "PC1", ram_bytes=8 * 1024**3)
    b = _hw_run("B", "PC2", ram_bytes=32 * 1024**3)
    matrix = {"rows": [
        {"run_id": "A", "primary": "memory", "overall": 45,
         "mem_avg": 90, "disk_avg": 10, "efficiency": 50, "security": 80, "cpu_avg": 30},
        {"run_id": "B", "primary": "cpu", "overall": 80,
         "mem_avg": 30, "disk_avg": 10, "efficiency": 70, "security": 80, "cpu_avg": 30},
    ]}
    hd = diff_hardware([a, b])
    hyps = generate_hypotheses([a, b], matrix, hd,
                               diff_software([a, b]), diff_config([a, b]))
    assert any(h["category"] == "memory" for h in hyps)


def test_recommendations_dedupe_per_run_category() -> None:
    hyps = [
        {"run_id": "A", "category": "disk", "severity": "high",
         "hypothesis": "h1", "recommendation": "r1", "evidence": []},
        {"run_id": "A", "category": "disk", "severity": "medium",
         "hypothesis": "h2", "recommendation": "r2", "evidence": []},
    ]
    recs = generate_recommendations(hyps)
    # should keep only the higher severity one
    assert len(recs) == 1
    assert recs[0]["severity"] == "high"


def test_bottleneck_comparison_groups_by_primary() -> None:
    matrix = {"rows": [
        {"run_id": "A", "primary": "disk"},
        {"run_id": "B", "primary": "disk"},
        {"run_id": "C", "primary": "cpu"},
    ]}
    out = bottleneck_comparison(matrix)
    assert set(out["by_primary"]["disk"]) == {"A", "B"}
    assert out["by_primary"]["cpu"] == ["C"]
