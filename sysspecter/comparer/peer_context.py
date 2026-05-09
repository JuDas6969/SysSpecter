"""Cross-run peer-context awareness (v3-priority-3).

The v2 production review caught the engine making a confident causal
claim that didn't hold up: it attributed the 20-point efficiency gap
between ATLT4407 (HP EliteBook, 16 GB, 4 cores, corporate-managed)
and MORGANA (desktop, 64 GB, 16 cores, standalone) to "106 unused
software programs." Most of those programs weren't running. The real
gap was driven by RAM headroom, core count, and active workload —
none of which the engine surfaced.

This module addresses one half of the fix: surfacing when two runs
aren't actually peers in the first place. A corporate-managed laptop
and a personal desktop are not directly comparable on idle CPU; their
expected workload profiles differ. The other half — distinguishing
*installed* from *running* software — lives in `diagnosis.py`.

Public API:

    extract_machine_classes(loaded) -> [{"run_id", "machine_class", ...}]
    is_peer_mismatch(class_a, class_b) -> bool
    build_peer_mismatch_findings(loaded) -> list[dict]

The peer-mismatch finding has the same shape as other root-cause
hypotheses (`severity`, `category`, `run_id`, `peer_id`, `hypothesis`,
`evidence`, `recommendation`) so it slots into the existing report
template without bespoke handling.
"""

from __future__ import annotations

from typing import Any

# Workload-profile peer groups. Two runs in the same group are
# considered comparable; runs in different groups are non-peers and
# need a caveat. The "default" / "unknown" buckets are treated
# permissively — we don't want to spam findings on every legacy run
# that pre-dates the C3 machine_class field.
_PEER_GROUPS: dict[str, str] = {
    # Workstation tier — user-driven, bursty, foreground-heavy
    "developer-workstation": "workstation",
    "engineering-workstation": "workstation",
    "personal-desktop": "workstation",
    # Office tier — light, mostly idle, occasional bursts
    "general-knowledge-worker": "office",
    "personal-laptop": "office",
    # v1.3.0 B.2: enterprise-managed laptops behave like office tier
    # under user load but carry significant management-agent overhead.
    # They share the office peer-group for cross-host comparisons.
    "enterprise-managed-laptop": "office",
    # Single-app embedded
    "kiosk": "embedded",
    "factory-floor": "embedded",
    # Multi-user host
    "terminal-server": "terminal-server",
    # v1.3.0 B.2: dedicated server SKU.
    "server": "server",
}


def _normalise_class(c: str | None) -> str | None:
    """Normalise machine_class string. Mirrors machine_class_baselines.for_class
    aliases so the two stay consistent."""
    if not c or not isinstance(c, str):
        return None
    key = c.strip().lower()
    aliases = {
        "developer": "developer-workstation",
        "engineer": "engineering-workstation",
        "engineering": "engineering-workstation",
        "office": "general-knowledge-worker",
        "knowledge-worker": "general-knowledge-worker",
        "ts": "terminal-server",
        "rdp": "terminal-server",
        "citrix": "terminal-server",
        "plc": "factory-floor",
        "shop-floor": "factory-floor",
    }
    return aliases.get(key, key)


def _peer_group(c: str | None) -> str | None:
    norm = _normalise_class(c)
    if norm is None:
        return None
    return _PEER_GROUPS.get(norm)


def is_peer_mismatch(class_a: str | None, class_b: str | None) -> bool:
    """Return True iff `class_a` and `class_b` belong to different
    workload-profile peer groups.

    Either side being None / unknown returns False — we don't have
    enough information to claim mismatch and we don't want to spam
    findings on legacy runs.
    """
    ga = _peer_group(class_a)
    gb = _peer_group(class_b)
    if ga is None or gb is None:
        return False
    return ga != gb


# v1.3.0 B.2: corporate-domain markers used by the static-snapshot
# classifier. FQDN ending in any of these → likely enterprise-managed.
# Override-friendly: future iterations can read this from a YAML.
_CORPORATE_FQDN_SUFFIXES: tuple[str, ...] = (
    ".ktm.local", ".ktm.com", ".corp", ".intranet",
)

# Substrings in installed-program names that strongly suggest an
# enterprise EDR (not just AV). The presence of any of these marks
# the host as enterprise-managed.
_EDR_MARKERS: tuple[str, ...] = (
    "crowdstrike", "sentinelone", "cortex xdr", "cybereason",
    "carbon black", "trellix endpoint", "microsoft defender for endpoint",
    "tanium", "esetinspect", "mde", "msSense",
)

# Substrings that suggest an enterprise VPN / management agent.
_ENTERPRISE_VPN_MARKERS: tuple[str, ...] = (
    "cisco anyconnect", "globalprotect", "openvpn-gui",
    "netextender", "zscaler", "checkpoint", "fortinet vpn",
    "ivanti secure access", "pulse secure",
)

# Server SKU markers in the OS caption.
_SERVER_OS_MARKERS: tuple[str, ...] = (
    "server 2016", "server 2019", "server 2022", "server 2025",
    "windows server",
)

# Laptop chassis / model keywords. Combined with manufacturer string,
# distinguishes laptop from desktop SKUs from the same vendor.
_LAPTOP_KEYWORDS: tuple[str, ...] = (
    "elitebook", "thinkpad", "latitude", "yoga", "envy",
    "probook", "zbook", "spectre", "ideapad", "surface laptop",
    "surface book", "macbook", "expertbook",
)


def _has_any(haystack: str, needles: tuple[str, ...]) -> bool:
    h = (haystack or "").lower()
    return any(n in h for n in needles)


def _ram_class(total_bytes: int | None) -> str:
    """Bin RAM into the four buckets used by `peer_group`."""
    if not total_bytes:
        return "unknown"
    gb = total_bytes / (1024 ** 3)
    if gb <= 16:
        return "<=16GB"
    if gb <= 32:
        return "32GB"
    if gb <= 64:
        return "64GB"
    return ">=128GB"


def _cpu_thread_class(thread_count: int | None) -> str:
    if not thread_count or thread_count <= 0:
        return "unknown"
    if thread_count <= 8:
        return "<=8"
    if thread_count <= 16:
        return "<=16"
    if thread_count <= 32:
        return "<=32"
    return ">32"


def classify_from_static_snapshot(
    static: dict[str, Any] | None,
    manifest: dict[str, Any] | None,
) -> str:
    """v1.3.0 B.2: derive a `machine_class` from the static snapshot
    when the user did not pass `--machine-class` at capture time.

    Inputs (all optional; missing keys soft-degrade):
      - static.computer_system.{Manufacturer, Model}
      - static.os.caption
      - static.installed_programs (list of dicts with `name` keys)
      - static.network.adapters_psutil
      - static.security.{defender_status, defender_preferences,
        installed_security_products}
      - static.cpu (uses count for thread class)
      - static.memory.total_bytes (uses for ram class)
      - manifest.fqdn / hostname (for corporate-domain match)

    Returns one of:
      enterprise-managed-laptop, personal-laptop, personal-desktop,
      server, kiosk, unknown.
    """
    if not isinstance(static, dict):
        static = {}
    if not isinstance(manifest, dict):
        manifest = {}

    cs = static.get("computer_system") or {}
    os_block = static.get("os") or {}
    installed = static.get("installed_programs") or []
    security = static.get("security") or {}
    fqdn = (manifest.get("fqdn") or "").lower()

    # `cs.get("Manufacturer")` is intentionally read but currently
    # unused — kept here as a hook for future rules that key on the
    # OEM (e.g. distinguishing Surface Pro vs ThinkPad in the kiosk
    # path). Drop the binding to satisfy ruff F841.
    model = (cs.get("Model") or "").lower()
    os_caption = (os_block.get("caption") or "").lower()
    installed_names = [
        ((p.get("name") if isinstance(p, dict) else None) or "").lower()
        for p in installed if p
    ]
    installed_blob = " ".join(installed_names)

    # 1. Server SKU.
    if any(m in os_caption for m in _SERVER_OS_MARKERS):
        return "server"

    # 2. Enterprise-managed laptop. Must be:
    #    - laptop chassis / model
    #    - corporate FQDN OR EDR running
    #    - VPN client OR explicit corporate-domain
    is_laptop_form_factor = any(k in model for k in _LAPTOP_KEYWORDS)
    fqdn_is_corporate = any(fqdn.endswith(s) for s in _CORPORATE_FQDN_SUFFIXES)
    has_edr = (
        _has_any(installed_blob, _EDR_MARKERS)
        or _has_any(str(security.get("defender_status") or ""), _EDR_MARKERS)
    )
    has_vpn = _has_any(installed_blob, _ENTERPRISE_VPN_MARKERS)
    if is_laptop_form_factor and (fqdn_is_corporate or has_edr) and (has_vpn or fqdn_is_corporate):
        return "enterprise-managed-laptop"

    # 3. Personal laptop: laptop form factor, off-corporate-domain.
    if is_laptop_form_factor and not fqdn_is_corporate:
        return "personal-laptop"

    # 4. Personal desktop / workstation: desktop form factor, off-domain.
    desktop_markers = ("desktop", "tower", "workstation", "optiplex",
                       "precision", "studio", "imac", "mac pro")
    if (any(m in model for m in desktop_markers)
            and not fqdn_is_corporate):
        return "personal-desktop"

    # If the model is empty / unrecognised but we know it's NOT a
    # laptop AND it's not server: classify as personal-desktop when
    # the FQDN looks personal (e.g. just hostname with no domain).
    # v1.3.1 fix: read the canonical static-snapshot keys
    # (`logical_cores` set by static._cpu_info, `total_bytes` set by
    # static._memory) — the v1.3.0 classifier looked for `count` and
    # `LogicalProcessors` which don't exist, so MORGANA (off-domain
    # ASRock workstation, 64 GB / 32 threads) returned None.
    if not is_laptop_form_factor and not fqdn_is_corporate:
        # As a last-resort signal: machines with >= 32 GB RAM AND
        # >= 16 threads are typically workstations.
        try:
            ram_bytes = int((static.get("memory") or {}).get("total_bytes") or 0)
        except (TypeError, ValueError):
            ram_bytes = 0
        cpu_block = static.get("cpu") or {}
        # Canonical: static.cpu.logical_cores (psutil.cpu_count).
        # Fallback chain handles Win32_Processor records or older
        # snapshots that may have used different keys.
        thread_count = (
            cpu_block.get("logical_cores")
            or cpu_block.get("count")  # legacy / test-fixture key
            or (cpu_block.get("cpus") or [{}])[0].get("NumberOfLogicalProcessors")
            or (cpu_block.get("cpus") or [{}])[0].get("LogicalProcessors")
        )
        try:
            thread_count = int(thread_count or 0)
        except (TypeError, ValueError):
            thread_count = 0
        if ram_bytes >= 32 * 1024 ** 3 and thread_count >= 16:
            return "personal-desktop"
        # ASRock / MSI / Gigabyte / EVGA motherboards under desktop
        # CPUs (Ryzen 9, Core i7/i9 etc.) are also workstations even
        # when memory/threads don't quite hit the workstation floor.
        # Manufacturer is one of the desktop-board OEMs → personal-desktop.
        manufacturer = (cs.get("Manufacturer") or "").lower()
        desktop_oem_markers = (
            "asrock", "msi", "gigabyte", "evga", "asus motherboard",
        )
        if any(m in manufacturer for m in desktop_oem_markers):
            return "personal-desktop"

    return "unknown"


def _peer_group_from_class(
    machine_class: str | None,
    static: dict[str, Any] | None,
) -> str | None:
    """Build the `class:ram_class:thread_class` peer-group string."""
    if not machine_class or machine_class == "unknown":
        return None
    static = static or {}
    ram_bytes = ((static.get("memory") or {}).get("total_bytes")) or 0
    cpu_block = static.get("cpu") or {}
    # v1.3.1 fix: read static.cpu.logical_cores (psutil) before
    # the WMI fallback. Same reason as the classifier above —
    # `count` doesn't exist in real snapshots.
    thread_count = (
        cpu_block.get("logical_cores")
        or cpu_block.get("count")
        or (cpu_block.get("cpus") or [{}])[0].get("NumberOfLogicalProcessors")
        or (cpu_block.get("cpus") or [{}])[0].get("LogicalProcessors")
        or 0
    )
    try:
        thread_count = int(thread_count)
    except (TypeError, ValueError):
        thread_count = 0
    return (
        f"{machine_class}:{_ram_class(ram_bytes)}:{_cpu_thread_class(thread_count)}"
    )


def extract_machine_classes(loaded: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Lift `manifest.meta.machine_class` for every loaded run.

    v1.3.0 B.2: when the manifest doesn't carry an explicit
    `machine_class` (i.e. `--machine-class` was not passed at
    capture), fall through to `classify_from_static_snapshot` which
    derives the class from hardware + installed-programs + FQDN
    signals. The `peer_group` field is then a richer
    `class:ram:threads` string instead of just the class name.

    Output entry shape:
        {
            "run_id": str,
            "hostname": str | None,
            "machine_class": str | None,         # raw or derived
            "machine_class_normalised": str | None,
            "machine_class_source": "explicit" | "derived" | None,
            "peer_group": str | None,
        }
    """
    out: list[dict[str, Any]] = []
    for r in loaded:
        m = r.get("manifest") or {}
        meta = m.get("meta") or {}
        raw = meta.get("machine_class")
        source = "explicit" if raw else None
        if not raw:
            # v1.3.0 B.2: fall through to the static-snapshot classifier.
            rd = r.get("rd")
            static = getattr(rd, "static", None) if rd is not None else None
            derived = classify_from_static_snapshot(static, m)
            if derived and derived != "unknown":
                raw = derived
                source = "derived"
        normalised = _normalise_class(raw)
        # Peer group: bucket form (`workstation` / `office` / `embedded`
        # / `terminal-server`) drives the mismatch-warning logic so
        # different-SKU runs in the same workload class don't get
        # spurious "non-peer" findings. The rich
        # `class:ram:threads` form is exposed separately as
        # `peer_group_detailed` for the analyst to read in the report.
        rd = r.get("rd")
        static = getattr(rd, "static", None) if rd is not None else None
        bucket_group = _peer_group(normalised)
        rich_group = _peer_group_from_class(normalised, static)
        out.append({
            "run_id": m.get("run_id"),
            "hostname": m.get("hostname"),
            "machine_class": raw,
            "machine_class_normalised": normalised,
            "machine_class_source": source,
            "peer_group": bucket_group,
            "peer_group_detailed": rich_group,
        })
    return out


def build_peer_mismatch_findings(
    loaded: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Emit one finding per pair of runs whose machine_classes belong
    to different peer groups.

    Returns empty list when:
    - all runs share a peer group (the happy case)
    - no runs declare machine_class (legacy data, not enough signal)

    Finding severity is intentionally only `medium` — it's a context
    caveat, not an indictment of either run. The `confidence` field
    is `high` because the determination is rule-based on declared
    metadata, not statistical.
    """
    classes = extract_machine_classes(loaded)
    findings: list[dict[str, Any]] = []
    declared = [c for c in classes if c.get("peer_group") is not None]
    if len(declared) < 2:
        # Not enough machine_class declarations to claim mismatch.
        return findings

    seen_pairs: set[tuple[str, str]] = set()
    for i, a in enumerate(declared):
        for b in declared[i + 1:]:
            ga = a.get("peer_group")
            gb = b.get("peer_group")
            if ga == gb:
                continue
            # Canonicalise pair ordering so we don't double-emit.
            pair = tuple(sorted((a["run_id"] or "", b["run_id"] or "")))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            findings.append({
                "severity": "medium",
                "confidence": "high",
                "category": "peer_mismatch",
                "kind": "machine_class_mismatch",
                "run_id": a["run_id"],
                "peer_id": b["run_id"],
                "hypothesis": (
                    f"`{a['run_id']}` is declared as "
                    f"`{a.get('machine_class_normalised')}` (peer group "
                    f"`{ga}`) while `{b['run_id']}` is declared as "
                    f"`{b.get('machine_class_normalised')}` (peer group "
                    f"`{gb}`). These workload profiles differ; direct "
                    f"comparison of idle CPU, memory pressure, or "
                    f"latency may overstate real differences."
                ),
                "evidence": [
                    f"{a['run_id']} machine_class: {a.get('machine_class')} "
                    f"(normalised: {a.get('machine_class_normalised')})",
                    f"{b['run_id']} machine_class: {b.get('machine_class')} "
                    f"(normalised: {b.get('machine_class_normalised')})",
                    f"peer-group mismatch: `{ga}` vs `{gb}`",
                ],
                "recommendation": (
                    "Either compare like-for-like (same peer group) or "
                    "scope the comparison to metrics that are inherent to "
                    "the host's hardware (RAM, CPU model, disk tier) rather "
                    "than to its workload."
                ),
                "affected_metrics": sorted({
                    "cpu_avg", "mem_avg", "disk_avg", "latency_p95_ms",
                    "stability", "efficiency",
                }),
            })

    # If two or more runs lack machine_class entirely AND we did emit
    # at least one mismatch finding above, mention it once as a
    # data-completeness note. Useful for the report so the operator
    # knows why some runs aren't paired.
    undeclared = [c for c in classes if c.get("peer_group") is None and c.get("run_id")]
    if findings and len(undeclared) >= 1:
        findings.append({
            "severity": "low",
            "confidence": "high",
            "category": "peer_mismatch",
            "kind": "machine_class_undeclared",
            "run_id": undeclared[0]["run_id"],
            "peer_id": None,
            "hypothesis": (
                f"{len(undeclared)} run(s) did not declare a machine_class. "
                f"Peer-group inference for those runs is skipped — supply "
                f"`--machine-class` (or the meta.machine_class field) to "
                f"unlock cross-context warnings."
            ),
            "evidence": [
                f"undeclared: {', '.join(c['run_id'] for c in undeclared)}",
            ],
            "recommendation": (
                "Pass `--machine-class developer-workstation` (or the "
                "appropriate value) on next capture; defined classes: "
                "developer-workstation, engineering-workstation, "
                "general-knowledge-worker, kiosk, terminal-server, "
                "factory-floor."
            ),
            "affected_metrics": [],
        })

    return findings
