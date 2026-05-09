"""Evidence-based root-cause hypotheses and concrete recommendations.

Takes the hardware/software/config diffs plus the metric matrix and applies
independent heuristic rules. Each rule emits a structured record with
severity, category, hypothesis, evidence (why we think so), and a concrete
recommendation.

Rules are intentionally simple and cite concrete values (model names, RAM
sizes, power plan strings) so the output stays specific and auditable.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Disk tier classification
# ---------------------------------------------------------------------------

def classify_disk_tier(disk: dict[str, Any] | None) -> str:
    """Return "NVMe", "SSD", "HDD", or "unknown" for a physical-drive record."""
    if not disk:
        return "unknown"
    model = (disk.get("Model") or "").lower()
    media = (disk.get("MediaType") or "").lower()
    interface = (disk.get("InterfaceType") or "").lower()

    nvme_markers = ("nvme", "nvm express", "pm9a1", "980 pro", "990 pro", "p5", "sn850", "sn770",
                    "ssd 970", "ssd 960")
    if "nvme" in model or "nvme" in interface:
        return "NVMe"
    if any(m in model for m in nvme_markers):
        return "NVMe"

    ssd_markers = ("ssd", "solid state", "evo", "samsung 860", "samsung 870", "crucial mx",
                   "intel 660p", "micron")
    if "ssd" in media or "solid state" in media:
        return "SSD"
    if any(m in model for m in ssd_markers):
        return "SSD"

    hdd_markers = ("hdd", "hard", "wd blue", "wd black", "st500", "st1000", "st2000",
                   "barracuda", "hgst", "toshiba mq")
    if "hdd" in media or "hard" in media or "rotational" in media:
        return "HDD"
    if any(m in model for m in hdd_markers):
        return "HDD"

    return "unknown"


# ---------------------------------------------------------------------------
# Helper lookups
# ---------------------------------------------------------------------------

def _rows_by_id(matrix: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["run_id"]: r for r in (matrix.get("rows") or []) if r.get("run_id")}


def _hw_by_id(hw_diff: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {p["run_id"]: p for p in (hw_diff.get("profiles") or []) if p.get("run_id")}


def _cfg_by_id(cfg_diff: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {p["run_id"]: p for p in (cfg_diff.get("profiles") or []) if p.get("run_id")}


def _primary_disk_dict(run: dict[str, Any]) -> dict[str, Any] | None:
    static = (run.get("rd").static or {}) if run.get("rd") is not None else {}
    disks = static.get("disks") or []
    phys = [d.get("_physical_drive") for d in disks if isinstance(d, dict) and d.get("_physical_drive")]
    if not phys:
        return None
    def _size(d: dict[str, Any]) -> int:
        try:
            return int(d.get("Size") or 0)
        except (TypeError, ValueError):
            return 0
    return max(phys, key=_size)


def _score(matrix_row: dict[str, Any], key: str) -> float | None:
    v = matrix_row.get(key)
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _is_high_performance(plan: str | None) -> bool:
    if not plan:
        return False
    p = plan.lower()
    return ("high performance" in p or "höchstleistung" in p
            or "ultimate performance" in p or "ultimative leistung" in p)


def _running_process_names(run: dict[str, Any]) -> set[str]:
    """v3-priority-3: extract the set of process names that actually
    fired during this run (lowercased, stripped of `.exe`).

    Used by the software-bloat rule to distinguish *installed* programs
    from *running* ones — the v2 production review caught the engine
    blaming installed-but-dormant Adobe Reader / 7-Zip / Beyond Compare
    for an efficiency gap that was actually driven by RAM headroom and
    active workload.
    """
    rd = run.get("rd")
    if rd is None:
        return set()
    rows = getattr(rd, "process_rows", None) or []
    out: set[str] = set()
    for row in rows:
        name = row.get("name") if isinstance(row, dict) else None
        if not name:
            continue
        n = str(name).strip().lower()
        if n.endswith(".exe"):
            n = n[:-4]
        out.add(n)
    return out


def _running_overlap(installed: list[str], running: set[str]) -> list[str]:
    """Return installed-program names that have a matching running-
    process name (case-insensitive, ignoring `.exe`).

    Match is liberal — a process name like `Adobe.Acrobat.Reader` and
    an installed program `Adobe Acrobat Reader` will match by token
    overlap. This is the right side of the precision/recall tradeoff
    here: false-negatives (missing a real match) silently lose us
    evidence; false-positives (matching loosely) produce one fewer
    spurious "installed but not running" claim.
    """
    if not installed or not running:
        return []
    out: list[str] = []
    for prog in installed:
        if not prog:
            continue
        prog_lower = str(prog).lower()
        # Exact name match first
        for tok in (prog_lower, prog_lower.replace(" ", ""), prog_lower.split()[0]):
            if tok in running:
                out.append(prog)
                break
        else:
            # Token-overlap fallback for multi-word program names like
            # "Microsoft Edge" matching process "msedge".
            tokens = {t for t in prog_lower.replace("-", " ").split() if len(t) >= 4}
            if tokens and any(rn in tokens or any(t in rn for t in tokens) for rn in running):
                out.append(prog)
    return out


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

def generate_hypotheses(
    runs: list[dict[str, Any]],
    matrix: dict[str, Any],
    hw_diff: dict[str, Any],
    sw_diff: dict[str, Any],
    cfg_diff: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return a list of hypothesis records.

    Each record:
      {
        "severity": "high" | "medium" | "low",
        "category": "disk" | "memory" | "cpu" | "software" | "security" | "power" | "regression",
        "run_id": "<the run the issue applies to>",
        "peer_id": "<reference/better run>",
        "hypothesis": "...",
        "evidence": ["...", "..."],
        "recommendation": "...",
      }
    """
    out: list[dict[str, Any]] = []
    rows = _rows_by_id(matrix)
    hws = _hw_by_id(hw_diff)
    cfgs = _cfg_by_id(cfg_diff)
    runs_by_id = {(r.get("manifest") or {}).get("run_id"): r for r in runs
                  if (r.get("manifest") or {}).get("run_id")}

    disk_tier_cache: dict[str, str] = {}
    for rid, r in runs_by_id.items():
        disk_tier_cache[rid] = classify_disk_tier(_primary_disk_dict(r))

    ids = [rid for rid in runs_by_id.keys() if rid in rows]

    # Build all ordered pairs so each run can be "slower" vs a peer.
    for a in ids:
        for b in ids:
            if a == b:
                continue
            ra, rb = rows[a], rows[b]
            ha, hb = hws.get(a) or {}, hws.get(b) or {}
            ca, cb = cfgs.get(a) or {}, cfgs.get(b) or {}

            # --- Disk tier rule
            if ra.get("primary") == "disk":
                tier_a = disk_tier_cache.get(a, "unknown")
                tier_b = disk_tier_cache.get(b, "unknown")
                if tier_a == "HDD" and tier_b in ("SSD", "NVMe"):
                    out.append({
                        "severity": "high",
                        # v3-priority-3: high confidence — disk-tier delta is
                        # a strong, well-documented mechanism for IO-bound
                        # workloads. The classifier reads media/interface
                        # strings directly from WMI, no inference.
                        "confidence": "high",
                        "category": "disk",
                        "kind": "disk_tier_mechanical",
                        "run_id": a,
                        "peer_id": b,
                        "hypothesis": f"{a} is disk-bound and runs on a mechanical HDD "
                                      f"while {b} has a {tier_b}.",
                        "evidence": [
                            f"{a} disk model: {ha.get('primary_disk_model') or '—'} "
                            f"({ha.get('primary_disk_media') or '?'}/{ha.get('primary_disk_interface') or '?'})",
                            f"{b} disk model: {hb.get('primary_disk_model') or '—'}",
                            f"{a} disk_avg: {ra.get('disk_avg')}% vs {b} disk_avg: {rb.get('disk_avg')}%",
                            f"primary_bottleneck on {a}: {ra.get('primary')}",
                        ],
                        "recommendation": (
                            f"Replace the HDD in {a} with a comparable {tier_b} "
                            f"(reference: {hb.get('primary_disk_model') or tier_b})."
                        ),
                    })

            # --- Memory / RAM capacity rule
            a_mem = ra.get("mem_avg") or 0
            ram_a = ha.get("ram_gb") or 0
            ram_b = hb.get("ram_gb") or 0
            if a_mem >= 80 and ram_a and ram_b and ram_a < ram_b:
                out.append({
                    "severity": "high",
                    # v3-priority-3: high — both sides are observed
                    # quantities (mem_avg from samples, RAM size from WMI).
                    # The "correlates with" wording in the hypothesis is
                    # already conservative.
                    "confidence": "high",
                    "category": "memory",
                    "kind": "memory_pressure_smaller_ram",
                    "run_id": a,
                    "peer_id": b,
                    "hypothesis": f"Memory pressure on {a} correlates with smaller RAM than {b}.",
                    "evidence": [
                        f"{a} mem_avg: {a_mem}%",
                        f"{a} RAM: {ram_a} GB vs {b} RAM: {ram_b} GB",
                    ],
                    "recommendation": (
                        f"Upgrade RAM in {a} from {ram_a} GB to at least {ram_b} GB."
                    ),
                })

            # --- CPU model / clock rule (only fire once per pair ordering when CPU-bound)
            cpu_a_mhz = ha.get("cpu_max_mhz") or 0
            cpu_b_mhz = hb.get("cpu_max_mhz") or 0
            if ra.get("primary") == "cpu" and cpu_a_mhz and cpu_b_mhz and cpu_b_mhz - cpu_a_mhz >= 400:
                out.append({
                    "severity": "medium",
                    # v3-priority-3: medium — clock-speed delta is real but
                    # IPC differences and core-count effects can dominate
                    # the actual CPU performance gap.
                    "confidence": "medium",
                    "category": "cpu",
                    "kind": "cpu_lower_clock",
                    "run_id": a,
                    "peer_id": b,
                    "hypothesis": f"{a} is CPU-bound and has a lower-clocked CPU than {b}.",
                    "evidence": [
                        f"{a} CPU: {ha.get('cpu_name') or '—'} @ {cpu_a_mhz} MHz",
                        f"{b} CPU: {hb.get('cpu_name') or '—'} @ {cpu_b_mhz} MHz",
                        f"{a} cpu_avg: {ra.get('cpu_avg')}%",
                    ],
                    "recommendation": (
                        f"Consider upgrading the CPU in {a} or reducing single-threaded peak "
                        f"load; CPU class lags {b} by {cpu_b_mhz - cpu_a_mhz} MHz."
                    ),
                })

            # --- Power plan rule
            if ra.get("primary") == "cpu" and not _is_high_performance(ca.get("power_plan")) \
                    and _is_high_performance(cb.get("power_plan")):
                out.append({
                    "severity": "medium",
                    # v3-priority-3: medium — power-plan does affect P-state
                    # selection but the actual CPU gap depends on workload
                    # type (CPU-bound benefits more than IO-bound).
                    "confidence": "medium",
                    "category": "power",
                    "kind": "non_high_performance_plan",
                    "run_id": a,
                    "peer_id": b,
                    "hypothesis": f"{a} is CPU-bound but does not use a High-Performance power plan.",
                    "evidence": [
                        f"{a} power plan: {ca.get('power_plan') or '—'}",
                        f"{b} power plan: {cb.get('power_plan') or '—'}",
                        f"{a} cpu_avg: {ra.get('cpu_avg')}%",
                    ],
                    "recommendation": (
                        f"Switch {a}'s power plan to 'High performance' / 'Höchstleistung' "
                        f"and re-measure."
                    ),
                })

            # --- AV / security overlap rule
            sec_a = _score(ra, "security")
            sec_b = _score(rb, "security")
            av_a = ca.get("av_product_count") or 0
            av_b = cb.get("av_product_count") or 0
            if sec_a is not None and sec_b is not None and sec_b - sec_a >= 10 and av_a > av_b:
                out.append({
                    "severity": "medium",
                    # v3-priority-3: medium — multiple AV products is a
                    # well-known mechanism for security-overhead spikes,
                    # but we don't observe per-product CPU here so we
                    # can't be high-confidence about which one dominates.
                    "confidence": "medium",
                    "category": "security",
                    "kind": "multiple_av_products",
                    "run_id": a,
                    "peer_id": b,
                    "hypothesis": f"{a} carries more AV products than {b}, which may overlap.",
                    "evidence": [
                        f"{a} AV products ({av_a}): {', '.join(ca.get('av_products') or []) or '—'}",
                        f"{b} AV products ({av_b}): {', '.join(cb.get('av_products') or []) or '—'}",
                        f"security score: {a}={sec_a:.0f} vs {b}={sec_b:.0f}",
                    ],
                    "recommendation": (
                        f"Remove overlapping AV products on {a}; keep one primary."
                    ),
                })

    # --- Software bloat rule per pair (un-ordered; software diff is symmetric)
    # v3-priority-3: tighten causal claims. The v2 production review caught
    # this rule attributing a 20-point efficiency gap to "106 unused
    # software programs" — most of which were installed-but-not-running
    # (Adobe Reader, 7-Zip, Beyond Compare). The fix: split installed
    # entries into actually-running vs installed-only, and:
    #   - fire a "medium" confidence finding only when the unique-to-A
    #     set has actually-running entries (real causal mechanism).
    #   - fire a "low" confidence candidate-factor finding when the diff
    #     is installed-only (correlation but no observed mechanism).
    # This keeps the engine helpful without overstating evidence.
    running_by_id: dict[str, set[str]] = {
        rid: _running_process_names(r) for rid, r in runs_by_id.items()
    }
    for pair_diff in (sw_diff.get("pairwise") or []):
        a, b = pair_diff["pair"]
        ra, rb = rows.get(a) or {}, rows.get(b) or {}
        eff_a = _score(ra, "efficiency")
        eff_b = _score(rb, "efficiency")
        if eff_a is None or eff_b is None:
            continue
        for src, dst, only_total_key, only_list_key in (
            (a, b, "only_in_a_total", "only_in_a"),
            (b, a, "only_in_b_total", "only_in_b"),
        ):
            if pair_diff.get(only_total_key, 0) < 10:
                continue
            eff_src = eff_a if src == a else eff_b
            eff_dst = eff_b if src == a else eff_a
            if eff_dst - eff_src < 5:
                continue
            installed_only_in_src = list(pair_diff.get(only_list_key) or [])
            running_overlap = _running_overlap(
                installed_only_in_src, running_by_id.get(src, set())
            )
            installed_count = pair_diff.get(only_total_key, 0)
            running_count = len(running_overlap)
            sample_running = running_overlap[:10]
            sample_installed = installed_only_in_src[:10]
            if running_count >= 1:
                # Real causal signal — at least one of the unique-to-src
                # programs was actively running and may have contributed
                # to the efficiency gap.
                out.append({
                    "severity": "medium",
                    "confidence": "medium",
                    "category": "software",
                    "kind": "running_software_delta",
                    "run_id": src,
                    "peer_id": dst,
                    "hypothesis": (
                        f"{src} ran {running_count} program(s) that "
                        f"{dst} did not — these may contribute to the "
                        f"efficiency gap (Δ {eff_dst - eff_src:.0f} pts)."
                    ),
                    "evidence": [
                        f"efficiency score: {src}={eff_src:.0f} vs {dst}={eff_dst:.0f}",
                        f"running-only-on-{src} sample: "
                        f"{', '.join(sample_running) or '—'}",
                        f"installed-only-on-{src} (broader set, "
                        f"{installed_count} entries): "
                        f"{', '.join(sample_installed) or '—'}",
                    ],
                    "recommendation": (
                        f"Investigate the actually-running programs first: "
                        f"{', '.join(sample_running)}. Installed-but-dormant "
                        f"entries don't consume resources unless launched."
                    ),
                })
            else:
                # No actually-running evidence — surface as a low-confidence
                # candidate factor rather than a confident cause.
                out.append({
                    "severity": "low",
                    "confidence": "low",
                    "category": "software",
                    "kind": "installed_software_delta_candidate",
                    "run_id": src,
                    "peer_id": dst,
                    "hypothesis": (
                        f"Candidate factor (low confidence): {src} carries "
                        f"{installed_count} installed programs that {dst} "
                        f"does not, but none were observed running during "
                        f"this capture. Direct causal claim is not supported."
                    ),
                    "evidence": [
                        f"efficiency score: {src}={eff_src:.0f} vs {dst}={eff_dst:.0f}",
                        f"installed-only-on-{src} sample: "
                        f"{', '.join(sample_installed) or '—'}",
                        "running-process overlap with installed-only set: 0",
                    ],
                    "recommendation": (
                        "Treat this as one of several plausible factors — RAM, "
                        "core count, and active workload typically dominate. "
                        "Re-capture with the suspected programs running to "
                        "test directly."
                    ),
                })

    return out


def bottleneck_comparison(matrix: dict[str, Any]) -> dict[str, Any]:
    """Summarise primary_bottleneck distribution across runs."""
    primaries: dict[str, list[str]] = {}
    for r in (matrix.get("rows") or []):
        p = r.get("primary") or "none"
        primaries.setdefault(p, []).append(r.get("run_id"))
    return {
        "by_primary": primaries,
        "unique_primary_classes": sorted(primaries.keys()),
    }


def generate_recommendations(hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse hypotheses into deduplicated recommendations per (run, category)."""
    bucket: dict[tuple[str, str], dict[str, Any]] = {}
    severity_rank = {"high": 3, "medium": 2, "low": 1}
    for h in hypotheses:
        key = (h.get("run_id") or "?", h.get("category") or "other")
        existing = bucket.get(key)
        if existing is None or severity_rank.get(h.get("severity"), 0) \
                > severity_rank.get(existing.get("severity"), 0):
            bucket[key] = {
                "run_id": h.get("run_id"),
                "category": h.get("category"),
                "severity": h.get("severity"),
                # v3-priority-3: carry confidence through so the
                # "Recommendations" section in the report can show
                # readers how strongly each one is grounded.
                "confidence": h.get("confidence") or "medium",
                "recommendation": h.get("recommendation"),
                "based_on": h.get("hypothesis"),
                "evidence": h.get("evidence") or [],
            }
    out = list(bucket.values())
    out.sort(key=lambda x: (-severity_rank.get(x.get("severity"), 0),
                            str(x.get("run_id") or "")))
    return out
