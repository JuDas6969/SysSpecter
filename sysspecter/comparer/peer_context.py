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
    # Office tier — light, mostly idle, occasional bursts
    "general-knowledge-worker": "office",
    # Single-app embedded
    "kiosk": "embedded",
    "factory-floor": "embedded",
    # Multi-user host
    "terminal-server": "terminal-server",
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


def extract_machine_classes(loaded: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Lift `manifest.meta.machine_class` for every loaded run.

    Output entry shape:
        {
            "run_id": str,
            "hostname": str | None,
            "machine_class": str | None,        # raw, as-supplied
            "machine_class_normalised": str | None,
            "peer_group": str | None,
        }
    """
    out: list[dict[str, Any]] = []
    for r in loaded:
        m = r.get("manifest") or {}
        meta = m.get("meta") or {}
        raw = meta.get("machine_class")
        out.append({
            "run_id": m.get("run_id"),
            "hostname": m.get("hostname"),
            "machine_class": raw,
            "machine_class_normalised": _normalise_class(raw),
            "peer_group": _peer_group(raw),
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
