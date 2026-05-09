"""v3-priority-3 (part 1): comparison-engine peer-context awareness.

The v2 production review caught the engine attributing the 20-point
ATLT4407↔MORGANA efficiency gap to "106 unused programs" — most of
which were installed-but-not-running. The actual gap was driven by
RAM headroom, core count, and active workload. The peer-context
module's job is to flag the simpler, declared mismatch first: a
corporate-managed laptop and a personal workstation aren't peers.

Tests pin:
- machine_class normalisation (tolerate aliases that mirror
  machine_class_baselines.for_class)
- peer-group classification (workstation / office / embedded /
  terminal-server)
- is_peer_mismatch logic (None-tolerant, group-based)
- build_peer_mismatch_findings emits one finding per non-peer pair
  + a low-severity completeness note when machine_class is undeclared
  on some runs
"""

from __future__ import annotations

from sysspecter.comparer.peer_context import (
    build_peer_mismatch_findings,
    extract_machine_classes,
    is_peer_mismatch,
)


def _run(run_id: str, *, machine_class: str | None = None,
         hostname: str | None = None) -> dict:
    """Build a minimal `loaded` entry shaped like comparer/loader output."""
    meta: dict = {}
    if machine_class is not None:
        meta["machine_class"] = machine_class
    return {
        "manifest": {
            "run_id": run_id,
            "hostname": hostname or run_id,
            "meta": meta,
        },
        "scores": {},
        "findings": {},
        "rd": None,
    }


# --- normalisation + peer-group classification ----------------------

def test_extract_machine_classes_lifts_meta_field() -> None:
    out = extract_machine_classes([
        _run("dev1", machine_class="developer-workstation"),
        _run("kiosk1", machine_class="kiosk"),
    ])
    assert out[0]["machine_class"] == "developer-workstation"
    assert out[0]["machine_class_normalised"] == "developer-workstation"
    assert out[0]["peer_group"] == "workstation"
    assert out[1]["peer_group"] == "embedded"


def test_extract_machine_classes_handles_alias() -> None:
    """`developer` and `engineering` are accepted aliases for full names."""
    out = extract_machine_classes([
        _run("a", machine_class="developer"),
        _run("b", machine_class="engineering"),
        _run("c", machine_class="office"),
    ])
    assert out[0]["machine_class_normalised"] == "developer-workstation"
    assert out[1]["machine_class_normalised"] == "engineering-workstation"
    assert out[2]["machine_class_normalised"] == "general-knowledge-worker"
    # All three: developer + engineering -> workstation; office -> office
    assert {o["peer_group"] for o in out} == {"workstation", "office"}


def test_extract_machine_classes_undeclared_is_none() -> None:
    out = extract_machine_classes([_run("legacy")])
    assert out[0]["machine_class"] is None
    assert out[0]["peer_group"] is None


def test_extract_machine_classes_unknown_class_no_peer_group() -> None:
    """An unrecognised class string is preserved but doesn't get a
    peer group — we don't want to invent groupings."""
    out = extract_machine_classes([_run("x", machine_class="custom-thing")])
    assert out[0]["machine_class"] == "custom-thing"
    assert out[0]["machine_class_normalised"] == "custom-thing"
    assert out[0]["peer_group"] is None


# --- is_peer_mismatch ----------------------------------------------

def test_is_peer_mismatch_same_group_returns_false() -> None:
    assert is_peer_mismatch("developer-workstation", "engineering-workstation") is False
    assert is_peer_mismatch("kiosk", "factory-floor") is False


def test_is_peer_mismatch_different_groups_returns_true() -> None:
    assert is_peer_mismatch("developer-workstation", "general-knowledge-worker") is True
    assert is_peer_mismatch("kiosk", "developer-workstation") is True
    assert is_peer_mismatch("terminal-server", "kiosk") is True


def test_is_peer_mismatch_with_none_returns_false() -> None:
    """One-sided unknown can't claim mismatch — be conservative."""
    assert is_peer_mismatch(None, "developer-workstation") is False
    assert is_peer_mismatch("developer-workstation", None) is False
    assert is_peer_mismatch(None, None) is False


# --- build_peer_mismatch_findings ----------------------------------

def test_no_findings_when_all_runs_share_peer_group() -> None:
    findings = build_peer_mismatch_findings([
        _run("dev1", machine_class="developer-workstation"),
        _run("dev2", machine_class="engineering-workstation"),
    ])
    assert findings == []


def test_no_findings_when_no_runs_declare_class() -> None:
    """Legacy runs (pre-C3) shouldn't trigger findings just for being
    legacy. We need at least 2 declared classes to claim mismatch."""
    findings = build_peer_mismatch_findings([_run("a"), _run("b")])
    assert findings == []


def test_atlt4407_vs_morgana_pattern_fires_mismatch() -> None:
    """The v2 production-review case: enterprise-managed laptop (treated
    as office) vs developer workstation (workstation group). Different
    peer groups -> finding."""
    findings = build_peer_mismatch_findings([
        _run("ATLT4407", machine_class="general-knowledge-worker",
             hostname="ATLT4407"),
        _run("MORGANA", machine_class="developer-workstation",
             hostname="MORGANA"),
    ])
    mismatches = [f for f in findings if f["kind"] == "machine_class_mismatch"]
    assert len(mismatches) == 1
    f = mismatches[0]
    assert f["severity"] == "medium"
    assert f["confidence"] == "high"  # rule-based on declared metadata
    assert f["category"] == "peer_mismatch"
    assert {f["run_id"], f["peer_id"]} == {"ATLT4407", "MORGANA"}
    # Affected metrics list must include the cadence-sensitive ones.
    assert "cpu_avg" in f["affected_metrics"]
    assert "mem_avg" in f["affected_metrics"]


def test_three_runs_two_groups_emits_one_pair_finding() -> None:
    """Two workstations + one kiosk -> one mismatch pair (workstation vs
    kiosk), not three. Same-group pairs don't fire."""
    findings = build_peer_mismatch_findings([
        _run("dev1", machine_class="developer-workstation"),
        _run("dev2", machine_class="developer-workstation"),
        _run("k1", machine_class="kiosk"),
    ])
    mismatches = [f for f in findings if f["kind"] == "machine_class_mismatch"]
    # dev1↔k1 and dev2↔k1 are both workstation↔embedded mismatches.
    assert len(mismatches) == 2


def test_undeclared_machine_class_completeness_note() -> None:
    """When at least one run declares machine_class AND another doesn't,
    AND we already emitted a mismatch finding, a low-severity
    completeness note suggests setting --machine-class for next time."""
    findings = build_peer_mismatch_findings([
        _run("dev1", machine_class="developer-workstation"),
        _run("kiosk1", machine_class="kiosk"),
        _run("legacy"),  # undeclared
    ])
    completeness = [f for f in findings if f["kind"] == "machine_class_undeclared"]
    assert len(completeness) == 1
    assert completeness[0]["severity"] == "low"
    assert completeness[0]["run_id"] == "legacy"


def test_no_completeness_note_when_no_mismatch_fires() -> None:
    """If everyone declared is in the same group, the completeness note
    is overhead — don't emit it."""
    findings = build_peer_mismatch_findings([
        _run("dev1", machine_class="developer-workstation"),
        _run("dev2", machine_class="engineering-workstation"),
        _run("legacy"),
    ])
    assert findings == []
