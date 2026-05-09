"""v3-priority-3 (part 2): software-bloat rule distinguishes installed
from actually-running.

The v2 production review caught the comparison engine attributing the
20-point ATLT4407↔MORGANA efficiency gap to "106 unused programs"
(Adobe Reader, 7-Zip, Beyond Compare, Check Point VPN client...) —
most of which were installed but never ran during the capture. The
rule had a real-correlation foundation but an overstated causal claim.

The fix splits the rule into two:

1. `running_software_delta` (medium severity, medium confidence) —
   fires when at least one of the unique-to-A programs was actually
   running. Real causal mechanism.

2. `installed_software_delta_candidate` (low severity, low confidence)
   — fires when the diff is installed-only with no observed run-time
   evidence. Surfaced as a "candidate factor" not a cause.

These tests pin both paths plus the helpers that drive them.
"""

from __future__ import annotations

from sysspecter.comparer.diagnosis import (
    _running_overlap,
    _running_process_names,
    generate_hypotheses,
)

# --- helpers -------------------------------------------------------

class _RD:
    def __init__(self, process_rows: list[dict]) -> None:
        self.process_rows = process_rows
        self.system_rows: list[dict] = []
        self.latency_rows: list[dict] = []
        self.connection_rows: list[dict] = []
        self.static: dict = {}
        self.manifest: dict = {}


def _run_with_processes(run_id: str, processes: list[str]) -> dict:
    rows = [{"name": p} for p in processes]
    return {
        "manifest": {"run_id": run_id, "hostname": run_id, "meta": {}},
        "scores": {},
        "findings": {},
        "rd": _RD(rows),
    }


# --- _running_process_names ---------------------------------------

def test_running_process_names_lowercases_and_strips_exe() -> None:
    run = _run_with_processes("r1", ["Chrome.exe", "MsSense.EXE", "code"])
    out = _running_process_names(run)
    assert out == {"chrome", "mssense", "code"}


def test_running_process_names_handles_missing_rd() -> None:
    run = {"manifest": {"run_id": "r1"}, "rd": None}
    assert _running_process_names(run) == set()


def test_running_process_names_handles_empty_process_rows() -> None:
    assert _running_process_names(_run_with_processes("r1", [])) == set()


# --- _running_overlap ---------------------------------------------

def test_running_overlap_exact_name_match() -> None:
    installed = ["Microsoft Edge", "Adobe Acrobat Reader", "7-Zip"]
    running = {"adobe", "msedge", "chrome"}
    # "adobe" matches "Adobe Acrobat Reader" by token
    overlap = _running_overlap(installed, running)
    assert "Adobe Acrobat Reader" in overlap


def test_running_overlap_returns_empty_when_nothing_matches() -> None:
    installed = ["Adobe Reader", "7-Zip", "VLC"]
    running = {"chrome", "code", "explorer"}
    assert _running_overlap(installed, running) == []


def test_running_overlap_handles_empty_inputs() -> None:
    assert _running_overlap([], {"chrome"}) == []
    assert _running_overlap(["Chrome"], set()) == []


# --- end-to-end via generate_hypotheses ----------------------------

def _matrix_row(run_id: str, *, efficiency: float = 70.0) -> dict:
    return {
        "run_id": run_id,
        "hostname": run_id,
        "primary": None,
        "efficiency": efficiency,
        "cpu_avg": 10.0,
        "mem_avg": 50.0,
        "disk_avg": 5.0,
    }


def _sw_diff(a: str, b: str, *, only_in_a: list[str], only_in_b: list[str] | None = None) -> dict:
    return {"pairwise": [{
        "pair": [a, b],
        "only_in_a": only_in_a,
        "only_in_a_total": len(only_in_a),
        "only_in_b": only_in_b or [],
        "only_in_b_total": len(only_in_b or []),
    }]}


def _empty_diffs() -> dict:
    return {"profiles": [], "divergent_fields": [], "pairwise": []}


def test_running_software_delta_fires_when_program_was_running() -> None:
    """The good case: ATLT4407 ran a program that MORGANA didn't, AND
    the efficiency gap is significant. Should fire 'running_software_delta'
    with medium confidence — real causal evidence."""
    runs = [
        _run_with_processes("ATLT4407", ["claude", "chrome", "code"] * 4 + ["explorer"]),
        _run_with_processes("MORGANA", ["explorer", "svchost"]),
    ]
    matrix = {"rows": [
        _matrix_row("ATLT4407", efficiency=60.0),
        _matrix_row("MORGANA", efficiency=80.0),
    ]}
    # ATLT4407 has 12 programs MORGANA doesn't. Enough installed to trip
    # the count gate (>= 10), and "Claude Code" is actually running.
    sw_diff = _sw_diff(
        "ATLT4407", "MORGANA",
        only_in_a=["Claude Code", "Microsoft Edge", "7-Zip", "Adobe Reader"]
                  + [f"FillerApp{i}" for i in range(8)],
    )
    hyps = generate_hypotheses(runs, matrix, _empty_diffs(), sw_diff, _empty_diffs())
    running_findings = [h for h in hyps if h.get("kind") == "running_software_delta"]
    assert len(running_findings) == 1
    f = running_findings[0]
    assert f["severity"] == "medium"
    assert f["confidence"] == "medium"
    assert f["run_id"] == "ATLT4407"
    # Hypothesis text should mention the running count, not the installed count.
    assert "may contribute" in f["hypothesis"]


def test_installed_software_delta_candidate_fires_when_nothing_runs() -> None:
    """The hard case: MORGANA has 12 unique installed programs but
    none are running on either side. The old rule fired confident
    "background noise" hypotheses; the new rule fires a low-confidence
    candidate-factor finding."""
    runs = [
        _run_with_processes("ATLT4407", ["explorer"]),
        _run_with_processes("MORGANA", ["explorer"]),
    ]
    matrix = {"rows": [
        _matrix_row("ATLT4407", efficiency=80.0),
        _matrix_row("MORGANA", efficiency=60.0),
    ]}
    # MORGANA has 12 unique installed programs, none running.
    sw_diff = _sw_diff(
        "ATLT4407", "MORGANA",
        only_in_a=[],
        only_in_b=["BeyondTrust", "Check Point VPN", "Adobe Reader"]
                  + [f"FillerApp{i}" for i in range(9)],
    )
    hyps = generate_hypotheses(runs, matrix, _empty_diffs(), sw_diff, _empty_diffs())
    candidates = [h for h in hyps if h.get("kind") == "installed_software_delta_candidate"]
    assert len(candidates) == 1
    c = candidates[0]
    assert c["severity"] == "low"
    assert c["confidence"] == "low"
    assert c["run_id"] == "MORGANA"
    # Hypothesis text must use the cautious "candidate factor" framing.
    assert "candidate factor" in c["hypothesis"].lower() \
        or "low confidence" in c["hypothesis"].lower()


def test_running_finding_replaces_installed_only_finding_when_evidence_exists() -> None:
    """If at least one program is actually running, ONLY the
    running_software_delta fires — not both findings for the same pair.
    Otherwise the report would double-count."""
    runs = [
        _run_with_processes("a", ["claude"] * 5),
        _run_with_processes("b", []),
    ]
    matrix = {"rows": [
        _matrix_row("a", efficiency=60.0),
        _matrix_row("b", efficiency=80.0),
    ]}
    sw_diff = _sw_diff(
        "a", "b",
        only_in_a=["Claude Code"] + [f"App{i}" for i in range(11)],
    )
    hyps = generate_hypotheses(runs, matrix, _empty_diffs(), sw_diff, _empty_diffs())
    running_findings = [h for h in hyps if h.get("kind") == "running_software_delta"]
    candidate_findings = [h for h in hyps if h.get("kind") == "installed_software_delta_candidate"]
    assert len(running_findings) == 1
    assert len(candidate_findings) == 0


def test_no_finding_when_efficiency_gap_too_small() -> None:
    """Even if 100 unique installed programs exist, no finding fires
    if the efficiency gap is < 5 — there's nothing to explain."""
    runs = [
        _run_with_processes("a", []),
        _run_with_processes("b", []),
    ]
    matrix = {"rows": [
        _matrix_row("a", efficiency=78.0),
        _matrix_row("b", efficiency=80.0),  # only 2-point gap
    ]}
    sw_diff = _sw_diff(
        "b", "a", only_in_a=[f"App{i}" for i in range(50)],
    )
    hyps = generate_hypotheses(runs, matrix, _empty_diffs(), sw_diff, _empty_diffs())
    sw = [h for h in hyps if h.get("category") == "software"]
    assert sw == []


def test_no_finding_when_unique_count_too_small() -> None:
    """Below the 10-program gate, no finding fires regardless of running."""
    runs = [
        _run_with_processes("a", ["chrome"]),
        _run_with_processes("b", []),
    ]
    matrix = {"rows": [
        _matrix_row("a", efficiency=60.0),
        _matrix_row("b", efficiency=80.0),
    ]}
    sw_diff = _sw_diff("a", "b", only_in_a=["Chrome", "VLC"])  # only 2
    hyps = generate_hypotheses(runs, matrix, _empty_diffs(), sw_diff, _empty_diffs())
    sw = [h for h in hyps if h.get("category") == "software"]
    assert sw == []
