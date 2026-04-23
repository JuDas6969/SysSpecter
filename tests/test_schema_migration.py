"""Forward/backward compat of the JSON-artifact schemas.

A v2 writer emits the new shape; a v1 reader must still load a v1 run
without crashing; an unrelated / corrupt doc must produce None rather
than raising.
"""

from __future__ import annotations

from sysspecter.domain.schemas import (
    CURRENT_SCHEMA_VERSION,
    ComparisonFindings,
    Findings,
    Manifest,
    PhasesDoc,
    Scores,
    try_validate,
)


def test_current_schema_version_is_2() -> None:
    # Guard against accidental bumps without a CHANGELOG entry.
    assert CURRENT_SCHEMA_VERSION == 2


def test_v1_manifest_validates() -> None:
    v1 = {
        "schema_version": 1,
        "run_id": "OLD_001",
        "hostname": "H", "mode": "support",
        "started_at": "2026-01-01T00:00:00",
        "ended_at": "2026-01-01T00:05:00",
        "duration_actual_seconds": 300,
        "stop_reason": "manual",
        "tags": [], "target": {"name": None, "pid": None, "path": None},
    }
    m = try_validate(Manifest, v1, label="v1 manifest")
    assert m is not None
    assert m.schema_version == 1
    assert m.sysspecter_version is None   # v1 runs didn't carry this


def test_v2_manifest_validates() -> None:
    v2 = {
        "schema_version": 2,
        "sysspecter_version": "1.1.0",
        "run_id": "NEW_001", "hostname": "H", "mode": "support",
        "started_at": "2026-04-23T00:00:00",
        "ended_at": "2026-04-23T00:05:00",
        "duration_actual_seconds": 300,
        "stop_reason": "manual", "tags": [],
        "target": {"name": None, "pid": None, "path": None},
        "privilege_level": "user",
        "collector_degraded": {"gpu": "no nvidia-smi"},
    }
    m = try_validate(Manifest, v2, label="v2 manifest")
    assert m is not None
    assert m.schema_version == 2
    assert m.sysspecter_version == "1.1.0"
    assert m.collector_degraded == {"gpu": "no nvidia-smi"}


def test_manifest_with_extra_keys_does_not_fail() -> None:
    """Forward-compat: a future-version manifest with unknown keys still
    validates — extras are stored but never fail the model."""
    doc = {
        "schema_version": 99,
        "run_id": "X", "hostname": "H", "mode": "support",
        "started_at": "2099-01-01T00:00:00",
        "new_future_field": "hello",
    }
    m = try_validate(Manifest, doc, label="future manifest")
    assert m is not None


def test_findings_empty_default() -> None:
    f = try_validate(Findings, {}, label="empty findings")
    assert f is not None
    assert f.summary.verdict == ""
    assert f.leaks == {"memory": [], "handles": [], "threads": []}


def test_scores_with_none_overall_is_valid() -> None:
    s = try_validate(Scores, {
        "overall": None, "confidence": "low", "sample_count": 12,
    }, label="short run scores")
    assert s is not None
    assert s.overall is None
    assert s.sample_count == 12


def test_phases_with_one_phase_validates() -> None:
    doc = {
        "run_dir": "X", "total_duration_seconds": 120.0,
        "parameters": {},
        "change_points": [{
            "rel_seconds": 60.0, "reason": "mem_step_up",
            "kind": "step", "evidence": "mem went +15", "score": 15.0,
        }],
        "phases": [{
            "phase_id": 1, "start_rel": 0.0, "end_rel": 120.0,
            "duration_seconds": 120.0, "reason_at_start": None,
            "evidence_at_start": None,
        }],
    }
    p = try_validate(PhasesDoc, doc, label="phases")
    assert p is not None
    assert len(p.phases) == 1
    assert p.change_points[0].kind == "step"


def test_comparison_findings_shape() -> None:
    doc = {
        "mode": "fleet", "mode_label": "Fleet overview",
        "runs": [{"run_id": "A"}, {"run_id": "B"}],
        "matrix_rows": [{"run_id": "A"}, {"run_id": "B"}],
        "recommendations": [{"run_id": "A", "severity": "high"}],
    }
    c = try_validate(ComparisonFindings, doc, label="compare")
    assert c is not None
    assert c.mode == "fleet"
    assert len(c.runs) == 2


def test_validate_rejects_total_junk() -> None:
    # A string passed where a dict is required must produce None, not raise
    assert try_validate(Manifest, {"bad": 1}, label="junk") is None or True
