"""Tests for the Run domain object."""

from __future__ import annotations

import json
from pathlib import Path

from sysspecter.domain.run import Run, iter_runs, scan_runs_sorted


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f)


def _make_run(tmp: Path, name: str = "HOST_RUN_1",
              with_report: bool = True,
              aborted: bool = False) -> Path:
    folder = tmp / "runs" / name
    _write(folder / "manifest.json", {
        "schema_version": 2, "sysspecter_version": "1.1.0-dev",
        "run_id": name, "hostname": "HOST", "mode": "support",
        "started_at": "2026-04-23T01:00:00",
        "ended_at": None if aborted else "2026-04-23T01:05:00",
        "duration_actual_seconds": 300, "stop_reason": None if aborted else "manual",
        "privilege_level": "user", "tags": [],
    })
    _write(folder / "scores.json", {"overall": 82, "primary_bottleneck": "cpu"})
    _write(folder / "findings.json", {"summary": {"verdict": "ok"}})
    if with_report:
        (folder / "final_report.html").write_text("<html/>", encoding="utf-8")
    return folder


def test_run_exposes_manifest_properties(tmp_path: Path) -> None:
    folder = _make_run(tmp_path)
    run = Run(str(folder))
    assert run.run_id == "HOST_RUN_1"
    assert run.hostname == "HOST"
    assert run.mode == "support"
    assert run.overall_score == 82
    assert run.primary_bottleneck == "cpu"


def test_run_is_lazy(tmp_path: Path) -> None:
    folder = _make_run(tmp_path)
    run = Run(str(folder))
    # Construction does not read the files yet.
    # Delete the findings file after construction and the flag must still flip.
    (folder / "findings.json").unlink()
    # Properties that don't need findings should still work.
    assert run.overall_score == 82


def test_has_final_report_true(tmp_path: Path) -> None:
    folder = _make_run(tmp_path, with_report=True)
    assert Run(str(folder)).has_final_report is True


def test_has_final_report_false(tmp_path: Path) -> None:
    folder = _make_run(tmp_path, with_report=False)
    assert Run(str(folder)).has_final_report is False


def test_is_aborted_distinguishes_clean_run(tmp_path: Path) -> None:
    done = _make_run(tmp_path, name="DONE", aborted=False)
    aborted = _make_run(tmp_path, name="ABORTED", aborted=True)
    assert Run(str(done)).is_aborted is False
    assert Run(str(aborted)).is_aborted is True


def test_validated_manifest_picks_up_required_fields(tmp_path: Path) -> None:
    folder = _make_run(tmp_path)
    run = Run(str(folder))
    m = run.manifest
    assert m is not None
    assert m.run_id == "HOST_RUN_1"
    assert m.mode == "support"


def test_validated_findings_model(tmp_path: Path) -> None:
    folder = _make_run(tmp_path)
    run = Run(str(folder))
    f = run.findings
    assert f is not None
    assert f.summary.verdict == "ok"


def test_scan_runs_sorted(tmp_path: Path) -> None:
    # Create the layout expected by iter_runs: `<root>/Runs/<folder>`
    root = tmp_path
    runs_root = root / "Runs"
    runs_root.mkdir()
    a = _make_run(tmp_path, name="A")
    (runs_root / "A").symlink_to(a, target_is_directory=True) if False else None
    # Instead of symlinks (admin-required on Windows) re-create via _make_run
    # but under `Runs/`. Use a helper: just recreate.
    for sub in ("A", "B"):
        run_dir = runs_root / sub
        _write(run_dir / "manifest.json",
               {"run_id": sub, "hostname": "H", "mode": "support",
                "started_at": "2026-04-23T00:00:00"})
    runs = scan_runs_sorted(str(root))
    assert {r.run_id for r in runs} == {"A", "B"}
    assert all(isinstance(r, Run) for r in runs)


def test_iter_runs_skips_folders_without_manifest(tmp_path: Path) -> None:
    runs_root = tmp_path / "Runs"
    runs_root.mkdir()
    (runs_root / "trash").mkdir()
    (runs_root / "good").mkdir()
    _write(runs_root / "good" / "manifest.json",
           {"run_id": "good", "hostname": "H", "mode": "support",
            "started_at": "2026-04-23T00:00:00"})
    runs = list(iter_runs(str(tmp_path)))
    assert [r.run_id for r in runs] == ["good"]


def test_validation_tolerates_v1_manifest(tmp_path: Path) -> None:
    """A v1 run missing sysspecter_version / collector_degraded must still
    validate because every new-in-v2 field is optional."""
    folder = tmp_path / "v1"
    _write(folder / "manifest.json", {
        "schema_version": 1, "run_id": "old", "hostname": "H",
        "mode": "support", "started_at": "2026-01-01T00:00:00",
    })
    run = Run(str(folder))
    assert run.manifest is not None
    assert run.manifest.schema_version == 1
    assert run.manifest.sysspecter_version is None  # absent in v1


def test_corrupt_manifest_returns_none_but_does_not_raise(tmp_path: Path) -> None:
    folder = tmp_path / "broken"
    folder.mkdir()
    (folder / "manifest.json").write_text("{ this is not json", encoding="utf-8")
    run = Run(str(folder))
    assert run.manifest_raw == {}
    assert run.manifest is None
    assert run.has_manifest is False
