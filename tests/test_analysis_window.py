"""Field-review B1: scores.json / findings.json / manifest.json carry a
single, consistent analysis_window block, even when --trim-seconds is in
play.

Before this fix, the same run produced three different "duration" answers:

- scores.json: 39 samples / 800 s   (the trim window the report ran on)
- timeline CSV: 344 samples / 7998 s (actual data captured, with sampler drops)
- manifest.json: 49309 s            (the full run length)

These tests pin the contract: every analyzer write stamps an
`analysis_window` object that is the single source of truth for "what
was actually analyzed", and a trimmed run carries the original full-run
duration alongside.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from sysspecter.analyzer.pipeline import analyze_run

REPO = Path(__file__).resolve().parent.parent
REFERENCE_RUN = REPO / "tests" / "data" / "reference_run"


@pytest.fixture
def scratch_run(tmp_path: Path) -> Path:
    dst = tmp_path / "ref"
    shutil.copytree(REFERENCE_RUN, dst)
    (dst / "logs").mkdir(exist_ok=True)
    return dst


def _read(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def test_full_run_window_present_in_both_artefacts(scratch_run: Path) -> None:
    """Without --trim-seconds, both findings.json and scores.json carry
    an analysis_window block describing the un-trimmed full run."""
    analyze_run(str(scratch_run))
    findings = _read(scratch_run / "findings.json")
    scores = _read(scratch_run / "scores.json")

    assert "analysis_window" in findings, \
        "findings.json must carry analysis_window for B1"
    assert "analysis_window" in scores, \
        "scores.json must carry analysis_window for B1"

    aw_f = findings["analysis_window"]
    aw_s = scores["analysis_window"]
    assert aw_f == aw_s, \
        "findings + scores must agree on the analysis window byte-for-byte"

    # Reference run is 300 samples at 1 Hz from rel_seconds 0..299.
    assert aw_f["samples_analyzed"] == 300
    assert aw_f["window_start_seconds"] == 0.0
    assert aw_f["window_end_seconds"] >= 299.0
    assert aw_f["trimmed"] is False


def test_trimmed_run_records_both_full_and_window(scratch_run: Path) -> None:
    """With --trim-seconds 100 the analyzer must record:

    - the trim window it actually ran on (start/end/samples)
    - AND the original full-run duration (so the report can show both)
    """
    analyze_run(str(scratch_run), max_rel_seconds=100)
    scores = _read(scratch_run / "scores.json")
    aw = scores["analysis_window"]

    assert aw["trimmed"] is True
    assert aw["window_start_seconds"] == 0.0
    assert aw["window_end_seconds"] <= 100.0
    # 100 1-Hz samples (give or take rounding at the boundary).
    assert 95 <= aw["samples_analyzed"] <= 105, \
        f"unexpected sample count {aw['samples_analyzed']} for 100 s window"

    # Crucial: the full-run duration is preserved alongside the window.
    assert aw["full_run_duration_seconds"] is not None
    assert aw["full_run_duration_seconds"] > aw["window_duration_seconds"]


def test_window_duration_matches_actual_csv_range(scratch_run: Path) -> None:
    """window_duration_seconds is computed from the actual loaded
    rel_seconds range, not from the requested trim parameters. This is
    what makes it the single source of truth: even if the sampler
    dropped half the run, the window reflects what really got analyzed."""
    analyze_run(str(scratch_run), max_rel_seconds=50)
    scores = _read(scratch_run / "scores.json")
    aw = scores["analysis_window"]

    # The window's duration must equal end - start exactly.
    expected = round(aw["window_end_seconds"] - aw["window_start_seconds"], 2)
    assert aw["window_duration_seconds"] == expected


def test_sample_count_in_window_matches_legacy_field(scratch_run: Path) -> None:
    """scores.sample_count and analysis_window.samples_analyzed must
    agree. The legacy field is kept for backwards compatibility but
    must never disagree with the new authoritative one."""
    analyze_run(str(scratch_run))
    scores = _read(scratch_run / "scores.json")
    assert scores["sample_count"] == scores["analysis_window"]["samples_analyzed"]
