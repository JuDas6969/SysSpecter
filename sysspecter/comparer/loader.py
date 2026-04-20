"""Load completed runs for comparison."""

from __future__ import annotations

import json
import os
from typing import Any

from ..analyzer.loader import load_run, RunData
from ..analyzer.pipeline import analyze_run


def load_run_full(run_dir: str) -> tuple[RunData, dict[str, Any], dict[str, Any]]:
    findings_path = os.path.join(run_dir, "findings.json")
    scores_path = os.path.join(run_dir, "scores.json")
    if not (os.path.exists(findings_path) and os.path.exists(scores_path)):
        analyze_run(run_dir)
    with open(findings_path, "r", encoding="utf-8") as f:
        findings = json.load(f)
    with open(scores_path, "r", encoding="utf-8") as f:
        scores = json.load(f)
    return load_run(run_dir), findings, scores


def load_run_summary(run_dir: str) -> str:
    rd, findings, scores = load_run_full(run_dir)
    manifest = rd.manifest or {}
    lines = [
        f"Run:       {manifest.get('run_id')}",
        f"Host:      {manifest.get('hostname')}",
        f"Mode:      {manifest.get('mode')}",
        f"Duration:  {manifest.get('duration_actual_seconds')}s",
        f"Tags:      {', '.join(manifest.get('tags') or []) or '—'}",
        f"Verdict:   {findings.get('summary',{}).get('verdict','')}",
        f"Overall:   {scores.get('overall')} (confidence {scores.get('confidence')})",
        f"Primary:   {scores.get('primary_bottleneck') or '—'}",
        f"Secondary: {', '.join(scores.get('secondary_bottlenecks') or []) or '—'}",
    ]
    return "\n".join(lines)
