"""The Run domain object.

A `Run` wraps a run-folder path with lazy-loaded, typed accessors for
the JSON artifacts (manifest, findings, scores, phases) and a set of
boolean convenience properties (`is_aborted`, `has_final_report`, ...).

The goal is to replace the `path: str` pattern that is currently
threaded through `gui/runs.py`, `gui/tab_runs.py`, `gui/tab_compare.py`,
`sanitizer.py`, and `sysspecter.py`. Callers can still get at the raw
dict via `run.manifest_raw` when they need to tolerate unknown keys.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cached_property
from typing import Any

from .schemas import (
    Findings,
    Manifest,
    PhasesDoc,
    Scores,
    try_validate,
)

_log = logging.getLogger(__name__)


@dataclass
class RunArtifact:
    """Descriptor for one file inside a run folder."""
    filename: str
    exists: bool
    size_bytes: int = 0

    @classmethod
    def probe(cls, run_dir: str, filename: str) -> RunArtifact:
        path = os.path.join(run_dir, filename)
        try:
            st = os.stat(path)
            return cls(filename=filename, exists=True, size_bytes=st.st_size)
        except OSError:
            return cls(filename=filename, exists=False, size_bytes=0)


class Run:
    """A finished (or in-progress) SysSpecter run on disk."""

    def __init__(self, path: str) -> None:
        self.path: str = os.path.abspath(path)

    # ---------------------------------------------------------------- lazy IO

    @cached_property
    def manifest_raw(self) -> dict[str, Any]:
        return self._read_json("manifest.json") or {}

    @cached_property
    def findings_raw(self) -> dict[str, Any]:
        return self._read_json("findings.json") or {}

    @cached_property
    def scores_raw(self) -> dict[str, Any]:
        return self._read_json("scores.json") or {}

    @cached_property
    def phases_raw(self) -> dict[str, Any]:
        return self._read_json("phases.json") or {}

    # ---------------------------------------------------------------- validated

    @cached_property
    def manifest(self) -> Manifest | None:
        return try_validate(Manifest, self.manifest_raw, label="manifest") \
            if self.manifest_raw else None  # type: ignore[return-value]

    @cached_property
    def findings(self) -> Findings | None:
        return try_validate(Findings, self.findings_raw, label="findings") \
            if self.findings_raw else None  # type: ignore[return-value]

    @cached_property
    def scores(self) -> Scores | None:
        return try_validate(Scores, self.scores_raw, label="scores") \
            if self.scores_raw else None  # type: ignore[return-value]

    @cached_property
    def phases(self) -> PhasesDoc | None:
        return try_validate(PhasesDoc, self.phases_raw, label="phases") \
            if self.phases_raw else None  # type: ignore[return-value]

    # ---------------------------------------------------------------- identity

    @property
    def run_id(self) -> str:
        return self.manifest_raw.get("run_id") or os.path.basename(self.path)

    @property
    def hostname(self) -> str:
        return self.manifest_raw.get("hostname") or "?"

    @property
    def mode(self) -> str:
        return self.manifest_raw.get("mode") or "?"

    # ---------------------------------------------------------------- booleans

    @property
    def has_manifest(self) -> bool:
        return bool(self.manifest_raw)

    @property
    def has_final_report(self) -> bool:
        return os.path.exists(os.path.join(self.path, "final_report.html"))

    @property
    def has_phases(self) -> bool:
        return os.path.exists(os.path.join(self.path, "phases_report.html"))

    @property
    def is_aborted(self) -> bool:
        """A run is 'aborted' when the manifest has no `ended_at`."""
        return bool(self.manifest_raw) and self.manifest_raw.get("ended_at") is None

    @property
    def is_sanitized(self) -> bool:
        return bool(self.manifest_raw.get("sanitized"))

    # ---------------------------------------------------------------- convenience

    @property
    def duration_seconds(self) -> float | None:
        v = self.manifest_raw.get("duration_actual_seconds")
        try:
            return float(v) if v is not None else None
        except (TypeError, ValueError):
            return None

    @property
    def overall_score(self) -> float | None:
        v = self.scores_raw.get("overall")
        try:
            return float(v) if v is not None else None
        except (TypeError, ValueError):
            return None

    @property
    def primary_bottleneck(self) -> str | None:
        return self.scores_raw.get("primary_bottleneck")

    @property
    def stop_reason(self) -> str | None:
        return self.manifest_raw.get("stop_reason")

    @property
    def collector_degraded(self) -> dict[str, str]:
        deg = self.manifest_raw.get("collector_degraded") or {}
        return dict(deg) if isinstance(deg, dict) else {}

    # ---------------------------------------------------------------- artifacts

    _ARTIFACT_NAMES: tuple[str, ...] = (
        "manifest.json", "static_snapshot.json",
        "findings.json", "scores.json",
        "phases.json", "phases_report.html",
        "final_report.html", "final_report.md",
        "timeline_system.csv", "timeline_processes.csv",
        "timeline_network.csv", "timeline_latency.csv",
        "timeline_connections.csv",
    )

    def artifacts(self) -> list[RunArtifact]:
        return [RunArtifact.probe(self.path, n) for n in self._ARTIFACT_NAMES]

    # ---------------------------------------------------------------- utils

    def _read_json(self, name: str) -> dict[str, Any] | None:
        path = os.path.join(self.path, name)
        if not os.path.exists(path):
            return None
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else None
        except (OSError, json.JSONDecodeError) as e:
            _log.warning("failed to read %s: %s", path, e)
            return None

    def __repr__(self) -> str:
        return f"Run({self.run_id!r} @ {self.path})"


def iter_runs(output_root: str) -> Iterable[Run]:
    """Yield every run under `<output_root>/Runs/` that has a manifest."""
    runs_root = os.path.join(output_root, "Runs")
    if not os.path.isdir(runs_root):
        return
    for name in os.listdir(runs_root):
        folder = os.path.join(runs_root, name)
        if not os.path.isdir(folder):
            continue
        run = Run(folder)
        if run.has_manifest:
            yield run


def scan_runs_sorted(output_root: str) -> list[Run]:
    """Return all runs under `output_root`, newest manifest first."""
    runs = list(iter_runs(output_root))

    def _mtime(r: Run) -> float:
        try:
            return os.path.getmtime(os.path.join(r.path, "manifest.json"))
        except OSError:
            return 0.0

    runs.sort(key=_mtime, reverse=True)
    return runs


__all__ = ["Run", "RunArtifact", "iter_runs", "scan_runs_sorted"]
