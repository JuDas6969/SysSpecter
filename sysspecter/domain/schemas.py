"""Pydantic schemas for SysSpecter's on-disk JSON artifacts.

These models are the authoritative contract for what lives in
`manifest.json`, `findings.json`, `scores.json`, `phases.json`,
`comparison_findings.json`, `comparison_scores.json`.

Usage patterns
--------------
- Writers stay unchanged: they emit plain dicts via `atomic_write_json`.
  The schemas are not enforced on WRITE so we don't regress the happy path.
- Readers call `try_validate(Manifest, raw_dict)` (see bottom). On the
  happy path they get a typed model; on mismatch they get None + a log
  message and the caller can keep using the raw dict.
- Old (`schema_version=1`) runs are tolerated: fields are `Optional`
  wherever they were introduced after v1, and extra keys are allowed
  via `model_config = ConfigDict(extra="allow")`.

This is intentionally a **tolerant** layer: the goal is to catch
"someone renamed a field and the report silently broke" in testing and
CI, not to reject slightly-old runs at runtime.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

_log = logging.getLogger(__name__)


# Every model below allows extras so unknown fields are preserved, and
# frames every field as Optional unless it is truly required by every
# pipeline stage. That keeps the schema tolerant across version bumps.
_MODEL_CONFIG = ConfigDict(extra="allow", str_strip_whitespace=True)


# --------------------------------------------------------------------- manifest


class ManifestTarget(BaseModel):
    model_config = _MODEL_CONFIG
    name: str | None = None
    pid: int | None = None
    path: str | None = None


class ManifestPhase3(BaseModel):
    model_config = _MODEL_CONFIG
    gpu: bool = False
    event_logs: bool = False
    etw_disk: bool = False


class Manifest(BaseModel):
    model_config = _MODEL_CONFIG

    schema_version: int = 1
    sysspecter_version: str | None = None
    run_id: str
    hostname: str
    fqdn: str | None = None
    started_at: str
    ended_at: str | None = None
    stop_reason: str | None = None
    mode: Literal["support", "baseline", "workload"] = "support"
    duration_requested_seconds: int | None = None
    duration_actual_seconds: float | None = None
    interval_seconds: float = 1.0
    manual_stop: bool = False
    tags: list[str] = Field(default_factory=list)
    # Field-review M2: structured fleet metadata (department, ticket,
    # scenario, …). Distinct from free-form tags. Optional for
    # backwards-compat with v1 / v2 manifests.
    meta: dict[str, str] = Field(default_factory=dict)
    target: ManifestTarget = Field(default_factory=ManifestTarget)
    latency_targets: list[str] = Field(default_factory=list)
    output_root: str | None = None
    run_dir: str | None = None
    privilege_level: Literal["admin", "user", "unknown"] | None = None
    thresholds: dict[str, Any] = Field(default_factory=dict)
    phase3: ManifestPhase3 = Field(default_factory=ManifestPhase3)
    collector_degraded: dict[str, str] = Field(default_factory=dict)
    sanitized: bool | None = None
    sanitized_source: str | None = None
    # v1 runs lack trim/window metadata; keep them optional
    window_start_seconds: float | None = None
    window_end_seconds: float | None = None
    trimmed_from_seconds: float | None = None


# --------------------------------------------------------------------- findings


class Summary(BaseModel):
    model_config = _MODEL_CONFIG
    verdict: str = ""
    total_anomalies: int = 0
    total_slowdown_windows: int = 0
    total_leak_candidates: int = 0
    primary_bottleneck: str | None = None
    insufficient_data: bool = False


class Findings(BaseModel):
    model_config = _MODEL_CONFIG

    anomalies: list[dict[str, Any]] = Field(default_factory=list)
    slowdowns: list[dict[str, Any]] = Field(default_factory=list)
    leaks: dict[str, list[dict[str, Any]]] = Field(
        default_factory=lambda: {"memory": [], "handles": [], "threads": []})
    offenders: dict[str, Any] = Field(default_factory=dict)
    apps: dict[str, Any] = Field(default_factory=dict)
    network_attribution: dict[str, Any] = Field(default_factory=dict)
    latency_analysis: dict[str, Any] = Field(default_factory=dict)
    gpu_analysis: dict[str, Any] = Field(default_factory=dict)
    event_correlation: dict[str, Any] = Field(default_factory=dict)
    etw_disk: dict[str, Any] = Field(default_factory=dict)
    process_churn: dict[str, Any] = Field(default_factory=dict)
    bottlenecks: dict[str, Any] = Field(default_factory=dict)
    summary: Summary = Field(default_factory=Summary)


# --------------------------------------------------------------------- scores


class ScoreDetail(BaseModel):
    model_config = _MODEL_CONFIG
    score: float | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class Scores(BaseModel):
    model_config = _MODEL_CONFIG

    stability: ScoreDetail = Field(default_factory=ScoreDetail)
    efficiency: ScoreDetail = Field(default_factory=ScoreDetail)
    workload_suitability: ScoreDetail = Field(default_factory=ScoreDetail)
    security_overhead: ScoreDetail = Field(default_factory=ScoreDetail)
    network_impact: ScoreDetail = Field(default_factory=ScoreDetail)
    resource_hygiene: ScoreDetail = Field(default_factory=ScoreDetail)

    overall: float | None = None
    weights: dict[str, float] = Field(default_factory=dict)
    primary_bottleneck: str | None = None
    secondary_bottlenecks: list[str] = Field(default_factory=list)
    confidence: str = "medium"
    sample_count: int = 0


# --------------------------------------------------------------------- phases


class ChangePointRecord(BaseModel):
    model_config = _MODEL_CONFIG
    rel_seconds: float
    reason: str
    kind: str
    evidence: str | None = None
    score: float = 0.0


class PhaseRecord(BaseModel):
    model_config = _MODEL_CONFIG
    phase_id: int
    start_rel: float
    end_rel: float
    duration_seconds: float
    reason_at_start: str | None = None
    evidence_at_start: str | None = None
    subreport_path: str | None = None
    error: str | None = None


class PhasesDoc(BaseModel):
    model_config = _MODEL_CONFIG

    run_dir: str | None = None
    total_duration_seconds: float | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    change_points: list[ChangePointRecord] = Field(default_factory=list)
    phases: list[PhaseRecord] = Field(default_factory=list)
    overview_report: str | None = None


# --------------------------------------------------------------------- comparison


class ComparisonFindings(BaseModel):
    model_config = _MODEL_CONFIG

    mode: str | None = None
    mode_label: str | None = None
    runs: list[dict[str, Any]] = Field(default_factory=list)
    matrix_rows: list[dict[str, Any]] = Field(default_factory=list)
    rankings: dict[str, Any] = Field(default_factory=dict)
    pairwise_observations: list[dict[str, Any]] = Field(default_factory=list)
    common_and_unique_problems: dict[str, Any] = Field(default_factory=dict)
    static_diff: dict[str, Any] = Field(default_factory=dict)
    bottleneck_comparison: dict[str, Any] = Field(default_factory=dict)
    root_causes: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[dict[str, Any]] = Field(default_factory=list)


# --------------------------------------------------------------------- helpers

# Current schema version the writers will emit going forward.
CURRENT_SCHEMA_VERSION = 2


def try_validate(model: type[BaseModel], raw: dict[str, Any] | None,
                 *, label: str = "artifact") -> BaseModel | None:
    """Return a validated model on success, None on failure.

    Logs a one-line warning on failure so CI can surface schema drift
    while production code can keep the raw dict as a fallback.
    """
    if raw is None:
        return None
    try:
        return model.model_validate(raw)
    except ValidationError as e:
        _log.warning("schema validation failed for %s: %s", label,
                     e.errors(include_url=False))
        return None


__all__ = [
    "Manifest",
    "ManifestTarget",
    "ManifestPhase3",
    "Findings",
    "Summary",
    "Scores",
    "ScoreDetail",
    "PhasesDoc",
    "PhaseRecord",
    "ChangePointRecord",
    "ComparisonFindings",
    "CURRENT_SCHEMA_VERSION",
    "try_validate",
]
