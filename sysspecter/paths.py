"""Run folder layout and manifest paths."""

from __future__ import annotations

import datetime as _dt
import os
import socket
import uuid
from dataclasses import dataclass


@dataclass
class RunPaths:
    root: str
    run_dir: str
    logs_dir: str
    run_id: str
    hostname: str
    started_at: _dt.datetime

    @property
    def manifest(self) -> str:
        return os.path.join(self.run_dir, "manifest.json")

    @property
    def static_snapshot(self) -> str:
        return os.path.join(self.run_dir, "static_snapshot.json")

    @property
    def process_start_snapshot(self) -> str:
        return os.path.join(self.run_dir, "process_start_snapshot.json")

    @property
    def service_start_snapshot(self) -> str:
        return os.path.join(self.run_dir, "service_start_snapshot.json")

    @property
    def timeline_system_csv(self) -> str:
        return os.path.join(self.run_dir, "timeline_system.csv")

    @property
    def timeline_processes_csv(self) -> str:
        return os.path.join(self.run_dir, "timeline_processes.csv")

    @property
    def timeline_network_csv(self) -> str:
        return os.path.join(self.run_dir, "timeline_network.csv")

    @property
    def timeline_latency_csv(self) -> str:
        return os.path.join(self.run_dir, "timeline_latency.csv")

    @property
    def timeline_connections_csv(self) -> str:
        return os.path.join(self.run_dir, "timeline_connections.csv")

    @property
    def timeline_gpu_engine_csv(self) -> str:
        return os.path.join(self.run_dir, "timeline_gpu_engine.csv")

    @property
    def timeline_gpu_process_csv(self) -> str:
        return os.path.join(self.run_dir, "timeline_gpu_process.csv")

    @property
    def timeline_gpu_adapter_csv(self) -> str:
        return os.path.join(self.run_dir, "timeline_gpu_adapter.csv")

    @property
    def event_log_json(self) -> str:
        return os.path.join(self.run_dir, "event_log.json")

    @property
    def etw_disk_summary(self) -> str:
        return os.path.join(self.run_dir, "etw_disk_summary.json")

    @property
    def etw_etl(self) -> str:
        return os.path.join(self.run_dir, "etw_disk.etl")

    @property
    def process_events(self) -> str:
        return os.path.join(self.run_dir, "process_events.json")

    @property
    def service_events(self) -> str:
        return os.path.join(self.run_dir, "service_events.json")

    @property
    def findings(self) -> str:
        return os.path.join(self.run_dir, "findings.json")

    @property
    def scores(self) -> str:
        return os.path.join(self.run_dir, "scores.json")

    @property
    def final_html(self) -> str:
        return os.path.join(self.run_dir, "final_report.html")

    @property
    def final_md(self) -> str:
        return os.path.join(self.run_dir, "final_report.md")

    @property
    def stop_sentinel(self) -> str:
        return os.path.join(self.run_dir, "STOP")

    @property
    def collector_log(self) -> str:
        return os.path.join(self.logs_dir, "collector.log")

    @property
    def analyzer_log(self) -> str:
        return os.path.join(self.logs_dir, "analyzer.log")

    @property
    def reporter_log(self) -> str:
        return os.path.join(self.logs_dir, "reporter.log")


def build_run_paths(output_root: str) -> RunPaths:
    hostname = socket.gethostname().upper()
    started_at = _dt.datetime.now()
    run_id = started_at.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
    run_dir = os.path.join(output_root, "Runs", f"{hostname}_{run_id}")
    logs_dir = os.path.join(run_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    return RunPaths(
        root=output_root,
        run_dir=run_dir,
        logs_dir=logs_dir,
        run_id=run_id,
        hostname=hostname,
        started_at=started_at,
    )


@dataclass
class ComparisonPaths:
    comparison_dir: str
    comparison_id: str

    @property
    def manifest(self) -> str:
        return os.path.join(self.comparison_dir, "comparison_manifest.json")

    @property
    def matrix_csv(self) -> str:
        return os.path.join(self.comparison_dir, "comparison_matrix.csv")

    @property
    def findings(self) -> str:
        return os.path.join(self.comparison_dir, "comparison_findings.json")

    @property
    def scores(self) -> str:
        return os.path.join(self.comparison_dir, "comparison_scores.json")

    @property
    def html(self) -> str:
        return os.path.join(self.comparison_dir, "comparison_report.html")

    @property
    def md(self) -> str:
        return os.path.join(self.comparison_dir, "comparison_report.md")


def build_comparison_paths(output_root: str) -> ComparisonPaths:
    started_at = _dt.datetime.now()
    comparison_id = started_at.strftime("CMP_%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
    comparison_dir = os.path.join(output_root, "Comparisons", comparison_id)
    os.makedirs(comparison_dir, exist_ok=True)
    return ComparisonPaths(comparison_dir=comparison_dir, comparison_id=comparison_id)
