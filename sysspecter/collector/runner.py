"""Collector runner — timed loop with manual stop and graceful shutdown.

Responsibilities:
- Build run folder + manifest
- Collect static snapshot at start
- Capture process tree + service snapshot at start
- Run per-second sampling (cheap tier) and periodic (expensive tier)
- Stream CSVs
- On Ctrl+C or STOP sentinel, finalize: end-snapshot, analyzer, reporter
"""

from __future__ import annotations

import datetime as _dt
import os
import signal
import time
from typing import Any

import psutil

from ..config import (
    Config, EXPENSIVE_COLLECTOR_INTERVAL, LATENCY_PROBE_INTERVAL,
)
from ..logging_setup import get_logger
from ..manifest import build_run_manifest, write_manifest, update_manifest_end
from ..paths import build_run_paths
from ..reporter.csv_export import (
    StreamingCSV, SYSTEM_FIELDS, PROCESS_FIELDS, NETWORK_FIELDS, LATENCY_FIELDS,
)
from ..reporter.json_export import atomic_write_json
from .static import (
    collect_static_snapshot, collect_installed_programs, collect_autoruns,
    collect_scheduled_tasks_summary, collect_process_tree_snapshot,
    collect_service_snapshot,
)
from .system_sampler import collect_system_sample, sample_to_dict as system_sample_to_dict
from .process_sampler import (
    collect_process_sample, sample_to_csv_row, refresh_candidates,
    maybe_refresh_candidates,
)
from .network_sampler import collect_network_sample, sample_to_dict as net_sample_to_dict
from .latency_sampler import collect_latency_sample, sample_to_dict as lat_sample_to_dict
from .service_sampler import refresh_and_diff_services
from .process_diff import diff_process_snapshot


_stop_requested = False


def _install_signal_handlers() -> None:
    def handler(signum, frame):
        global _stop_requested
        _stop_requested = True
    try:
        signal.signal(signal.SIGINT, handler)
    except Exception:
        pass
    try:
        signal.signal(signal.SIGBREAK, handler)  # Windows Ctrl+Break
    except Exception:
        pass


def _proc_map_from_snapshot(snap: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    return {p["pid"]: p for p in snap if p.get("pid") is not None}


def run_monitor(config: Config) -> str:
    """Run one monitoring session. Returns path to the run folder."""
    global _stop_requested
    _stop_requested = False

    paths = build_run_paths(config.output_root)
    logger = get_logger("collector", paths.collector_log)
    logger.info("pcb starting run=%s mode=%s duration=%s interval=%.2fs tags=%s",
                paths.run_id, config.mode, config.duration, config.interval, config.tags)

    manifest = build_run_manifest(paths, config)
    write_manifest(paths.manifest, manifest)

    if manifest.get("privilege_level") != "admin":
        logger.warning(
            "Not running as admin. Some counters (handles on protected processes, "
            "certain WMI classes) may be unavailable.")

    _install_signal_handlers()

    logger.info("Collecting static snapshot...")
    static = collect_static_snapshot(logger=logger)
    static["installed_programs"] = collect_installed_programs(logger=logger)
    static["autoruns"] = collect_autoruns(logger=logger)
    static["scheduled_tasks_summary"] = collect_scheduled_tasks_summary(logger=logger)
    atomic_write_json(paths.static_snapshot, static)

    logger.info("Capturing start-of-run process tree + service snapshot...")
    start_procs = collect_process_tree_snapshot()
    atomic_write_json(paths.process_start_snapshot, start_procs)
    start_services = collect_service_snapshot(logger=logger)
    atomic_write_json(paths.service_start_snapshot, start_services)

    psutil.cpu_percent(interval=None, percpu=True)
    psutil.cpu_percent(interval=None)

    refresh_candidates(config.target_pid, config.target_name, config.target_path)

    system_csv = StreamingCSV(paths.timeline_system_csv, SYSTEM_FIELDS)
    process_csv = StreamingCSV(paths.timeline_processes_csv, PROCESS_FIELDS)
    network_csv = StreamingCSV(paths.timeline_network_csv, NETWORK_FIELDS)
    latency_csv = StreamingCSV(paths.timeline_latency_csv, LATENCY_FIELDS)
    system_csv.open()
    process_csv.open()
    network_csv.open()
    latency_csv.open()

    process_events: list[dict[str, Any]] = []
    service_events: list[dict[str, Any]] = []
    prev_proc_map = _proc_map_from_snapshot(start_procs)
    prev_services = start_services

    started_mono = time.monotonic()
    started_wall = time.time()
    next_tick = started_mono
    next_expensive = started_mono + EXPENSIVE_COLLECTOR_INTERVAL
    next_latency = started_mono + 5.0  # first latency probe shortly after start
    next_flush = started_mono + 10.0

    stop_reason = "completed"
    sample_count = 0

    try:
        while True:
            now = time.monotonic()
            rel = now - started_mono

            if _stop_requested:
                stop_reason = "manual_stop_signal"
                break
            if os.path.exists(paths.stop_sentinel):
                stop_reason = "manual_stop_sentinel"
                break
            if config.duration is not None and rel >= config.duration:
                stop_reason = "duration_reached"
                break

            sys_sample = collect_system_sample(started_mono)
            system_csv.write(system_sample_to_dict(sys_sample))

            maybe_refresh_candidates(config.target_pid, config.target_name, config.target_path)
            proc_samples = collect_process_sample(
                config.target_pid, config.target_name, config.target_path
            )
            process_csv.write_many([
                sample_to_csv_row(s, sys_sample.rel_seconds, sys_sample.timestamp)
                for s in proc_samples
            ])

            net_samples = collect_network_sample(started_mono)
            network_csv.write_many([net_sample_to_dict(s) for s in net_samples])

            if now >= next_latency:
                lat_samples = collect_latency_sample(
                    config.latency_targets, started_mono, logger=logger
                )
                latency_csv.write_many([lat_sample_to_dict(s) for s in lat_samples])
                next_latency = now + LATENCY_PROBE_INTERVAL

            if now >= next_expensive:
                curr_procs = collect_process_tree_snapshot()
                curr_map = _proc_map_from_snapshot(curr_procs)
                events = diff_process_snapshot(
                    prev_proc_map, curr_map, rel, sys_sample.timestamp
                )
                if events:
                    process_events.extend(events)
                prev_proc_map = curr_map

                new_services, svc_events = refresh_and_diff_services(
                    prev_services, rel, sys_sample.timestamp
                )
                prev_services = new_services
                if svc_events:
                    service_events.extend(svc_events)

                next_expensive = now + EXPENSIVE_COLLECTOR_INTERVAL

            if now >= next_flush:
                system_csv.flush()
                process_csv.flush()
                network_csv.flush()
                latency_csv.flush()
                next_flush = now + 10.0

            sample_count += 1

            next_tick += config.interval
            sleep_for = next_tick - time.monotonic()
            if sleep_for < 0:
                logger.debug("collector tick behind schedule by %.3fs", -sleep_for)
                next_tick = time.monotonic()
                continue
            time.sleep(sleep_for)

    except KeyboardInterrupt:
        stop_reason = "keyboard_interrupt"
    except Exception as e:
        logger.exception("collector loop crashed: %s", e)
        stop_reason = f"error:{type(e).__name__}"
    finally:
        system_csv.close()
        process_csv.close()
        network_csv.close()
        latency_csv.close()

        end_mono = time.monotonic()
        actual_duration = end_mono - started_mono
        ended_at = _dt.datetime.now()
        logger.info("stopping: reason=%s samples=%d duration=%.1fs",
                    stop_reason, sample_count, actual_duration)

        atomic_write_json(paths.process_events, process_events)
        atomic_write_json(paths.service_events, service_events)

        update_manifest_end(paths.manifest, ended_at, stop_reason, actual_duration)

    logger.info("running analysis + reports...")
    try:
        from ..analyzer.pipeline import analyze_run
        analyze_run(paths.run_dir)
    except Exception as e:
        logger.exception("analyzer failed: %s", e)

    try:
        from ..reporter.html_report import build_report
        build_report(paths.run_dir)
    except Exception as e:
        logger.exception("reporter failed: %s", e)

    return paths.run_dir
