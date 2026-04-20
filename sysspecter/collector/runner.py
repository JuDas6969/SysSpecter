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
import sys
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
    CONNECTIONS_FIELDS, GPU_ENGINE_FIELDS, GPU_PROCESS_FIELDS, GPU_ADAPTER_FIELDS,
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
from .connections_sampler import (
    collect_connection_snapshot, sample_to_dict as conn_sample_to_dict,
)
from .gpu_sampler import (
    collect_gpu_snapshot, engine_to_dict as gpu_engine_to_dict,
    proc_to_dict as gpu_proc_to_dict, adapter_to_dict as gpu_adapter_to_dict,
)
from .eventlog import collect_event_log_for_window
from .etw import EtwDiskSession


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
    logger.info("sysspecter starting run=%s mode=%s duration=%s interval=%.2fs tags=%s",
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
    connections_csv = StreamingCSV(paths.timeline_connections_csv, CONNECTIONS_FIELDS)
    system_csv.open()
    process_csv.open()
    network_csv.open()
    latency_csv.open()
    connections_csv.open()

    # Phase 3 optional streams
    gpu_engine_csv = gpu_process_csv = gpu_adapter_csv = None
    if config.enable_gpu:
        gpu_engine_csv = StreamingCSV(paths.timeline_gpu_engine_csv, GPU_ENGINE_FIELDS)
        gpu_process_csv = StreamingCSV(paths.timeline_gpu_process_csv, GPU_PROCESS_FIELDS)
        gpu_adapter_csv = StreamingCSV(paths.timeline_gpu_adapter_csv, GPU_ADAPTER_FIELDS)
        gpu_engine_csv.open()
        gpu_process_csv.open()
        gpu_adapter_csv.open()
        logger.info("Phase 3: GPU metrics enabled")

    etw_session: EtwDiskSession | None = None
    if config.enable_etw_disk:
        etw_session = EtwDiskSession(paths.etw_etl, logger=logger)
        if not etw_session.start():
            logger.warning("Phase 3: ETW disk session could not be started (admin required?)")
            etw_session = None
        else:
            logger.info("Phase 3: ETW disk capture started")

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
    next_heartbeat = started_mono + 2.0

    stop_reason = "completed"
    sample_count = 0

    _print_start_banner(paths, config)

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

                try:
                    conn_samples = collect_connection_snapshot(started_mono)
                    connections_csv.write_many([conn_sample_to_dict(c) for c in conn_samples])
                except Exception as e:
                    logger.warning("connection snapshot failed: %s", e)

                if config.enable_gpu and gpu_engine_csv is not None:
                    try:
                        eng, proc_gpu, adp = collect_gpu_snapshot(started_mono, logger)
                        if eng:
                            gpu_engine_csv.write_many([gpu_engine_to_dict(e) for e in eng])
                        if proc_gpu:
                            gpu_process_csv.write_many([gpu_proc_to_dict(p) for p in proc_gpu])
                        if adp:
                            gpu_adapter_csv.write_many([gpu_adapter_to_dict(a) for a in adp])
                    except Exception as e:
                        logger.warning("gpu snapshot failed: %s", e)

                next_expensive = now + EXPENSIVE_COLLECTOR_INTERVAL

            if now >= next_flush:
                system_csv.flush()
                process_csv.flush()
                network_csv.flush()
                latency_csv.flush()
                connections_csv.flush()
                if gpu_engine_csv is not None:
                    gpu_engine_csv.flush()
                    gpu_process_csv.flush()
                    gpu_adapter_csv.flush()
                next_flush = now + 10.0

            if now >= next_heartbeat:
                _print_heartbeat(rel, config.duration, sys_sample)
                next_heartbeat = now + 5.0

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
        _print_stopping(stop_reason)
        system_csv.close()
        process_csv.close()
        network_csv.close()
        latency_csv.close()
        connections_csv.close()
        if gpu_engine_csv is not None:
            gpu_engine_csv.close()
            gpu_process_csv.close()
            gpu_adapter_csv.close()

        end_mono = time.monotonic()
        actual_duration = end_mono - started_mono
        ended_at = _dt.datetime.now()
        logger.info("stopping: reason=%s samples=%d duration=%.1fs",
                    stop_reason, sample_count, actual_duration)

        atomic_write_json(paths.process_events, process_events)
        atomic_write_json(paths.service_events, service_events)

        if etw_session is not None:
            try:
                logger.info("Phase 3: stopping ETW capture and summarizing")
                summary = etw_session.stop_and_summarize(paths.etw_etl)
                atomic_write_json(paths.etw_disk_summary, summary)
            except Exception as e:
                logger.warning("Phase 3: ETW finalize failed: %s", e)

        if config.enable_event_logs:
            try:
                logger.info("Phase 3: querying Windows event logs for run window")
                evs = collect_event_log_for_window(started_wall, time.time(), logger=logger)
                atomic_write_json(paths.event_log_json, evs)
            except Exception as e:
                logger.warning("Phase 3: event log collection failed: %s", e)

        update_manifest_end(paths.manifest, ended_at, stop_reason, actual_duration)

    print("  Analysiere Daten und baue Report...", flush=True)
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

    _print_done_banner(paths.run_dir, actual_duration, sample_count)
    return paths.run_dir


# --- DAU-friendly console output -------------------------------------------

def _print_start_banner(paths, config) -> None:
    mode = config.mode
    if config.duration is None:
        dur_text = "manueller Stopp (Ctrl+C oder 'sysspecter.bat stop')"
    else:
        mins = config.duration // 60
        secs = config.duration % 60
        dur_text = f"{config.duration}s ({mins}m {secs}s)"
    phase3 = []
    if config.enable_gpu:
        phase3.append("GPU")
    if config.enable_event_logs:
        phase3.append("EventLog")
    if config.enable_etw_disk:
        phase3.append("ETW")
    phase3_text = ("  Phase 3: " + ", ".join(phase3)) if phase3 else ""

    bar = "=" * 68
    print()
    print(bar)
    print("  SysSpecter  -  See everything. Find the cause.")
    print(bar)
    print(f"  Modus:     {mode}")
    print(f"  Dauer:     {dur_text}")
    print(f"  Ausgabe:   {paths.run_dir}")
    if phase3_text:
        print(phase3_text)
    print(bar)
    print("  >> Zum STOPPEN (eine der beiden Varianten):")
    print("     1) Ctrl+C in diesem Fenster druecken")
    print("     2) In einem zweiten Fenster:  sysspecter.bat stop")
    print("     Der Report wird danach automatisch gebaut.")
    print(bar, flush=True)


def _fmt_elapsed(rel: float) -> str:
    s = int(rel)
    h, rem = divmod(s, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h:d}h{m:02d}m{s:02d}s"
    return f"{m:02d}m{s:02d}s"


def _print_heartbeat(rel: float, duration: int | None, sys_sample) -> None:
    elapsed = _fmt_elapsed(rel)
    if duration is None:
        progress = "manueller Stopp"
    else:
        pct = min(100.0, 100.0 * rel / duration)
        progress = f"{pct:5.1f}% von {duration}s"
    cpu = getattr(sys_sample, "cpu_total_pct", 0.0) or 0.0
    mem = getattr(sys_sample, "mem_percent", 0.0) or 0.0
    try:
        msg = (f"  [laeuft] {elapsed}  {progress}  "
               f"CPU {cpu:5.1f}%  RAM {mem:5.1f}%   (Ctrl+C = stoppen)")
    except Exception:
        msg = f"  [laeuft] {elapsed}  (Ctrl+C = stoppen)"
    # Overwrite the same line in-place if stdout is a TTY, else newline
    if sys.stdout.isatty():
        sys.stdout.write("\r" + msg.ljust(90))
        sys.stdout.flush()
    else:
        print(msg, flush=True)


def _print_stopping(reason: str) -> None:
    reason_map = {
        "keyboard_interrupt": "Stopp durch Ctrl+C",
        "manual_stop_signal": "Stopp-Signal empfangen",
        "manual_stop_sentinel": "STOP-Datei gefunden",
        "duration_reached": "Zeit abgelaufen",
        "completed": "fertig",
    }
    text = reason_map.get(reason, reason)
    if sys.stdout.isatty():
        sys.stdout.write("\n")
    print()
    print("=" * 68)
    print(f"  Wird beendet ({text}). Schreibe Daten ab, bitte warten...")
    print("=" * 68, flush=True)


def _print_done_banner(run_dir: str, actual_duration: float, samples: int) -> None:
    report = os.path.join(run_dir, "final_report.html")
    bar = "=" * 68
    print()
    print(bar)
    print("  Fertig!")
    print(bar)
    print(f"  Gemessen:  {_fmt_elapsed(actual_duration)}  ({samples} Samples)")
    print(f"  Report:    {report}")
    print()
    print("  Oeffnen mit:")
    print(f"     start {report}")
    print(bar, flush=True)
