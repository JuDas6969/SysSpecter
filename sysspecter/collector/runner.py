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

import bisect
import ctypes
import datetime as _dt
import os
import signal
import sys
import time
from typing import Any

import psutil

from ..config import (
    EXPENSIVE_COLLECTOR_INTERVAL,
    HANDLES_PROBE_INTERVAL,
    HANDLES_TOP_N_PIDS,
    LATENCY_PROBE_INTERVAL,
    MANAGED_HEAP_PROBE_INTERVAL,
    Config,
)
from ..logging_setup import get_logger
from ..manifest import build_run_manifest, mark_degraded, update_manifest_end, write_manifest
from ..paths import build_run_paths
from ..reporter.csv_export import (
    CONNECTIONS_FIELDS,
    GPU_ADAPTER_FIELDS,
    GPU_ENGINE_FIELDS,
    GPU_PROCESS_FIELDS,
    HANDLES_FIELDS,
    LATENCY_FIELDS,
    MANAGED_HEAP_FIELDS,
    NETWORK_FIELDS,
    PER_CORE_FIELDS,
    PROCESS_FIELDS,
    SYSTEM_FIELDS,
    StreamingCSV,
)
from ..reporter.json_export import atomic_write_json
from ..safe_collect import set_manifest_path
from .connections_sampler import (
    collect_connection_snapshot,
)
from .connections_sampler import (
    sample_to_dict as conn_sample_to_dict,
)
from .etw import EtwDiskSession
from .eventlog import collect_event_log_for_window
from .gpu_sampler import (
    adapter_to_dict as gpu_adapter_to_dict,
)
from .gpu_sampler import (
    collect_gpu_snapshot,
)
from .gpu_sampler import (
    engine_to_dict as gpu_engine_to_dict,
)
from .gpu_sampler import (
    proc_to_dict as gpu_proc_to_dict,
)
from .handles_sampler import collect_handles_snapshot
from .handles_sampler import to_csv_rows as handles_to_csv_rows
from .latency_sampler import collect_latency_sample
from .latency_sampler import sample_to_dict as lat_sample_to_dict
from .managed_heap_sampler import collect_managed_heap_snapshot
from .managed_heap_sampler import to_csv_rows as managed_heap_to_csv_rows
from .network_sampler import collect_network_sample
from .network_sampler import sample_to_dict as net_sample_to_dict
from .process_diff import diff_process_snapshot
from .process_sampler import (
    collect_process_sample,
    maybe_refresh_candidates,
    refresh_candidates,
    sample_to_csv_row,
)
from .service_sampler import refresh_and_diff_services
from .static import (
    collect_autoruns,
    collect_installed_programs,
    collect_process_tree_snapshot,
    collect_scheduled_tasks_summary,
    collect_service_snapshot,
    collect_static_snapshot,
)
from .system_sampler import collect_system_sample
from .system_sampler import sample_to_dict as system_sample_to_dict

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


# v3-priority-1: HIGH_PRIORITY_CLASS for the SysSpecter process. The
# v2 production review showed cadence collapsed from 1 Hz to 1/18 Hz on
# a 4-core / 16 GB host because the sampler couldn't get scheduled
# fast enough under load. Bumping our own priority class is the
# cheapest fix: only the SysSpecter process is elevated, no behaviour
# change for the user's apps. Best-effort — soft-degrade if the OS
# refuses (no admin, sandboxed, non-Windows).
#
# Constants from <winbase.h>:
#   NORMAL_PRIORITY_CLASS      0x00000020
#   HIGH_PRIORITY_CLASS        0x00000080
#   ABOVE_NORMAL_PRIORITY_CLASS 0x00008000
_PRIORITY_CLASSES: dict[int, str] = {
    0x00000040: "IDLE",
    0x00004000: "BELOW_NORMAL",
    0x00000020: "NORMAL",
    0x00008000: "ABOVE_NORMAL",
    0x00000080: "HIGH",
    0x00000100: "REALTIME",
}


def _set_high_priority_class(logger) -> str:
    """Bump our own process to HIGH_PRIORITY_CLASS on Windows.

    Returns the priority-class name actually achieved (one of
    "HIGH", "ABOVE_NORMAL", "NORMAL", "UNCHANGED") so the runner can
    record it in the manifest. Never raises.
    """
    if sys.platform != "win32":
        return "UNCHANGED"
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetCurrentProcess()
        # Try HIGH first; fall back to ABOVE_NORMAL if HIGH refused
        # (some EPM / lockdown profiles deny HIGH for non-admin).
        for cls_value, cls_name in (
            (0x00000080, "HIGH"),
            (0x00008000, "ABOVE_NORMAL"),
        ):
            ok = kernel32.SetPriorityClass(handle, cls_value)
            if ok:
                logger.info("process priority class set to %s", cls_name)
                return cls_name
        logger.warning("SetPriorityClass refused both HIGH and ABOVE_NORMAL")
        return "NORMAL"
    except Exception as e:
        logger.warning("could not set priority class: %s", e)
        return "UNCHANGED"


def _percentile(sorted_values: list[float], q: float) -> float:
    """Nearest-rank percentile on a pre-sorted list. q in [0, 100]."""
    if not sorted_values:
        return 0.0
    if q <= 0:
        return sorted_values[0]
    if q >= 100:
        return sorted_values[-1]
    # rank in [0, n-1]
    rank = (q / 100.0) * (len(sorted_values) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = rank - lo
    return sorted_values[lo] + frac * (sorted_values[hi] - sorted_values[lo])


def _summarise_cadence(
    nominal_interval_s: float, gaps: list[float],
) -> dict[str, Any]:
    """Build the manifest.cadence_quality block from observed gaps.

    Inputs:
        nominal_interval_s: what the runner asked for (e.g. 1.0)
        gaps: wall-clock seconds between consecutive system samples
              (the first sample's gap is dropped — it has no predecessor).

    Output describes the run's true cadence and flags drift. Consumers
    (notably the comparison engine) use `cadence_health` to refuse
    cross-run analyses across heterogeneous cadence quality.
    """
    real_gaps = [g for g in gaps if g > 0.0]
    if not real_gaps:
        return {
            "nominal_interval_seconds": nominal_interval_s,
            "samples_total": 0,
            "median_gap_seconds": 0.0,
            "p95_gap_seconds": 0.0,
            "max_gap_seconds": 0.0,
            "gaps_over_2x_nominal": 0,
            "gaps_over_5x_nominal": 0,
            "cadence_health": "no_data",
            "ratio_median_to_nominal": 0.0,
        }
    s = sorted(real_gaps)
    median = _percentile(s, 50.0)
    p95 = _percentile(s, 95.0)
    mx = s[-1]
    threshold_2x = 2.0 * nominal_interval_s
    threshold_5x = 5.0 * nominal_interval_s
    over_2x = len(s) - bisect.bisect_left(s, threshold_2x)
    over_5x = len(s) - bisect.bisect_left(s, threshold_5x)
    ratio = median / nominal_interval_s if nominal_interval_s > 0 else 0.0
    if ratio <= 1.5:
        health = "good"
    elif ratio <= 3.0:
        health = "degraded"
    else:
        health = "broken"
    return {
        "nominal_interval_seconds": nominal_interval_s,
        "samples_total": len(real_gaps) + 1,  # +1 for the first sample (no gap)
        "median_gap_seconds": round(median, 3),
        "p95_gap_seconds": round(p95, 3),
        "max_gap_seconds": round(mx, 3),
        "gaps_over_2x_nominal": over_2x,
        "gaps_over_5x_nominal": over_5x,
        "cadence_health": health,
        "ratio_median_to_nominal": round(ratio, 2),
    }


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
    # @safe_collect uses the manifest path to record collector failures.
    set_manifest_path(paths.manifest)

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
    # H5: long-format per-core CPU stream alongside the system timeline.
    per_core_csv = StreamingCSV(paths.timeline_per_core_csv, PER_CORE_FIELDS)
    # v3-priority-4 (H1): per-PID handle counts by object type.
    handles_csv = StreamingCSV(paths.timeline_handles_csv, HANDLES_FIELDS)
    # v3-priority-5 (H2): .NET CLR managed-heap counters per PID.
    managed_heap_csv = StreamingCSV(
        paths.timeline_managed_heap_csv, MANAGED_HEAP_FIELDS,
    )
    system_csv.open()
    process_csv.open()
    network_csv.open()
    latency_csv.open()
    connections_csv.open()
    per_core_csv.open()
    handles_csv.open()
    managed_heap_csv.open()

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
            mark_degraded(paths.manifest, "etw_disk",
                          "session failed to start (admin required?)")
            etw_session = None
        else:
            logger.info("Phase 3: ETW disk capture started")

    process_events: list[dict[str, Any]] = []
    service_events: list[dict[str, Any]] = []
    prev_proc_map = _proc_map_from_snapshot(start_procs)
    prev_services = start_services

    # v3-priority-1: bump our priority before the loop. Helps weak
    # hosts hit cadence under load. Result is recorded in the manifest
    # so the comparison engine can attribute cadence drift correctly.
    priority_class = _set_high_priority_class(logger)

    started_mono = time.monotonic()
    started_wall = time.time()
    next_tick = started_mono
    next_expensive = started_mono + EXPENSIVE_COLLECTOR_INTERVAL
    next_latency = started_mono + 5.0  # first latency probe shortly after start
    # v3-priority-4: first handles probe shortly after start (3 s) so
    # short runs still get one snapshot; subsequent ones every minute.
    next_handles = started_mono + 3.0
    # v3-priority-5: first managed-heap probe at +5 s; subsequent
    # probes every MANAGED_HEAP_PROBE_INTERVAL seconds.
    next_managed_heap = started_mono + 5.0
    next_flush = started_mono + 10.0
    next_heartbeat = started_mono + 2.0
    next_log_heartbeat = started_mono + 10.0  # touches collector.log for the stop-detector

    stop_reason = "completed"
    sample_count = 0
    # v3-priority-1: track every observed gap so we can write a
    # cadence_quality block to the manifest at run-end. The first
    # sample's gap is 0.0 (no predecessor) — _summarise_cadence
    # filters that out.
    observed_gaps: list[float] = []

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

            # v3-priority-1: pass next_tick so collect_system_sample
            # can compute sample_late_ms (= how late this tick fired
            # vs. the schedule). Without this, late_ms is always 0.
            sys_sample = collect_system_sample(started_mono, scheduled_at=next_tick)
            observed_gaps.append(sys_sample.gap_seconds)
            system_csv.write(system_sample_to_dict(sys_sample))
            # H5: emit one per-core row per sample. Same timestamp /
            # rel_seconds keys so a join recovers the system context.
            for idx, core_pct in enumerate(sys_sample.cpu_per_core_pct):
                per_core_csv.write({
                    "timestamp": sys_sample.timestamp,
                    "rel_seconds": sys_sample.rel_seconds,
                    "core_idx": idx,
                    "cpu_pct": round(float(core_pct), 1),
                })

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

            # v3-priority-4 (H1): handle-table snapshot. The single
            # most-impactful missing-data item from the v2 review.
            # Soft-degrades: collect_handles_snapshot returns [] on
            # any failure (no admin, sandboxed, ntdll missing) so we
            # log the degradation once and continue.
            if now >= next_handles:
                try:
                    h_rows = collect_handles_snapshot(
                        top_n_pids=HANDLES_TOP_N_PIDS,
                    )
                    if h_rows:
                        # Build pid → name map from the most recent
                        # process sample so the CSV is human-readable
                        # without joining against timeline_processes.
                        pid_to_name = {
                            int(s.pid): s.name for s in proc_samples
                            if getattr(s, "pid", None) and getattr(s, "name", None)
                        }
                        handles_csv.write_many(handles_to_csv_rows(
                            h_rows,
                            sys_sample.timestamp,
                            sys_sample.rel_seconds,
                            pid_to_name,
                        ))
                    elif next_handles == started_mono + 3.0:
                        # First probe came back empty — record
                        # degradation once. Subsequent empties don't
                        # spam the manifest.
                        mark_degraded(
                            paths.manifest, "handles_sampler",
                            "snapshot returned no rows (locked-down host?)",
                        )
                except Exception as e:
                    logger.warning("handle snapshot failed: %s", e)
                    mark_degraded(paths.manifest, "handles_sampler",
                                  f"{type(e).__name__}: {e}")
                next_handles = now + HANDLES_PROBE_INTERVAL

            # v3-priority-5 (H2): .NET CLR managed-heap snapshot.
            # Distinguishes native leaks (RSS up, heap flat — C/C++/COM
            # bug) from managed leaks (RSS up, gen2 also up — retained
            # roots in .NET code). Soft-degrades on hosts with no .NET
            # processes (returns []) or missing pywin32.
            if now >= next_managed_heap:
                try:
                    mh_rows = collect_managed_heap_snapshot()
                    if mh_rows:
                        managed_heap_csv.write_many(managed_heap_to_csv_rows(
                            mh_rows,
                            sys_sample.timestamp,
                            sys_sample.rel_seconds,
                        ))
                    elif next_managed_heap == started_mono + 5.0:
                        # Mark degradation once on the first empty
                        # probe — most common cause: no .NET app
                        # running on the host. Subsequent empties
                        # don't spam the manifest.
                        mark_degraded(
                            paths.manifest, "managed_heap_sampler",
                            "no .NET processes found "
                            "(category empty or .NET Core only)",
                        )
                except Exception as e:
                    logger.warning("managed-heap snapshot failed: %s", e)
                    mark_degraded(paths.manifest, "managed_heap_sampler",
                                  f"{type(e).__name__}: {e}")
                next_managed_heap = now + MANAGED_HEAP_PROBE_INTERVAL

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
                    mark_degraded(paths.manifest, "connections", f"{type(e).__name__}: {e}")

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
                        mark_degraded(paths.manifest, "gpu", f"{type(e).__name__}: {e}")

                next_expensive = now + EXPENSIVE_COLLECTOR_INTERVAL

            if now >= next_flush:
                system_csv.flush()
                process_csv.flush()
                network_csv.flush()
                latency_csv.flush()
                connections_csv.flush()
                handles_csv.flush()
                managed_heap_csv.flush()
                if gpu_engine_csv is not None:
                    gpu_engine_csv.flush()
                    gpu_process_csv.flush()
                    gpu_adapter_csv.flush()
                next_flush = now + 10.0

            if now >= next_heartbeat:
                _print_heartbeat(rel, config.duration, sys_sample)
                next_heartbeat = now + 5.0

            if now >= next_log_heartbeat:
                # Touch collector.log so sysspecter.bat stop can still find us
                # during long quiet periods where no events get logged.
                logger.info(
                    "heartbeat rel=%.1fs samples=%d cpu=%.1f%% mem=%.1f%%",
                    rel, sample_count, sys_sample.cpu_total_pct or 0.0,
                    sys_sample.mem_percent or 0.0,
                )
                next_log_heartbeat = now + 10.0

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
        per_core_csv.close()
        handles_csv.close()
        managed_heap_csv.close()
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
                mark_degraded(paths.manifest, "etw_disk", f"finalize failed: {type(e).__name__}")

        if config.enable_event_logs:
            try:
                logger.info("Phase 3: querying Windows event logs for run window")
                evs = collect_event_log_for_window(started_wall, time.time(), logger=logger)
                atomic_write_json(paths.event_log_json, evs)
            except Exception as e:
                logger.warning("Phase 3: event log collection failed: %s", e)
                mark_degraded(paths.manifest, "event_logs",
                              f"query failed: {type(e).__name__}: {e}")

        # v3-priority-1: stamp the cadence-quality block onto the
        # manifest so consumers (especially the comparison engine)
        # can refuse cross-run analyses across heterogeneous cadence.
        cadence_quality = _summarise_cadence(config.interval, observed_gaps)
        if cadence_quality["cadence_health"] != "good":
            logger.warning(
                "cadence drift detected: median %.1fs vs nominal %.1fs (health=%s, "
                "%d/%d gaps over 2× nominal)",
                cadence_quality["median_gap_seconds"],
                cadence_quality["nominal_interval_seconds"],
                cadence_quality["cadence_health"],
                cadence_quality["gaps_over_2x_nominal"],
                cadence_quality["samples_total"],
            )
        update_manifest_end(
            paths.manifest, ended_at, stop_reason, actual_duration,
            cadence_quality=cadence_quality,
            process_priority_class=priority_class,
        )

        # Field-review D3: phase3 in the manifest records what was
        # REQUESTED. Stamp a parallel phase3_captured block recording
        # what actually produced data, so consumers don't have to
        # re-walk the folder to know whether the file is just empty
        # or simply was never produced.
        try:
            from ..manifest import stamp_phase3_captured
            captured = stamp_phase3_captured(paths.run_dir)
            logger.info("phase3 captured map: %s", captured)
        except Exception as e:
            logger.warning("phase3_captured stamping failed: %s", e)

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
    set_manifest_path(None)
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
