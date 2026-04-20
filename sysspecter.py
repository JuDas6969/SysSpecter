"""SysSpecter — Windows performance diagnostic + comparative benchmark framework.

See everything. Find the cause.

Main launcher. Subcommands:
    monitor   — run a monitoring session (support/baseline/workload mode)
    stop      — stop the currently running monitor session (STOP sentinel)
    compare   — compare multiple completed runs
    report    — rebuild reports from an existing run folder
    inspect   — quick console summary of a completed run
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Sequence

from sysspecter.config import (
    Config,
    DEFAULT_INTERVAL_SECONDS,
    DEFAULT_DURATION_SECONDS_BASELINE,
    DEFAULT_DURATION_SECONDS_WORKLOAD,
    DEFAULT_OUTPUT_ROOT,
    DEFAULT_LATENCY_TARGETS,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sysspecter",
        description="SysSpecter — Windows performance diagnostic + benchmark framework",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    m = sub.add_parser("monitor", help="Run a monitoring session")
    m.add_argument(
        "--mode",
        choices=["support", "baseline", "workload"],
        default="support",
    )
    m.add_argument("--duration", type=int, default=None,
                   help="Duration in seconds. Default: manual-stop (support) / 1800 (baseline/workload)")
    m.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_SECONDS)
    m.add_argument("--target-name", default=None)
    m.add_argument("--target-pid", type=int, default=None)
    m.add_argument("--target-path", default=None)
    m.add_argument("--tag", action="append", default=[], dest="tags")
    m.add_argument("--latency-target", action="append", default=None, dest="latency_targets",
                   help="Latency probe target (host or IP). Repeat for multiple.")
    m.add_argument("--output-root", default=DEFAULT_OUTPUT_ROOT)
    m.add_argument("--manual-stop", action="store_true",
                   help="Force manual-stop mode even in baseline/workload")

    m.add_argument("--gpu", action="store_true",
                   help="Phase 3: sample GPU engine/memory counters (optional)")
    m.add_argument("--event-logs", action="store_true", dest="event_logs",
                   help="Phase 3: query Windows event logs for the run window (optional)")
    m.add_argument("--etw", action="store_true",
                   help="Phase 3: capture kernel disk-I/O ETW trace for per-process "
                        "byte attribution (admin required; optional)")
    m.add_argument("--phase3", action="store_true",
                   help="Enable all Phase 3 optional collectors: --gpu --event-logs --etw")

    c = sub.add_parser("compare", help="Compare multiple completed runs")
    c.add_argument("--runs", nargs="+", default=None,
                   help="Explicit list of run folders to compare")
    c.add_argument("--input", default=None,
                   help="Auto-discover runs under this folder (e.g. C:\\Temp\\SysSpecter\\Runs)")
    c.add_argument("--output-root", default=DEFAULT_OUTPUT_ROOT)

    s = sub.add_parser("stop", help="Stop the active monitor run (creates STOP sentinel)")
    s.add_argument("--run", default=None,
                   help="Specific run folder to stop. Default: auto-detect the latest active run.")
    s.add_argument("--output-root", default=DEFAULT_OUTPUT_ROOT,
                   help="Root folder to search for active runs (default: %(default)s)")

    r = sub.add_parser("report", help="Rebuild reports from an existing run")
    r.add_argument("--run", required=True, help="Path to a run folder")

    i = sub.add_parser("inspect", help="Quick console summary of a completed run")
    i.add_argument("--run", required=True, help="Path to a run folder")

    return parser


def _cmd_monitor(args: argparse.Namespace) -> int:
    from sysspecter.collector.runner import run_monitor

    if args.duration is None:
        if args.mode == "support" or args.manual_stop:
            duration = None
        elif args.mode == "baseline":
            duration = DEFAULT_DURATION_SECONDS_BASELINE
        else:
            duration = DEFAULT_DURATION_SECONDS_WORKLOAD
    else:
        duration = args.duration

    if args.mode == "workload" and not (args.target_name or args.target_pid or args.target_path):
        print("warning: workload mode running without --target-name/--target-pid/--target-path. "
              "Offender detection will still work but target attribution will be generic.",
              file=sys.stderr)

    config = Config(
        output_root=args.output_root,
        interval=args.interval,
        mode=args.mode,
        duration=duration,
        target_name=args.target_name,
        target_pid=args.target_pid,
        target_path=args.target_path,
        tags=list(args.tags or []),
        latency_targets=list(args.latency_targets) if args.latency_targets else list(DEFAULT_LATENCY_TARGETS),
        manual_stop=args.manual_stop or (args.mode == "support" and args.duration is None),
        enable_gpu=args.gpu or args.phase3,
        enable_event_logs=args.event_logs or args.phase3,
        enable_etw_disk=args.etw or args.phase3,
    )
    run_monitor(config)
    return 0


def _cmd_compare(args: argparse.Namespace) -> int:
    from sysspecter.comparer.compare_runs import run_compare

    if not args.runs and not args.input:
        print("error: provide --runs or --input", file=sys.stderr)
        return 2

    runs: list[str] = []
    if args.runs:
        runs.extend(args.runs)
    if args.input:
        if not os.path.isdir(args.input):
            print(f"error: --input is not a directory: {args.input}", file=sys.stderr)
            return 2
        for name in sorted(os.listdir(args.input)):
            candidate = os.path.join(args.input, name)
            if os.path.isdir(candidate) and os.path.exists(os.path.join(candidate, "manifest.json")):
                runs.append(candidate)

    runs = [os.path.abspath(p) for p in runs]
    if len(runs) < 2:
        print(f"error: need at least 2 runs to compare (found {len(runs)})", file=sys.stderr)
        return 2

    out = run_compare(runs, args.output_root)
    print(f"Comparison complete. Artifacts: {out}")
    return 0


def _find_active_run(output_root: str, freshness_seconds: float = 30.0) -> str | None:
    """Return the path of the currently running monitor session.

    A run is considered "active" when its collector.log was written to within
    the last `freshness_seconds`. This avoids targeting stale folders from
    previous runs that were killed without finalizing.
    """
    import time

    runs_root = os.path.join(output_root, "Runs")
    if not os.path.isdir(runs_root):
        return None
    now = time.time()
    candidates: list[tuple[float, str, bool]] = []
    for name in os.listdir(runs_root):
        folder = os.path.join(runs_root, name)
        if not os.path.isdir(folder):
            continue
        if not os.path.exists(os.path.join(folder, "manifest.json")):
            continue
        if os.path.exists(os.path.join(folder, "final_report.html")):
            continue
        log = os.path.join(folder, "logs", "collector.log")
        try:
            log_mtime = os.path.getmtime(log)
        except OSError:
            continue
        if now - log_mtime > freshness_seconds:
            continue
        has_stop = os.path.exists(os.path.join(folder, "STOP"))
        candidates.append((log_mtime, folder, has_stop))
    if not candidates:
        return None
    fresh = [c for c in candidates if not c[2]]
    pool = fresh or candidates
    pool.sort(key=lambda c: c[0], reverse=True)
    return pool[0][1]


def _cmd_stop(args: argparse.Namespace) -> int:
    if args.run:
        run = os.path.abspath(args.run)
        if not os.path.isdir(run):
            print(f"error: not a directory: {run}", file=sys.stderr)
            return 2
    else:
        run = _find_active_run(args.output_root)
        if run is None:
            print(f"Keine aktive Session gefunden unter {os.path.join(args.output_root, 'Runs')}.",
                  file=sys.stderr)
            print("Tipp: Starte zuerst 'sysspecter.bat monitor ...' in einem anderen Fenster.",
                  file=sys.stderr)
            return 1

    stop_file = os.path.join(run, "STOP")
    if os.path.exists(stop_file):
        print(f"STOP-Datei existiert bereits: {stop_file}")
        print("Die laufende Session sollte sich jeden Moment beenden.")
        return 0

    try:
        with open(stop_file, "w", encoding="utf-8") as f:
            f.write("stop\n")
    except OSError as e:
        print(f"error: STOP-Datei konnte nicht angelegt werden: {e}", file=sys.stderr)
        return 1

    print("============================================================")
    print(" Stopp-Signal gesendet")
    print("============================================================")
    print(f" Run:  {run}")
    print(f" Datei: {stop_file}")
    print()
    print(" Die laufende Session wird in wenigen Sekunden beendet")
    print(" und erstellt automatisch den Abschlussbericht.")
    print("============================================================")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    from sysspecter.reporter.html_report import regenerate_report

    run = os.path.abspath(args.run)
    if not os.path.isdir(run):
        print(f"error: not a directory: {run}", file=sys.stderr)
        return 2
    regenerate_report(run)
    print(f"Report rebuilt: {os.path.join(run, 'final_report.html')}")
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    from sysspecter.comparer.loader import load_run_summary

    run = os.path.abspath(args.run)
    summary = load_run_summary(run)
    print(summary)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "monitor":
        return _cmd_monitor(args)
    if args.command == "stop":
        return _cmd_stop(args)
    if args.command == "compare":
        return _cmd_compare(args)
    if args.command == "report":
        return _cmd_report(args)
    if args.command == "inspect":
        return _cmd_inspect(args)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
