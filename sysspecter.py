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
    m.add_argument("--tag", action="append", default=[], dest="tags",
                   help="Free-form tag stored alongside the run. Repeat for "
                        "multiple. Use --meta KEY=VALUE for structured tags "
                        "that fleet aggregation can filter on.")
    # Field-review M2: structured fleet metadata.
    m.add_argument("--meta", action="append", default=[], dest="meta_kv",
                   metavar="KEY=VALUE",
                   help="Structured metadata, repeatable. e.g. "
                        "--meta department=engineering "
                        "--meta change_under_test=defender-1.1.27. Stored on "
                        "the manifest under a `meta` block, distinct from "
                        "free-form --tag entries.")
    m.add_argument("--department", default=None,
                   help="Convenience for --meta department=…")
    m.add_argument("--ticket", default=None,
                   help="Convenience for --meta ticket=… (e.g. PERF-1234)")
    m.add_argument("--scenario", default=None,
                   help="Convenience for --meta scenario=… "
                        "(e.g. post-update-regression-check)")
    m.add_argument("--change-under-test", default=None, dest="change_under_test",
                   help="Convenience for --meta change_under_test=… "
                        "(e.g. defender-engine-1.1.27)")
    m.add_argument("--machine-class", default=None, dest="machine_class",
                   help="Convenience for --meta machine_class=… "
                        "(e.g. developer-workstation, kiosk, terminal-server)")
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

    m.add_argument("--redact", action="store_true",
                   help="After the run finishes, also produce a sanitized "
                        "sibling folder with hostname / username / serials "
                        "replaced by stable hashes (HOST-7f3a, USER-bb9c, …) "
                        "and credential-looking strings stripped from text "
                        "fields. Use this when the run will be shared with "
                        "an external vendor.")

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
    r.add_argument("--trim-seconds", type=float, default=None, dest="trim_seconds",
                   help="Only include data from the first N seconds of the run "
                        "(e.g. --trim-seconds 800). Non-destructive: original CSVs "
                        "are left intact; only final_report.html/.md, findings.json, "
                        "scores.json are rebuilt with the trimmed view.")

    i = sub.add_parser("inspect", help="Quick console summary of a completed run")
    i.add_argument("--run", required=True, help="Path to a run folder")

    z = sub.add_parser("sanitize",
                       help="Copy a run into a shippable, de-identified sibling folder")
    z.add_argument("--run", required=True, help="Path to a run folder")
    z.add_argument("--out", default=None,
                   help="Output folder for the sanitized copy "
                        "(default: <run>_sanitized next to it)")

    g = sub.add_parser("gui", help="Launch the Tkinter-based graphical interface")
    g.add_argument("--output-root", default=DEFAULT_OUTPUT_ROOT,
                   help="Default output root shown in the UI (default: %(default)s)")

    doc = sub.add_parser("doctor",
                         help="Self-check: verify Python / PowerShell / logman / "
                              "tracerpt / output-root are usable")
    doc.add_argument("--output-root", default=DEFAULT_OUTPUT_ROOT,
                     help="Output root to probe for writability (default: %(default)s)")

    sp = sub.add_parser(
        "split",
        help="Split a finished run into phases based on metric change points",
    )
    sp.add_argument("--run", required=True, help="Path to a run folder")
    sp.add_argument("--min-phase-seconds", type=float, default=None,
                    dest="min_phase_seconds",
                    help="Drop/merge phases shorter than this many seconds. "
                         "Auto (~5%% of run, clipped to 60 s..1 h) when omitted.")
    sp.add_argument("--window-seconds", type=float, default=None,
                    dest="window_seconds",
                    help="Sliding-window size in seconds for change-point detection. "
                         "Auto (~2%% of run, clipped to 30 s..10 min) when omitted.")
    sp.add_argument("--step-threshold", type=float, default=6.0,
                    dest="step_threshold",
                    help="Minimum per-metric mean shift (percent points) to flag a step (default: 6).")
    sp.add_argument("--slope-threshold", type=float, default=0.6,
                    dest="slope_threshold",
                    help="Minimum slope shift to flag a regime change (default: 0.6).")
    sp.add_argument("--proximity-seconds", type=float, default=None,
                    dest="proximity_seconds",
                    help="Merge change points closer than this many seconds. "
                         "Auto (~2.5%% of run) when omitted.")
    sp.add_argument("--no-subreports", action="store_true", dest="no_subreports",
                    help="Only detect phases; skip generating per-phase HTML reports")

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

    # Field-review M2: collect structured metadata from the convenience
    # flags + repeated --meta KEY=VALUE pairs. Convenience flags win
    # over generic --meta of the same key.
    meta: dict[str, str] = {}
    for kv in (args.meta_kv or []):
        if "=" not in kv:
            print(f"warning: --meta '{kv}' has no '=' — skipped",
                  file=sys.stderr)
            continue
        k, _, v = kv.partition("=")
        k = k.strip().lower()
        v = v.strip()
        if not k:
            print(f"warning: --meta '{kv}' has empty key — skipped",
                  file=sys.stderr)
            continue
        meta[k] = v
    for arg_name, meta_key in (
        ("department", "department"),
        ("ticket", "ticket"),
        ("scenario", "scenario"),
        ("change_under_test", "change_under_test"),
        ("machine_class", "machine_class"),
    ):
        v = getattr(args, arg_name, None)
        if isinstance(v, str) and v.strip():
            meta[meta_key] = v.strip()

    config = Config(
        output_root=args.output_root,
        interval=args.interval,
        mode=args.mode,
        duration=duration,
        target_name=args.target_name,
        target_pid=args.target_pid,
        target_path=args.target_path,
        tags=list(args.tags or []),
        meta=meta,
        latency_targets=list(args.latency_targets) if args.latency_targets else list(DEFAULT_LATENCY_TARGETS),
        manual_stop=args.manual_stop or (args.mode == "support" and args.duration is None),
        enable_gpu=args.gpu or args.phase3,
        enable_event_logs=args.event_logs or args.phase3,
        enable_etw_disk=args.etw or args.phase3,
    )
    try:
        run_dir = run_monitor(config)
    except Exception as e:
        from sysspecter.paths import OutputRootError
        if isinstance(e, OutputRootError):
            print(f"\nERROR: {e}\n", file=sys.stderr)
            return 2
        raise

    # Field-review M1: --redact produces a sanitized sibling folder so
    # the operator can hand the run to a vendor without exporting a
    # second time. The original run is kept intact for local analysis.
    if getattr(args, "redact", False) and run_dir:
        try:
            from sysspecter.sanitizer import sanitize_run
            from sysspecter.sanitizer_verify import verify
            sanitized = sanitize_run(run_dir)
            leaks = verify(sanitized)
            if leaks:
                print(
                    f"\nWARNING: --redact left {len(leaks)} identifier "
                    f"occurrence(s) in {sanitized}. Review before sharing.\n",
                    file=sys.stderr,
                )
            else:
                print(f"\nSanitized copy ready: {sanitized}\n")
        except Exception as e:
            print(f"\nWARNING: --redact failed: {e}. "
                  f"Original run at {run_dir} is unchanged.\n",
                  file=sys.stderr)
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


def _find_active_run(output_root: str, freshness_seconds: float = 120.0) -> str | None:
    """Return the path of the currently running monitor session.

    A run is considered "active" when its collector.log was written to within
    the last `freshness_seconds`. The collector emits a throttled heartbeat
    log entry every 10 s so this detector keeps working even during long
    quiet stretches.
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
    trim = getattr(args, "trim_seconds", None)
    if trim is not None and trim <= 0:
        print("error: --trim-seconds must be > 0", file=sys.stderr)
        return 2
    regenerate_report(run, max_rel_seconds=trim)
    print(f"Report rebuilt: {os.path.join(run, 'final_report.html')}")
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    from sysspecter.comparer.loader import load_run_summary

    run = os.path.abspath(args.run)
    summary = load_run_summary(run)
    print(summary)
    return 0


def _cmd_gui(args: argparse.Namespace) -> int:
    from sysspecter.gui.app import run_gui
    return run_gui(output_root=args.output_root)


def _cmd_doctor(args: argparse.Namespace) -> int:
    from sysspecter.doctor import print_report, run_all
    return print_report(run_all(args.output_root))


def _cmd_sanitize(args: argparse.Namespace) -> int:
    import json

    from sysspecter.sanitizer import sanitize_run
    from sysspecter.sanitizer_verify import verify

    run = os.path.abspath(args.run)
    if not os.path.isdir(run):
        print(f"error: not a directory: {run}", file=sys.stderr)
        return 2

    # Snapshot the originals BEFORE writing the sanitized copy so verify can
    # look for the real pre-redaction identifiers.
    try:
        with open(os.path.join(run, "manifest.json"), encoding="utf-8") as f:
            orig_manifest = json.load(f)
    except (OSError, json.JSONDecodeError):
        orig_manifest = {}
    try:
        with open(os.path.join(run, "static_snapshot.json"), encoding="utf-8") as f:
            orig_static = json.load(f)
    except (OSError, json.JSONDecodeError):
        orig_static = {}

    out = sanitize_run(run, args.out)
    hits = verify(out, original_manifest=orig_manifest,
                  original_static=orig_static)
    print("============================================================")
    print(" Sanitized copy written")
    print("============================================================")
    print(f" Source: {run}")
    print(f" Output: {out}")
    if hits:
        print(f" WARNING: verifier found {len(hits)} potential leaks:")
        for hit in hits[:10]:
            print(f"   - {hit.file} @ {hit.location}: {hit.snippet[:80]}")
        if len(hits) > 10:
            print(f"   ... and {len(hits) - 10} more.")
    else:
        print(" Verify OK: no known identifier present in the sanitized copy.")
    print("============================================================")
    return 0


def _cmd_split(args: argparse.Namespace) -> int:
    from sysspecter.splitter.orchestrator import split_run

    run = os.path.abspath(args.run)
    if not os.path.isdir(run):
        print(f"error: not a directory: {run}", file=sys.stderr)
        return 2
    if args.min_phase_seconds is not None and args.min_phase_seconds <= 0:
        print("error: --min-phase-seconds must be > 0", file=sys.stderr)
        return 2
    result = split_run(
        run,
        min_phase_seconds=args.min_phase_seconds,
        window_seconds=args.window_seconds,
        step_threshold=args.step_threshold,
        slope_threshold=args.slope_threshold,
        proximity_seconds=args.proximity_seconds,
        build_subreports=not args.no_subreports,
    )
    print()
    print("============================================================")
    print(f" Phasen-Split fertig: {len(result.get('phases', []))} Phasen")
    print(f" Uebersicht: {os.path.join(run, 'phases_report.html')}")
    print("============================================================")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    # When invoked with no arguments (e.g. a double-clicked USB executable)
    # fall back to launching the GUI rather than printing argparse usage.
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = ["gui"]

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
    if args.command == "split":
        return _cmd_split(args)
    if args.command == "gui":
        return _cmd_gui(args)
    if args.command == "sanitize":
        return _cmd_sanitize(args)
    if args.command == "doctor":
        return _cmd_doctor(args)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
