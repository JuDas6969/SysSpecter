# SysSpecter — Windows Performance Diagnostic & Comparative Benchmark Framework

> **See everything. Find the cause.**

<p align="center"><img src="assets/logo_long.png" alt="SysSpecter" height="90" /></p>

A Python tool for **evidence-based** Windows performance diagnostics and
cross-machine comparison. Intended for admins and technicians working on
"my PC is slow" complaints, Autopilot vs standard-build comparisons, and
stress-test observations.

It does not just dump counters — it detects anomalies, slowdown windows,
resource leaks, ranks offenders across multiple axes, classifies bottlenecks,
and produces a self-contained HTML report plus machine-readable artifacts.

## Install

Requires Windows 10 / 11 and Python 3.12 or 3.14 (either works on current wheels).

```
py -m venv C:\Claude\Monitoring\.venv
C:\Claude\Monitoring\.venv\Scripts\python.exe -m pip install -r C:\Claude\Monitoring\requirements.txt
C:\Claude\Monitoring\.venv\Scripts\python.exe C:\Claude\Monitoring\.venv\Scripts\pywin32_postinstall.py -install
```

Run SysSpecter via `sysspecter.bat`, which points at the venv's Python:

```
sysspecter.bat monitor --mode support
```

For a GUI wrapper around the same commands (tabs for Monitor / Runs / Compare):

```
sysspecter-gui.bat
```

### Portable single-file EXE (for USB sticks)

Once `install.bat` has set up the venv, package everything into one
self-contained executable:

```
build_exe.bat
```

This drops `dist\SysSpecter.exe` (~40–60 MB). Copy the EXE onto a USB stick
and run it on any Windows 10/11 box — no Python install needed. Double-click
launches the GUI. CLI usage still works too:

```
SysSpecter.exe monitor --mode support
SysSpecter.exe compare --input X:\SysSpecter\Runs
```

When running as a frozen EXE, the default output root becomes
`<exe_dir>\SysSpecter\Runs`, so all reports stay on the stick.

## Permissions

Run in an **elevated (admin) terminal** for full coverage — a few counters
(handle counts on protected processes, certain WMI classes) require admin.
The tool will still run without admin: it logs a warning, degrades to the
available subset, and the report marks `privilege_level: user`.

## Modes

| Mode | Default duration | Target required | Use case |
|------|------------------|-----------------|----------|
| `support` | manual stop | no | "my PC is slow" diagnostics |
| `baseline` | 1800 s | no | measure ground noise (idle, no workload) |
| `workload` | 1800 s | recommended | measure a stress test or specific app |
| *(compare)* | n/a | n/a | cross-run analysis |

Examples:

```
sysspecter.bat monitor --mode support
sysspecter.bat monitor --mode baseline --duration 600 --tag standard-build
sysspecter.bat monitor --mode workload --duration 900 --target-name StressApp.exe --tag autopilot
sysspecter.bat compare --runs C:\Temp\SysSpecter\Runs\HOST1_... C:\Temp\SysSpecter\Runs\HOST2_...
sysspecter.bat compare --input C:\Temp\SysSpecter\Runs
sysspecter.bat report --run C:\Temp\SysSpecter\Runs\HOST1_...    # rebuild reports
sysspecter.bat inspect --run C:\Temp\SysSpecter\Runs\HOST1_...   # quick console summary
```

Manual stop: press `Ctrl+C`, or create an empty file named `STOP` in the
run folder. Finalization (end snapshot, analysis, report) always runs.

## Options

```
--mode support|baseline|workload
--duration <seconds>
--interval <seconds>           (default 1.0)
--target-name <exe name>
--target-pid <pid>
--target-path <absolute exe path>
--tag <label>                  (repeatable, goes into manifest)
--latency-target <host>        (repeatable; defaults: 127.0.0.1, 8.8.8.8, 1.1.1.1)
--output-root <dir>            (default C:\Temp\SysSpecter)
--manual-stop                  (force manual stop even in baseline/workload)
```

## Output

```
C:\Temp\SysSpecter\Runs\<HOSTNAME>_<RUNID>\
  manifest.json
  static_snapshot.json
  process_start_snapshot.json
  service_start_snapshot.json
  timeline_system.csv          # 1 row / second: CPU, RAM, disk, net totals
  timeline_processes.csv       # 1 row per (second, candidate process)
  timeline_network.csv         # 1 row per (second, adapter)
  timeline_latency.csv         # 1 row per (probe, target); probes every ~15s
  process_events.json          # start/stop events captured during the run
  service_events.json          # service state changes
  findings.json                # anomalies, slowdowns, leaks, offenders, bottlenecks
  scores.json                  # stability/efficiency/workload/security/network/hygiene/overall
  final_report.html            # primary human report, fully offline
  final_report.md              # markdown summary
  logs\
    collector.log
    analyzer.log
    reporter.log

C:\Temp\SysSpecter\Comparisons\<CMP_ID>\
  comparison_manifest.json
  comparison_matrix.csv
  comparison_findings.json
  comparison_scores.json
  comparison_report.html
  comparison_report.md
```

## Heuristics (summary)

### Anomalies
- CPU sustained >85% for ≥10s → `cpu_sustained_high`
- Single-core pinned >95% while others avg <50% → `cpu_single_core_saturation`
- Memory used >85% sustained → `memory_pressure` (>93% → severity `high`)
- Swap used >20% → `swap_usage` (>40% → `medium`)
- Disk active >85% for ≥8s → `disk_active_high`
- Latency peak ≥200ms → `network_latency_spike` (≥500ms → `high`)

### Slowdown windows
Contiguous second-ranges with at least one pressure reason (CPU / memory /
swap / disk / network latency). Windows shorter than 3s are dropped; gaps of
≤5s are merged. Each window reports peak metrics, reason tags, top offender
processes, and a confidence tier:
- <10s → `suspicious`
- ≥10s → `likely`
- ≥20s with ≥2 reasons → `strong evidence`

### Leak heuristics
For each process, a linear-regression slope is computed over smoothed RSS /
handle count / thread count series. A leak candidate requires:
- ≥120 s of observation window
- slope ≥ threshold (memory 50 KB/s, handles 50/min, threads 10/min)
- ≥20 MB (or ≥100 handles, ≥20 threads) cumulative growth

Confidence tiers (`suspicious` / `likely` / `strong evidence`) depend on
slope magnitude and growth ratio relative to the starting value.

### Scoring
Each score is 0–100, higher = better:
- **Stability** — penalises CPU/mem variance and medium/high anomalies
- **Efficiency** — rewards idle headroom, penalises background noise
- **Workload suitability** — fraction of time *not* in a slowdown window (workload mode only)
- **Security overhead** — penalises AV/security CPU + RAM cost
- **Network impact** — penalises avg/p95 latency and loss
- **Resource hygiene** — penalises leak candidates weighted by confidence tier

Overall is weighted: stability 0.25, efficiency 0.15, workload 0.15,
security 0.10, network 0.15, hygiene 0.20. Weights are printed in the
report. Confidence of the diagnosis depends on sample count
(<60 → low, ≥600 → high).

## Compare workflow

1. Run the same scenario on each machine, using consistent `--tag`s:
   ```
   sysspecter.bat monitor --mode workload --duration 600 --target-name StressApp.exe --tag autopilot
   sysspecter.bat monitor --mode workload --duration 600 --target-name StressApp.exe --tag standard-build
   ```
2. Compare:
   ```
   sysspecter.bat compare --runs <autopilot_run> <standard_run>
   ```
3. Open the generated `comparison_report.html`. Expect: metric matrix,
   overlaid CPU/memory charts, per-axis rankings (best overall, most stable,
   lowest avg CPU, lowest p95 latency, fewest anomalies), pairwise deltas,
   and common/unique problem kinds.

## Low-overhead design

- 1-second "cheap" collectors use `psutil` on a **rolling top-N candidate
  set** (CPU / RAM / handles / I/O union), not every process every second.
- Candidate set refreshes every 10s via a full enumeration.
- Expensive tier (service state, process tree diff, latency probes) runs every
  15–30s on a separate cadence.
- CSVs stream to disk and flush every 10s — no in-memory accumulation.

## How to read the report

The HTML report opens with a brand-coloured header and key metadata.
Below that are several banners and sections you should read top-down.

| Banner | Meaning | Action |
|---|---|---|
| **Running as standard user** (red) | You were not an Administrator. ETW disk I/O, handle counts on protected processes, and some WMI classes are missing from the data. | Re-run from an elevated prompt / "Run as administrator" on the EXE if those signals matter. |
| **Collector degraded** (red) | One or more samplers failed mid-run (GPU, ETW, event-log, connections). The named collector's data is incomplete. | Open `logs/collector.log` for the exception; often means a driver/tool is missing. |
| **Low sample count** (yellow) | Run ended with fewer than 60 system samples. Scoring and slowdown detection are statistically weak. | Re-run with a longer duration (≥ 5 min is a reasonable minimum). |

**Executive summary** states the verdict in one sentence and lists six scores
(0–100, higher = better):

- `Overall` — weighted blend of the other five (weights printed at the bottom).
- `Stability` — penalises CPU/mem variance and medium/high anomalies.
- `Efficiency` — rewards idle headroom, penalises background noise.
- `Workload` — fraction of time **not** in a slowdown window (only meaningful in `workload` mode).
- `Security` — penalises AV/security-product CPU + RAM cost.
- `Network` — penalises avg/p95 latency and loss.
- `Hygiene` — penalises leak candidates weighted by confidence tier.

The primary + secondary bottlenecks summarise the pressure axes that
accumulated the most evidence. `none clearly dominant` means no single
resource is driving the slowdown.

**Slowdown windows** each have a confidence tier:

- `suspicious` — short (< 10 s) or low evidence; often transient.
- `likely` — ≥ 10 s and at least one sustained pressure reason.
- `strong evidence` — ≥ 20 s and ≥ 2 reasons; worth a root-cause discussion.

**Leak candidates** for memory, handles, and threads are ranked by the
linear-regression slope of the per-process smoothed series. Confidence tiers
(`suspicious` / `likely` / `strong evidence`) depend on slope magnitude and
growth ratio relative to the starting value. A single `strong evidence`
memory leak is usually worth reproducing and capturing an ETW trace for.

**Offenders** is the list of PIDs and applications that consumed the most CPU,
memory, handles, I/O, or thread count during the run. Use this to decide where
to focus next — a clear top-1 CPU offender that also shows leak-candidate
behaviour is usually the explanation.

**Recommendations** at the bottom are observational ("your top 3 AV components
averaged 15 % CPU"), not automated fixes.

For the **comparison** report, the banner up top shows the detected mode
(`Before/after`, `Pair diagnosis`, or `Fleet`). The hardware-diff table
highlights fields that differ between the runs in yellow; read those first
because they usually explain the score gaps.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| **`sysspecter stop` says "no active session found"** on a session that is clearly running | Tool version < 1.0.0 (collector heartbeat wasn't throttled to the log) | Upgrade. From 1.0.0 on the collector touches `collector.log` every 10 s. |
| **SmartScreen blocks `SysSpecter.exe` on first launch** | The EXE is unsigned. | Click "More info" → "Run anyway". Re-appears on each machine until we ship a signed build (tracked in `BUILDING.md`). |
| **Report shows "ETW disk capture not enabled" even though `--etw` was passed** | Not running elevated, or a stale `NT Kernel Logger` session is still live | Run as Administrator. If the problem persists, run `logman stop "NT Kernel Logger" -ets` in a terminal once. |
| **GUI looks like Windows 98** | `ttk` fell back to its default theme on a very old Python/Tcl | Not a functional problem. Upgrade to Python 3.12+ if cosmetically important. |
| **GUI window just flashes / disappears** | Hidden exception in a tab's constructor | Launch via `sysspecter.bat gui` (not `-gui.bat`) so you see the traceback in the console. |
| **"Output folder is not writable" on USB** | Stick is read-only, full, or the path has characters Windows refuses | Re-insert the stick, test another path with `--output-root D:\SysSpecter`, or format as NTFS/exFAT. |
| **Run folder exists but no `final_report.html`** | Monitor was killed hard before finalize could run | `sysspecter report --run <folder>` rebuilds it; the manifest is repaired on the fly. |
| **Huge run with too many phases after `split`** | Defaults only kick in when threshold flags are omitted | Omit `--window-seconds` / `--min-phase-seconds` so the auto-scaled defaults engage, or raise them manually. |
| **"psutil ImportError" when running sysspecter.bat** | The venv's Python is broken or the wrong interpreter is on PATH | Re-run `install.bat`. |

If the tool crashes in a way that is not covered here, please capture
`logs/collector.log`, `logs/analyzer.log`, `logs/reporter.log` from the
affected run folder (plus the GUI console if running `sysspecter.bat gui`)
before re-running.

## Known limitations

- **Unsigned EXE.** Windows SmartScreen will warn on first run; see
  `BUILDING.md` for the customer-facing bypass and the code-signing path.
- **Disk active %** is computed from psutil's `busy_time`; accuracy depends
  on the Windows counter behaviour for the volume. Treat values near 100 %
  as "likely saturated" rather than an absolute truth.
- **`net_connections(kind="tcp")`** requires elevated rights on some systems;
  the CSV stores `-1` when the call is denied.
- Commit bytes / pagefile-committed are not captured in Phase 1 (`psutil`
  does not expose the Windows commit counters directly). The manifest's
  `commit_used_bytes` fields are left null and will be added in Phase 2.
- The tool does not modify system state. Recommendations in the report are
  *observations*, not automated fixes.
```

## License / Copyright

© 2026 David Juriga. All rights reserved.

