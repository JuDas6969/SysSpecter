# SysSpecter — Windows Performance Diagnostic & Comparative Benchmark Framework

> **See everything. Find the cause.**

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

## Known limitations (Phase 1 scope)

- No ETW integration, no deep GPU metrics, no event-log correlation, no DNS
  attribution beyond a simple `ping` probe. These are called out in the spec
  as Phase 2/3 and are deliberately out of scope.
- Disk active % is computed from psutil's `busy_time`; accuracy depends on
  the Windows counter behaviour for the volume. Treat values near 100% as
  "likely saturated" rather than absolute truth.
- `net_connections(kind="tcp")` requires elevated rights on some systems;
  the CSV stores `-1` when the call is denied.
- Commit bytes / pagefile-committed are not captured in Phase 1 (`psutil`
  does not expose the Windows commit counters directly). The manifest's
  `commit_used_bytes` fields are left null and will be added in Phase 2.
- The tool does not modify system state. Recommendations in the report are
  *observations*, not automated fixes.
```
