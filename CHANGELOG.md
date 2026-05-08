# Changelog

All notable changes to SysSpecter are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed (data correctness — from production-use review)

- **B4**: `cpu_freq_current_mhz` no longer reads WMI's nominal P-state
  (which capped at 1532 / 2500 MHz on an i7-13800H even at full turbo).
  The sampler now calls `CallNtPowerInformation(ProcessorInformation)`
  via ctypes, queries every logical CPU, and reports
  `max(CurrentMhz)` — so any single-core boost is captured. Falls
  back to `psutil.cpu_freq()` only on locked-down hosts where
  `powrprof.dll` is unavailable.

### Added

- **D3 / H4**: `manifest.phase3_captured` block alongside the existing
  `phase3` (request) block. Records what actually produced data:
  `process_events`, `service_events`, `event_logs`, `etw_disk`,
  `gpu_engine`, `gpu_process`, `gpu_adapter`. Distinguishes "feature
  was off" from "feature was on but produced an empty file" — the
  field-review noted these were indistinguishable before.
- **H5**: `timeline_per_core.csv` long-format file (columns
  `timestamp, rel_seconds, core_idx, cpu_pct`). Replaces the
  semicolon-blob workflow when analyzing core pinning, hybrid-CPU
  scheduling, or HT behaviour. The legacy `cpu_per_core_pct` column
  in `timeline_system.csv` stays for backwards compatibility.

### Fixed (data correctness — from production-use review)

- **B1**: `scores.json` and `findings.json` now both carry an
  `analysis_window` block — single source of truth for "what was
  actually analyzed". Resolves the three-way duration ambiguity where
  the same run reported 39 samples / 800 s in scores, 344 / 7998 s in
  the CSV, and 49309 s in the manifest. The window records:
  `window_start_seconds`, `window_end_seconds`,
  `window_duration_seconds`, `samples_analyzed`,
  `full_run_duration_seconds` (untrimmed original),
  `requested_window_*` (what the caller asked for), and `trimmed: bool`.
  HTML report now shows "Full run: X s / Analyzed window: Y..Z (W
  samples)" when --trim-seconds was used. Tested in
  `tests/test_analysis_window.py` (4 contract tests).
- **B2**: `commit_used_bytes` and `commit_total_bytes` are now populated
  via `GlobalMemoryStatusEx` (Win32). Previously emitted as None for
  every sample despite being declared in the schema, so downstream
  consumers thought commit charge data simply didn't exist.
- **B3**: PDH counter rollover that produced values around `-1.5e8`
  in `ctx_switches_per_sec` and `interrupts_per_sec` after multi-day
  uptime is now caught — negative deltas surface as `None` rather
  than poisoning the timeline with synthetic giant spikes.
- **B5**: `disk_active_pct_est` carries an explicit docstring noting
  it's an estimate from psutil's `busy_time` delta and biased low on
  NVMe. Rename deferred (would touch the golden test fixture).

### Added (schema additions — from production-use review)

- **H3** — `ppid` and `parent_name` columns in `timeline_processes.csv`.
  Removes the manifest-join-per-PID step when reconstructing
  worker-supervisor trees during analysis.
- **H9** — `num_page_faults` per process. Leading indicator for memory
  pressure / page-file thrashing.
- **S3** — `sample_late_ms` column in `timeline_system.csv`. The
  sampler now records how late each tick fired vs. its scheduled
  time, so a consumer can distinguish "system was idle" from "the
  sampler was preempted under load."

### Added
- **SECURITY.md** with CVE reporting process + disclosure policy.
- **CONTRIBUTING.md** with quick-start, coding guidelines, and release
  instructions for new contributors.
- **Pre-commit config** (`.pre-commit-config.yaml`) — Ruff, Bandit, and
  a handful of file-hygiene hooks run on every commit.
- **End-to-end smoke test** (`tests/test_e2e_monitor.py`) — spawns the
  real CLI, runs a 5-second monitor, asserts artefacts + manifest are
  valid. Gated behind `pytest -m e2e` so it does not slow the unit pass.
- **Collector safety-net tests** — `tests/test_winutil.py` (powershell
  wrapper failure modes), `tests/test_collector_system_sampler.py`
  (sampler schema + rate math + psutil fall-backs), `tests/test_manifest.py`
  (build / end-update / degradation records).
- **Typography hierarchy** in the ttk theme (`H1 / H2 / H3 / Muted`
  label styles) so section headers render at the right weight.
- **Keyboard focus indicator** on buttons — 2-px brand-cyan outline when
  a widget has keyboard focus, finally usable with Tab-navigation.
- **Progressive disclosure** in the Monitor tab — target / PID / path /
  tags / latency fields are hidden behind a "Show advanced options"
  toggle. First-time users see 3 fields (Mode / Duration / Output)
  instead of 12.

### Changed
- **Silent `except Exception: pass`-Blöcke** audited: 48 total, 16
  classified as real diagnostic failures and given a `_log.warning` /
  `_log.debug` call with `exc_info=True`. The remaining 32 are
  legitimate Tk-shutdown / optional-feature probes and kept silent.
- **Dev-dependency pinning** — `requirements-dev.txt` now pins every
  tool exactly (`pytest==9.0.3`, `ruff==0.15.11`, …) so CI never breaks
  on a surprise upstream release.


## [1.0.0] — 2026-04-23

First production-ready release. Portable single-file EXE, Tkinter GUI,
comparison tool, session splitter, and per-run HTML report.

### Added
- **GUI** (Tkinter, stdlib only) with tabs for Monitor, Runs, Compare, About.
  Progress bar + ETA, admin-warning label, graceful-close dialog, tooltips.
- **Portable EXE** built via PyInstaller (`build_exe.bat` → `dist/SysSpecter.exe`).
  Default output root is `<exe_dir>/SysSpecter` when frozen, so reports stay
  on a USB stick alongside the binary.
- **Session splitter** (`sysspecter split`) — post-hoc phase detection with
  per-metric step/slope/inflection signals, strict process-end filter, and
  per-phase sub-reports plus a timeline overview HTML.
- **Comparison tool** rework — auto-detects mode from hostnames
  (before_after / pair_diagnosis / fleet), diffs hardware, installed
  programs, autoruns, and configuration; emits evidence-based
  recommendations with disk-tier, RAM, CPU, power-plan, AV, and
  software-bloat rules.
- **`sysspecter report --trim-seconds N`** for retroactive truncation.
- **Manifest repair** for runs killed hard (infers `ended_at` from CSV).
- **Graceful-stop heartbeat** — collector writes a log entry every 10 s so
  `sysspecter stop` can still find the run during quiet stretches.
- **`sysspecter_version`** + **`collector_degraded`** fields in `manifest.json`;
  report header surfaces the version and shows red banners when the tool
  runs without admin, when collectors degraded, or when there were too few
  samples for a confident verdict.
- **LICENSE** and **THIRD_PARTY_NOTICES.md** shipped next to the EXE.
- Brand logo (header, window icon, multi-resolution ICO) and cyan→purple
  report accents.

### Fixed
- **ETW disk-I/O capture** — kernel-trace sessions now use the OS-reserved
  name `NT Kernel Logger` instead of a custom name that Windows rejected
  ("session name provided is invalid"); stale sessions from a prior crashed
  run are stopped before starting.
- **GUI on Python 3.14** — About tab no longer crashes on ttk's missing
  `-background` option.
- **Windowed subprocess shutdown** — closing the GUI with a monitor still
  running now prompts and cleans up instead of orphaning the child.
- **Output-root validation** — reports on an unwritable USB stick or invalid
  path now fail with a clear message before sampling starts.
- **Sparse-data crashes** — runs with fewer than 30 system samples return
  a minimal `findings.json` + `scores.json` with `insufficient_data=true`
  instead of exploding in the analyzer.

### Changed
- Splitter defaults moved from fixed thresholds to duration-scaled auto
  values; a 49 k-second reference run that previously produced 31 phases
  now yields the expected 2. Override with `--window-seconds`,
  `--min-phase-seconds`, `--step-threshold`, `--slope-threshold`,
  `--proximity-seconds`.
- Dependency versions pinned exactly in `requirements.txt` +
  `requirements-dev.txt`; `build_exe.bat` no longer silently upgrades
  PyInstaller/Pillow on each run.

### Known limitations
- The EXE is unsigned; Windows SmartScreen may warn on first launch.
  See `BUILDING.md` for the customer-facing workaround and the
  code-signing roadmap.
- ETW disk capture requires Administrator; a non-admin run shows a red
  banner in the report listing the disabled features instead.
- Scoring heuristics are documented but not machine-learned; they are
  deliberately conservative and explainable rather than optimised.

[Unreleased]: /compare/v1.0.0...HEAD
[1.0.0]: /releases/tag/v1.0.0
