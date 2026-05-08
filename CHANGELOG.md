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

- **A3** (periodic-pattern detection): new analyzer module
  `sysspecter/analyzer/periodicity.py` runs Pearson autocorrelation
  on system-level (CPU, network, disk) and per-PID (CPU) metrics
  to surface AV / EDR / scheduler cycles automatically. Catches
  the field-review's three production patterns: Defender-scan
  ~593 s, MsSense ~989 s, NetSetupSvc ~291 s. All-stdlib — no
  scipy / numpy. 5-second binning, lag range 30 s..30 min,
  correlation threshold 0.30, top 3 per system metric / top 1
  per PID. Findings carry `metric`, `period_seconds`, `strength`,
  and a human-readable description; per-PID entries also carry
  `pid` and `process_name`. HTML report shows a dedicated
  "Periodic patterns" section with a system-metrics table and a
  per-process-CPU table. 12 contract tests in
  `tests/test_periodicity.py` covering primitive autocorrelation
  math, clean-sine detection, square-pulse (EDR-shaped) detection,
  noise rejection (no false positives on random uniform), and the
  per-PID path.

- **A6** (cap-window-aware scoring): scores normalised over the
  whole run aren't comparable across runs of different lengths —
  a 30-min run and an 8-h run produce different statistical
  signals because everything depends on duration. New
  `compute_tail_window_scores()` re-runs the score model over
  canonical TAIL windows (`last_1h`, `last_8h`) so a fleet
  aggregator or longitudinal trend can compare apples-to-apples.
  Each tail score carries the same shape as the full-run score
  plus `window_label` / `window_start_seconds` /
  `window_end_seconds` / `window_duration_seconds` /
  `window_samples`. Short runs emit no tail (1-h tail requires
  ≥ 1 h duration). HTML report shows a "Tail-window comparison"
  table side-by-side with the full-run scores. 6 contract tests
  in `tests/test_tail_window_scores.py` covering emit-decision
  rules, schema preservation, and the semantic check that a
  calm-then-stormy run grades the tail LOWER on stability than
  the full run.

- **A4** (process-tree visual): new analyzer module
  `sysspecter/analyzer/process_tree.py` aggregates the H3 schema
  (`ppid` + `parent_name` per sample) and the H4 always-on
  `process_events.json` into a parent → child relationship view.
  Findings carry `process_tree.by_parent` (sorted by total peak RSS
  desc, capped at 50 pairs) plus per-name `spawn_counts` and
  `exit_counts` from the event stream. HTML report renders a
  dedicated "Process tree" section: one row per
  (parent_name, child_name) pair with instance count, total peak
  RSS, sample count, and example PIDs. Worker-pool architectures
  (e.g. supervisor → 15 hyperd → 4 motodb) are now visible in 5
  seconds instead of after parsing raw event JSON. 8 contract tests
  in `tests/test_process_tree.py`.

- **A2** (deadlock-after-leak detection): new analyzer module
  `sysspecter/analyzer/deadlocks.py` and a new finding type
  `deadlock_suspected` in `findings.json`. Detects the canonical
  failure signature the field review surfaced on the MotoDB run:
  a process accumulates RSS at ≥ 50 KB/s for ≥ 1 hour, THEN holds
  RSS flat (slope < 10 KB/s) AND drops to < 5 % CPU for ≥ 10 minutes.
  Stack-aware (reuses C1 multipliers, so a JVM ramping its heap
  doesn't trip the growth phase). Findings carry both phases'
  bounds + aggregate stats:
    growth_phase: start_s / end_s / duration_s / mean_slope / mean_r2
    plateau_phase: start_s / end_s / duration_s / mean_slope / mean_cpu_pct
  HTML report ships a dedicated "Deadlock-suspected processes"
  section; pipeline summary verdict mentions the count. 8 contract
  tests in `tests/test_deadlock_detection.py` covering the happy
  path AND the false-positive guards (active-leak-without-plateau,
  pure-plateau, busy-flat-RSS, growth too short, plateau too short,
  too-few-samples edge case).

- **A1** (sliding-window leak detection): the legacy
  `detect_memory_leaks` regressed over the entire run, which on long
  captures meant a clear leak phase followed by a plateau got its
  slope diluted below threshold and the leak was MISSED. Motivating
  case: the production MotoDB analysis on a 49 309 s run where the
  leak ran for 8 hours, plateaued for 2, and the full-run slope was
  masked by the post-plateau samples. New `_sliding_window_stats`
  function computes slope / R² / monotonic-ratio per 1-h window
  with 10-min stride. `detect_memory_leaks` picks the peak-slope
  window for grading when its slope exceeds the full-run slope —
  catching leaks the old path missed without raising false-positives
  on short clean linear leaks (which still grade through the
  full-run path). New `_find_plateau_start` annotates the moment
  the leak phase ended (slope drops below 10 KB/s after a sustained
  growth phase). Findings now carry `slope_source` (`peak_window`
  vs `full_run`), `windows_evaluated`, `peak_window` (start, end,
  slope, R², samples), and `growth_phase_end_s`. 8 contract tests
  in `tests/test_sliding_window_leaks.py`.

- **C1** (stack-aware leak detection): the leak heuristic in
  `analyzer/leaks.py` was tuned for native / Matlab / .NET-desktop
  workloads. On customer hosts running JVM, Chromium-family browsers
  (or Electron apps), Node.js, or Go, the same heuristic produced
  endless false positives because those runtimes are SUPPOSED to grow:
  - JVM grows toward `-Xmx` then plateaus by design
  - .NET server-GC produces saw-tooth RSS until Gen 2 collections
  - Chromium / Electron renderers cycle GC per-tab, accumulate caches
  - Node.js V8 ramps toward its 1.4 GB ceiling
  - CPython with reference cycles reaches a non-flat steady state.
  Process catalog (C2) gained a `stack` field — the JSON catalog tags
  Chrome/Edge/VS Code/Slack as `chromium`, java/IntelliJ as `jvm`,
  python as `cpython`, etc. New module
  `analyzer/leak_thresholds.py` ships per-stack profiles with tuned
  multipliers (slope, min growth, mono floor, R² floor, plateau-is-
  normal flag). `detect_memory_leaks` / `detect_handle_leaks` /
  `detect_thread_leaks` look up the canonical stack per PID and apply
  the profile before grading confidence. Findings now carry the
  resolved `stack` tag in their output. 9 contract tests in
  `tests/test_leak_thresholds.py` verify the false-positive gate
  (JVM-at-Xmx, Chromium-saw-tooth) AND the true-positive path
  (genuine native + steeper-than-JVM-bar leaks still fire).

- **C4** (capture profiles): `sysspecter monitor --profile NAME` plus
  `--list-profiles`. Bundles "what kind of question are you answering"
  into named presets that fill in mode + duration + Phase 3 collectors
  + suggested meta tags. Shipped catalog covers the use cases the
  field review called out: `support`, `baseline`, `workload`,
  `leak-hunt`, `av-overhead`, `thermal`, `incident-snapshot`,
  `vpn-troubleshoot`, `security-audit`. Every individual flag still
  overrides the profile (`--profile thermal --duration 60` runs the
  thermal preset for 60 s instead of the default 300 s). The active
  profile name is stamped into `manifest.meta.capture_profile`.
  GUI Monitor-tab presets are now generated from the same catalog —
  one source of truth, CLI and GUI stay in sync. 24 contract tests
  in `tests/test_profiles.py` covering catalog completeness,
  CLI-override semantics, and per-profile resolution smoke checks.

- **M2** (structured fleet metadata): manifest now carries a `meta`
  block alongside the existing free-form `tags` array. CLI:
  `monitor --meta department=engineering --meta ticket=PERF-1234`,
  plus convenience flags `--department`, `--ticket`, `--scenario`,
  `--change-under-test`, `--machine-class` for the well-known keys.
  Pydantic schema validates the new field; v1 / v2 manifests without
  a `meta` block still load (back-compat). The Runs-tab filter now
  matches both keys and values, so a fleet operator can pull "all
  runs for ticket PERF-1234" with one search. 6 contract tests
  pinned in `tests/test_meta_tags.py`.

- **M1** (privacy redaction at capture-time): `monitor --redact` flag.
  When set, after the run finishes the sanitize pass runs automatically,
  produces a `<run_id>_sanitized` sibling folder, and verifies the
  redaction with the same `sanitizer_verify` self-check the post-hoc
  command uses. The original run is kept on disk for local analysis;
  the sanitized copy is what gets shipped to a vendor.
- **M1 / sanitizer hardening**: identifiers (hostname / FQDN / username
  / BIOS / disk / baseboard serial) are now replaced by **stable
  hashes** (`HOST-7f3a`, `USER-bb9c`, `BIOS-3e2d`, …) instead of the
  literal `[REDACTED]`. Same input → same hash, so cross-process
  attribution survives redaction (you can still see that two PIDs
  belong to the same user, just not which one). Hashes are
  blake2b-2-bytes → 4 hex chars per token. Hostname and FQDN map to
  the same token so `BOX1` / `BOX1.corp.local` collapse correctly.
- **M1 / cmdline secret stripping**: the sanitizer now runs a
  pre-pass against every string field that strips credential-shaped
  substrings before the identifier substitution: `--password=...`,
  `--token ...`, `Authorization: Bearer ...`, raw JWTs, AWS access
  keys (`AKIA...`), GitHub tokens (`ghp_`, `github_pat_`). Cmdline
  capture isn't persisted yet, but the verdict / tags / arbitrary
  text fields are also covered.

- **C2** (cross-vendor EDR support): replaced the hardcoded
  `{"msmpeng.exe", "mssense.exe", "mpcmdrun.exe", "smartscreen.exe",
  "nissrv.exe", "windowsdefender.exe"}` Microsoft-only set in the
  analyzer with a JSON-driven process catalog
  (`assets/process_catalog.json` + 8-test contract pinned in
  `tests/test_process_catalog.py`). Ships covering all 7 major EDR
  vendors — Microsoft Defender for Endpoint, CrowdStrike Falcon,
  SentinelOne, Sophos Intercept X, Palo Alto Cortex XDR, VMware
  Carbon Black, Trend Micro — plus AV (ESET, Kaspersky, Avira,
  Malwarebytes, Bitdefender), VPN (Zscaler, Netskope, GlobalProtect,
  FortiClient, Cisco AnyConnect, OpenVPN, WireGuard), MDM (Intune,
  Workspace ONE), DLP (Trend Micro, Digital Guardian), and the
  full set of browsers / IDEs / runtimes / containers / chat tools.
  Customers can extend without forking via
  `%APPDATA%\\SysSpecter\\process_catalog.json` (user override beats
  shipped entry). `KNOWN_APPS` dict in `analyzer/grouping.py` is
  removed; the catalog supersedes it.

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
