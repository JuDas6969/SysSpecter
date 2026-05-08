# SysSpecter Roadmap — 3-Week Push to 8/10 Across All Dimensions

> Goal: bring every review dimension from its current score to **≥ 8 / 10**
> inside 3 focused working weeks, without stalling feature work.

**Current vs. target**

| Dimension | Today | Target | Δ |
|---|---:|---:|---:|
| Codequalität | 6 | 8 | +2 |
| Architektur | 6 | 8 | +2 |
| Sicherheit | 5 | 8 | +3 |
| Performance | 7 | 8 | +1 |
| Testreife | 2 | 8 | **+6** |
| DevOps-Reife | 4 | 8 | +4 |
| UI-Qualität | 5 | 8 | +3 |
| UX-Qualität | 5 | 8 | +3 |
| Produktvollständigkeit | 5 | 8 | +3 |
| Produktionsreife | 5 | 8 | +3 |

The biggest gaps are **Testreife (+6)** and **DevOps-Reife (+4)**. Everything
else is 1–3 points away and already sits on foundations laid in v1.0.0.

---

## 0. Ground rules

- **Definition of "8"** per dimension is spelled out below; "it feels good"
  does not count.
- Every task lists an **acceptance test** — a concrete, checkable
  outcome, not an activity.
- Tasks are sized **S (≤ 4 h)**, **M (≤ 1 day)**, **L (≤ 3 days)**.
- Tasks are tagged with dimensions they move, so we can track coverage.
- Nothing ships unless CI passes with `pytest + ruff + pip-audit`.

---

## 1. Phased plan

### Week 1 — Foundations + signed EXE

The goal of week 1 is to remove the two biggest risk factors (untested
business logic, unsigned binary) and to clear the refactoring rubble so
the next weeks can iterate quickly.

| # | Task | Size | Dimensions | Acceptance |
|---|---|---|---|---|
| W1.1 | GitHub Actions CI: `pytest`, `ruff`, `pip-audit` on 3.12 / 3.13 / 3.14 | S | DevOps, Code | badge green on `main`, failing PRs blocked |
| W1.2 | Resolve `except: pass`: central `@safe_collect` decorator, wire into all samplers | S | Code, Security | 0 `except Exception: pass` left; every failure lands in `collector_degraded` |
| W1.3 | Split `html_report.py` into `templates/final_report.html.j2`, `styles/report.css`, `reporter/_banners.py`, `reporter/_score_cards.py` | M | Code, UI | `html_report.py` ≤ 300 LoC; template has no inline CSS |
| W1.4 | Test suite — analyzer: `scores`, `anomalies`, `slowdowns`, `leaks` | M | Tests | ≥ 30 new cases, all dimensions checked |
| W1.5 | Test suite — comparer: `diagnosis`, `static_diff`, `matrix`, `mode` | M | Tests | ≥ 25 new cases |
| W1.6 | Test suite — sanitizer: cmdline redaction, short hostname safety, round-trip verify | S | Tests, Security | ≥ 10 cases; `sanitizer::verify(run)` returns no leaks |
| W1.7 | EV code-signing in `build_exe.bat` (signtool + timestamp) | S after cert | Security, DevOps | `signtool verify /pa /all dist\SysSpecter.exe` exits 0 |
| W1.8 | SBOM generation: `cyclonedx-py` in build → `dist\SysSpecter.sbom.json` | S | Security, DevOps | SBOM references every installed wheel |
| W1.9 | Resolve the `sysspecter.py` / `sysspecter/` name collision: introduce `sysspecter/__main__.py`, drop `cli.py` runpy hack | M | Code, Architecture | `python -m sysspecter --help` works, `.bat` scripts unchanged |

**End of week 1 checkpoint**
- CI green on `main`
- Signed EXE on a fresh Win11 VM launches without SmartScreen prompt
- `pytest tests/` reports ≥ 90 cases
- Reviewer re-audit expects: Code 6 → 7, Security 5 → 7, Tests 2 → 6, DevOps 4 → 6.

---

### Week 2 — Architecture, schemas, observability, theme tokens

Week 2 hardens what week 1 put in place and adds the product-quality
signals the customer actually feels: crash reporter, settings
persistence, update channel, consistent visual language.

| # | Task | Size | Dimensions | Acceptance |
|---|---|---|---|---|
| W2.1 | `sysspecter/domain/run.py` — Run domain object with lazy-loaded manifest/findings/scores + artifacts catalogue | M | Architecture, Code | all Runs-tab / Compare-tab / Sanitizer callsites use `Run`, no bare path strings |
| W2.2 | Pydantic schemas for every JSON artifact (`manifest`, `findings`, `scores`, `phases`, `comparison_findings`) | M | Architecture, Security | loader validates on read; `schema_version` bumped to 2 with migration doc |
| W2.3 | Migration guide: v1 runs readable by v2 (schema_version=1 path tolerated) | S | Architecture | tests/test_schema_migration.py passes |
| W2.4 | `theme.py` — color / typography / spacing tokens for GUI AND HTML reports | S | UI, Code | 0 hex literals in `reporter/*` + `gui/*` outside `theme.py` |
| W2.5 | ttk Style setup: hover / focus / disabled / primary / danger variants | M | UI | Monitor-tab buttons animate on hover, focus ring visible |
| W2.6 | Empty-state + Toast widget library (`gui/components/empty.py`, `gui/components/toast.py`) | M | UI, UX | Runs-tab on empty shows the logo + CTA; archive/sanitize/delete trigger a toast |
| W2.7 | Settings dialog: Output-root MRU, default mode, default duration, threshold overrides, theme | M | UX, Feature-Completeness | dialog persists to `%APPDATA%\SysSpecter\config.toml`; restart keeps changes |
| W2.8 | Status bar (bottom of GUI): version, output root, admin-yes/no, current operation | S | UI, UX | visible on all tabs |
| W2.9 | Crash reporter: unhandled GUI exceptions dump `logs\crash_<timestamp>.txt` and offer a dialog link | S | DevOps, Code | injecting a `raise` in a button handler produces the dialog + file |
| W2.10 | Update checker: HEAD request against GitHub Releases API on About-tab mount | S | Feature, DevOps | `About` shows "v1.0.0 (current)" or "v1.1.0 available" |
| W2.11 | Log rotation: `collector.log` capped at 5 MB x 3 files | S | DevOps | a 12-h run leaves 3 files, total < 15 MB |
| W2.12 | `sanitizer` hardening: explicit rules in `sanitizer/rules.py`, cmdline redaction, self-verify pass | M | Security, Quality | `sanitize_run(run); verify(run)` finds no leak of known identifiers |
| W2.13 | README extras: Troubleshooting keeps growing, add "Quick start in 60 s" block | S | UX, Docs | new user can run first monitor in < 60 s |
| W2.14 | Golden-file regression test: checked-in reference run → rendered HTML diffed against golden (timestamps masked) | M | Tests, UI | `tests/test_golden_report.py` passes; fails on any unintended template change |

**End of week 2 checkpoint**
- Schemas enforced everywhere
- GUI looks visibly modern (focus rings, hover states, toasts, empty state)
- Settings persist across launches
- Crash reporter + update checker in place
- Reviewer re-audit expects: Code 7 → 8, Architecture 6 → 8, Tests 6 → 7, DevOps 6 → 7, UI 5 → 7, UX 5 → 6, Feature 5 → 6, Security 7 → 8.

---

### Week 3 — UX polish, features, release automation

Week 3 closes the scorecard: premium UX touches, the features Customer
Support keeps asking for (scheduled runs, PDF export, live charts),
and the GitHub-Releases pipeline so shipping the next version takes
one `git tag` instead of four manual steps.

| # | Task | Size | Dimensions | Acceptance |
|---|---|---|---|---|
| W3.1 | Live-charts Monitor tab: `tkinter.Canvas` sparkline showing CPU/Mem/Disk from the heartbeat stream | M | UX, UI | visible line moves while the monitor runs |
| W3.2 | Monitor presets dropdown ("Quick idle 5 min", "Workload 30 min", "Long baseline 1 h", "VPN troubleshoot 10 min") | S | UX | one click fills all fields |
| W3.3 | Onboarding flow on first GUI launch: 3-step "what would you like to do" with CTAs to Monitor/Compare/Schedule | M | UX | triggered when `config.toml` has `first_run=true` |
| W3.4 | Runs-tab search/filter (host, mode, tag, date-range); MRU in Output-root field | M | UX, Feature | 100+ runs filterable in < 100 ms |
| W3.5 | Clickable phase bar in `phases_report.html`: SVG segments link to their sub-report | S | UX | clicking segment #3 opens the phase 3 report |
| W3.6 | Progress bar + cancel for Compare and Split operations | M | UX | both show ETA, Stop button aborts cleanly |
| W3.7 | Scheduled runs via `schtasks` integration: Settings → Schedule → create/delete | M | Feature, UX | task visible in Windows Task Scheduler, deletes cleanly |
| W3.8 | PDF / Word export of the HTML report (`weasyprint` for PDF, `pypandoc` optional) | M | Feature | "Export as PDF" button in Runs tab; file opens in default viewer |
| W3.9 | History-view tab: per-host Overall / CPU / Mem trend across all runs | M | Feature, UX | 2-axis SVG chart, hover = run-id + click = open report |
| W3.10 | Release workflow `release.yml` in GitHub Actions: tag `v*` → build signed EXE, generate SBOM, upload to GitHub Release, auto-draft changelog entry | M | DevOps, Security | `git push origin v1.1.0-rc1` produces a release asset with signed EXE + SBOM |
| W3.11 | Reproducible builds: `SOURCE_DATE_EPOCH` + PyInstaller `--deterministic` where available | S | DevOps, Security | two builds from same commit produce byte-identical EXE (bar signature) |
| W3.12 | Self-check command `sysspecter doctor`: verifies PowerShell / logman / tracerpt reachable, prints Python version, venv path, output-root writability | S | UX, DevOps | `sysspecter doctor` returns rc=0 when healthy, rc=1 with per-check report otherwise |
| W3.13 | ADRs under `docs/adr/`: (1) PowerShell for WMI, (2) Tkinter choice, (3) PyInstaller onefile, (4) schema-version bumps, (5) sanitizer rules | S | Architecture, Docs | 5 ADRs checked in |
| W3.14 | Bandit security scan in CI | S | Security, DevOps | `bandit -r sysspecter` exit 0; findings are either fixed or annotated with `# nosec` + reason |
| W3.15 | Uninstall helper: `install.bat --uninstall` removes venv, dist/, build/, optionally Runs/ | S | UX, DevOps | prompts, honours per-folder user consent |

**End of week 3 checkpoint** — **every dimension ≥ 8 / 10**.

- Release is one-tag, reproducible, signed, attested.
- GUI feels 2026 (live charts, presets, toasts, progress, focus rings).
- History + schedule + export close the remaining feature gaps.
- Full Pydantic-validated schemas + golden regression test + crash reporter
  make regressions hard to hide.
- Reviewer re-audit expects: Tests 7 → 8, DevOps 7 → 8, UI 7 → 8, UX 6 → 8,
  Feature 6 → 8, Production 5 → 8.

---

## 2. Dimension-by-dimension definition of "8"

### Codequalität → 8
Minimum proof: `ruff check` + `mypy --strict sysspecter` green, no module
over 500 LoC, 0 swallow-style exceptions, single canonical CLI entry
point (`python -m sysspecter`), design-tokens used instead of hex
literals, every non-trivial function type-annotated.

### Architektur → 8
Minimum proof: Pydantic schemas for all artifact types, `schema_version`
bump workflow documented, `Run` domain object in place, template + CSS +
Python separated in reporter, CLI dispatcher split into per-command
modules, 5 ADRs documenting the load-bearing decisions.

### Sicherheit → 8
Minimum proof: EV-signed EXE (SmartScreen silent), SBOM per release,
`pip-audit` + `bandit` in CI, sanitizer with rule-based (not raw regex)
redaction + self-verify, cmdline redaction, privacy statement in the
report footer, no shell-injection callsites (already true, locked in
by test).

### Performance → 8
Minimum proof: GUI "cheap" operations (inspect, stop, sanitize, open
report) < 50 ms to visible feedback, Compare-tab Refresh cached
(mtime-invalidated), reporter rendering bounded by downsampling
(verified up to 200 k samples), `run_ps` calls batched in the static
snapshot where possible.

### Testreife → 8
Minimum proof: ≥ 70 % line coverage across `analyzer/`, `comparer/`,
`sanitizer/`, `splitter/`, `reporter/_banners.py`, `_score_cards.py`,
`domain/run.py`. Golden-file regression test for the HTML report.
Integration test running the full pipeline on a synthetic 5-minute
fixture. CI fails under 65 %.

### DevOps-Reife → 8
Minimum proof: CI workflow (lint + test + audit + build) on every PR,
release workflow on tag (signed EXE + SBOM + changelog + GitHub
Release asset), log rotation, reproducible-build flag, crash reporter,
update checker, `sysspecter doctor` self-test command.

### UI-Qualität → 8
Minimum proof: design-token system used everywhere, Empty/Loading/
Success/Error states implemented, hover/focus/disabled styles on all
interactive widgets, status bar, consistent spacing scale, HTML-report
score-card hierarchy fixed (Overall dominant), icons where useful,
Dark-mode optional but not a blocker for 8.

### UX-Qualität → 8
Minimum proof: first-run onboarding, Monitor presets, live-chart
feedback, progress for Compare/Split, toasts on long-running ops,
context help links in warning banners, search/filter in Runs tab, MRU
output-root, clickable phase bar.

### Produktvollständigkeit → 8
Minimum proof: Scheduler, History-view, PDF/Word export, Update
checker, Settings dialog with threshold overrides and profiles,
Doctor self-check, sanitize with verify. Missing items for 9+ (live
alerting, cloud sync, fleet-management UI) explicitly parked.

### Produktionsreife → 8
Minimum proof: everything above + release workflow tested on a fresh
Win11 VM end-to-end, uninstall helper, documented ADRs, version
migration path, signing keys documented in `BUILDING.md`,
LICENSE accepted by legal review.

---

## 3. Cross-cutting work

Several tasks unlock multiple dimensions. Tackle them early:

| Task | Lifts |
|---|---|
| `@safe_collect` decorator + `mark_degraded` wiring | Code, Security, Tests (deterministic failure path) |
| Pydantic schemas | Architecture, Security, Tests, DevOps |
| `Run` domain object | Code, Architecture, UX (dedup), Performance (caching) |
| Design tokens | UI, Code, UX |
| Golden-file regression test | Tests, UI (prevents silent template drift) |
| GitHub Actions CI + Release | DevOps, Security, Tests |
| `sysspecter doctor` | UX, DevOps, Feature |

---

## 4. Risks and how to mitigate

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| EV-cert delivery delays week 1 finish | medium | Medium | Start cert procurement **day 1**. Week 1 tasks other than W1.7 do not depend on it. |
| Refactor of `sysspecter.py` breaks PyInstaller bundling | medium | high | Keep W1.9 behind a feature flag until CI passes end-to-end including a signed EXE smoke test |
| Pydantic adds ~2 MB to EXE | low | low | Acceptable; if tighter, use `msgspec` instead |
| `weasyprint` for PDF is heavy on Windows | medium | medium | If build grows > 30 MB, fall back to HTML → browser-print workflow and keep PDF export as a stretch |
| Live charts in Tkinter feel clunky | low | medium | Keep charts dead simple (sparkline only), no dependency on matplotlib |
| Customer pushes for Linux support | low | high | Explicit non-goal for 1.x; Zielarchitektur makes the stub path cheap |

---

## 5. Not in scope for reaching 8/10 (parked for 9+)

These are acknowledged but deliberately **not** required to hit 8s:

- Localization (i18n / gettext)
- Screen-reader / UIA accessibility audit
- Cross-platform (Linux / macOS) collector
- Cloud / fleet management UI
- Live alerting to Teams / Slack / Syslog
- Licensing enforcement (license keys, phone-home validation)
- Kernel ETW live-viewer (instead of post-hoc summary)
- Time-zone normalization in manifest timestamps

Re-evaluate after the customer has run v1.1 in production for a quarter.

---

## 6. Deliverables checklist (end of week 3)

- [ ] `.github/workflows/ci.yml` — lint + test + audit, green on all PRs
- [ ] `.github/workflows/release.yml` — tag → signed EXE + SBOM + Release
- [ ] `sysspecter/__main__.py` + `sysspecter/cli/<cmd>.py` split
- [ ] `sysspecter/domain/run.py`, `sysspecter/domain/schemas.py`
- [ ] `sysspecter/theme.py` + reporter templates extracted
- [ ] `sysspecter/gui/components/{toast,empty,status_bar}.py`
- [ ] `sysspecter/gui/tabs/{history,settings}.py`
- [ ] `sysspecter/sanitizer/{core,rules,verify}.py`
- [ ] `sysspecter/telemetry/crash_reporter.py`
- [ ] `sysspecter/updater/check.py`
- [ ] `docs/adr/0001..0005-*.md`
- [ ] `tests/` ≥ 150 cases, ≥ 70 % coverage on analyzer/comparer/sanitizer
- [ ] `tests/test_golden_report.py` — reference run + golden HTML
- [ ] `dist/SysSpecter.exe` signed + `dist/SysSpecter.sbom.json`
- [ ] `install.bat --uninstall` path
- [ ] `sysspecter doctor` subcommand
- [ ] README: "Quick start in 60 s" + Troubleshooting grown
- [ ] CHANGELOG entries per PR
- [ ] First tagged release `v1.1.0` produced by the release workflow, not by hand

---

## 7. How we know we reached 8/10

At end of week 3, run the **same multi-agent review** on the codebase and
compare scores. Every dimension must be ≥ 8. If any is below, open an
explicit follow-up issue with the delta and a cause analysis — we
accept slipping by ≤ 1 week on at most 2 dimensions, but not silently.

© 2026 David Juriga — SysSpecter

---

## Appendix — Field-Use Review (post-1.0 production findings)

Items below come from a real-world diagnosis (KTM MotoDB, multi-day
race-day workloads). They survive the multi-agent review's speculative
recommendations because they were validated against actual data the
tool produced. Numbering is the ID used in the field-review document.

### Bug fixes — data correctness

- [x] **B2** — `commit_used_bytes` / `commit_total_bytes` populated via
  `GlobalMemoryStatusEx` (was always None). `proc_queue_len` deprecated
  (kept for backwards-compat, will be dropped in schema v3).
- [x] **B3** — PDH counter rollover on `ctx_switches_per_sec` /
  `interrupts_per_sec`: negative deltas surface as `None` instead of
  `~-1.5e8` poisoning the timeline.
- [x] **B1** — three-way duration mismatch resolved. Both scores.json
  and findings.json now stamp an `analysis_window` block (start / end /
  duration / samples_analyzed / full_run_duration_seconds / trimmed)
  that downstream consumers (HTML report, comparison, splitter) read
  as the single source of truth. Contract pinned in
  `tests/test_analysis_window.py`.
- [x] **B4** — `cpu_freq_current_mhz` now reads
  `CallNtPowerInformation(ProcessorInformation)` across all logical
  CPUs and reports `max(CurrentMhz)` so single-core turbo is captured.
  Falls back to psutil only when powrprof is unavailable.
- [x] **B5** — `disk_active_pct_est` documented as estimate (rename
  deferred — touches 18 files including golden test fixtures).

### Schema additions — unlock new analyses

- [x] **H3** — `ppid` and `parent_name` in `timeline_processes.csv`. No
  more manifest-lookup-per-pid for parent attribution.
- [x] **H9** — `num_page_faults` per process (psutil). Leading
  indicator for memory pressure / swap thrash.
- [x] **S3** — `sample_late_ms` column in `timeline_system.csv`. Lets
  consumers distinguish "system was idle" from "we missed the tick"
  under load.
- [ ] **H1** — handle types over time (File/Event/Mutex/Section/COM)
  via `NtQuerySystemInformation(SystemHandleInformation)`. Diagnoses
  managed-handle leaks without ETW. **Open — weeks of work.**
- [ ] **H2** — managed-runtime metrics (.NET, JVM, Python). ETW
  `Microsoft-Windows-DotNETRuntime` for .NET; `\.NET CLR Memory(*)`
  perfcounters as MVP. **Open.**
- [x] **H4** — `process_events.json` was already always-on; the actual
  D3 issue (manifest.phase3 reflects request, not capture) is fixed
  by stamping `phase3_captured` from artefact-walk at finalisation.
- [x] **H5** — `timeline_per_core.csv` ships per run in long-format
  (timestamp / rel_seconds / core_idx / cpu_pct). Legacy semicolon
  blob in timeline_system.csv kept for backwards compatibility.
- [ ] **H6** — `cpu_user_pct` / `cpu_system_pct` as per-sample deltas
  alongside cumulative. **Open.**
- [ ] **H7** — CPU package power + temperature (Intel RAPL via MSR or
  Power Gadget). **Open.**
- [ ] **H8** — short-lived TCP connections via kernel ETW provider
  instead of polling. **Open.**

### Sampling discipline

- [ ] **S1** — sampler drops > 30 s gaps under load. Mitigations:
  HIGH_PRIORITY_CLASS, queue-based CSV writer, ETW for events. **Open.**
- [ ] **S2** — sampler is itself 95–98 % of one core. Native (Rust/C++)
  hot loop the strategic fix. **Open — months.**

### Analyzer engine

- [x] **A1** — sliding-window per-PID linear regression in
  `analyzer/leaks.py::_sliding_window_stats`. 1-h window / 10-min
  stride. `detect_memory_leaks` picks the peak-slope window for
  grading when it beats the full-run slope, with provenance
  annotated as `slope_source`. New `_find_plateau_start` annotates
  the leak-phase end. Catches the MotoDB-pattern (8 h leak +
  2 h plateau in a 10 h run) the old heuristic missed.
- [ ] **A2** — plateau / deadlock detection (RSS growth then RSS+CPU
  flat for 10 min).
- [ ] **A3** — periodicity detection on system metrics (autocorrelation
  finds Defender / EDR / SCM cycles).
- [ ] **A4** — process-tree visual reconstruction in HTML report.
- [ ] **A6** — cap-window-aware scoring (current scores normalize over
  full run length, comparable scores require canonical windows).

### Cross-domain (multi-vendor / multi-stack)

- [x] **C1** — stack-aware leak thresholds shipped:
  `sysspecter/analyzer/leak_thresholds.py` carries per-stack profiles
  for chromium / gecko / jvm / dotnet / cpython / nodejs / go /
  system / native; the C2 catalog tags processes with their stack;
  `detect_memory_leaks` looks up the profile per PID and tightens
  the bar before flagging. JVM-at-Xmx and Chromium-saw-tooth no
  longer fire (regression-tested). Original (jvm heaps, .NET server-GC
  saw-tooth, browser auto-GC differ from Python/Matlab). False
  positives blocked.
- [x] **C2** — JSON-driven process catalog
  (`assets/process_catalog.json`) covers all 7 major EDR vendors plus
  AV / VPN / MDM / DLP / browser / IDE / runtime / container / chat /
  cloud-sync. User override at
  `%APPDATA%\\SysSpecter\\process_catalog.json` beats shipped entry.
  Replaced hardcoded Microsoft-only sets in `analyzer/offenders.py`,
  `analyzer/bottlenecks.py`, `analyzer/grouping.py`. Pinned by 8
  contract tests.
- [ ] **C3** — machine-class baselines (developer / kiosk / terminal-
  server / engineering-workstation).
- [x] **C4** — `monitor --profile NAME` + `--list-profiles`. Shipped
  catalog: support / baseline / workload / leak-hunt / av-overhead /
  thermal / incident-snapshot / vpn-troubleshoot / security-audit.
  CLI flags override profile defaults; active profile stamped into
  `manifest.meta.capture_profile`. GUI Monitor-tab presets are
  generated from the same catalog (single source of truth).
- [ ] **C5** — cross-platform abstraction (ETW / eBPF / dtrace).

### Multi-tenant / fleet

- [x] **M1** — `monitor --redact` runs the sanitize pass automatically
  after the run finishes. Sanitizer rewritten to use stable hashes
  (`HOST-7f3a`, `USER-bb9c`, `BIOS-3e2d`) instead of literal
  `[REDACTED]`, so cross-process correlation survives redaction. New
  pre-pass strips credential-shaped substrings (passwords / tokens /
  Bearer / JWT / AWS keys / GitHub tokens) from every text field.
- [x] **M2** — `manifest.meta` block carrying structured fleet
  metadata (department / ticket / scenario / change_under_test /
  machine_class) alongside the existing free-form `tags` array.
  CLI flags: `--meta KEY=VALUE` (repeatable) plus convenience
  shortcuts. Pydantic schema validates; v1/v2 manifests without
  `meta` still load. Runs-tab filter searches both keys + values.
- [ ] **M3** — fleet aggregation tool downstream of capture.
- [ ] **M5** — stable `machine_id` independent of hostname renames.

### Architecture / strategic

- [ ] **X1** — native sampler (Rust/C++) reading the same APIs in
  1–2 % CPU instead of 95–98 %. Months.
- [ ] **X2** — hybrid ETW (events) + polling (samples) eliminates
  missed-event class entirely.
- [ ] **X3** — plug-in analyzer architecture (`analyzers/` directory,
  declared inputs/outputs, union of findings).
- [ ] **X4** — streaming / online analysis (live findings during long
  idle runs).

These items have been prioritized. The **B**-block plus **H3 / H9 / S3**
landed this session; **B1 / B4** remain as data-correctness debt that
needs correcting before fleet-rollout. **C1 / C2 / M1** are the
cross-domain blockers — without them every customer with a non-Microsoft
EDR or a JVM workload sees false positives.
