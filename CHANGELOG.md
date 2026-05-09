# Changelog

All notable changes to SysSpecter are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.3.0] — 2026-05-09

Closes the v1.2 production-test review (self-leak + 8 quality bugs +
regression suite) per the v1.3.0 implementation plan. **No new data
captures** in this release — the focus is making the v1.2 features
trustworthy on real production data. New data captures
(cross-run leak signature, JVM / Python managed heap, stack-aware
heuristic, RAPL thermal) are queued for v1.4 in `ROADMAP.md`.

### Phase A — self-leak fix

- **`--profile-leak` CLI flag** (Phase A.0) takes a `tracemalloc`
  snapshot every 60 s, writes a top-30 growing-source-locations report
  to `leak_profile.txt` at run end. Used to confirm the actual leak
  source instead of guessing.
- **Streaming JSONL events** (Phase A.1, Suspect 1) — `process_events`
  and `service_events` are now appended to `*.jsonl.partial` files as
  they arrive instead of accumulating in unbounded in-memory lists.
  At run end, atomic-rewrite to `process_events.json` /
  `service_events.json` (single JSON array, back-compat for existing
  `analyzer/loader.py` consumers).
- **Streaming gap statistics** (Phase A.1, Suspect 1) — replaces the
  `observed_gaps: list[float]` accumulator with a reservoir-sampling
  + running-counter `StreamingGapStats` class. Memory is O(1) in run
  length; the resulting `cadence_quality` block is byte-identical to
  the v1.2 list-based path.
- **`process_sampler` cache pruning** (Phase A.1, Suspect 3) —
  `_last_io` and `_last_cpu_time` are now pruned alongside
  `_proc_cache` on every `refresh_candidates()` call, bounding their
  size to the candidate set instead of letting stale PIDs accumulate.

### Phase B — eight quality bugs

- **B.1 deterministic_deadlock detector tightened** — full sequence
  required (180 s growth phase with R² ≥ 0.85 + 120 s plateau + 300 s
  CPU < 1 % + Pearson correlation ≥ 0.7 between RSS and handles
  during growth). Default-excludes svchost / Discord /
  msedgewebview2 / etc. Counting fix: dedup by `run_id` so "12 of 6
  runs" can never appear. Severity calibrated: ≥ 50 % share → high,
  ≥ 2 runs → medium.
- **B.2 peer_classes static-snapshot classifier** —
  `classify_from_static_snapshot` derives `machine_class` from
  Manufacturer / Model / FQDN / installed-programs (EDR / VPN
  markers) / Windows OS caption when `--machine-class` was not
  passed. New `peer_group_detailed` field exposes the rich
  `class:ram_class:cpu_thread_class` form for the analyst; the
  bucket-form `peer_group` keeps mismatch detection sensible.
  `machine_class_source` field tells consumers whether the value
  came from explicit user input or classifier inference.
- **B.3 `window_aligned_view` fresh-compute fallback** — when a run
  doesn't carry a pre-computed `tail_windows` block, the comparer
  re-invokes `analyzer/scores.compute_tail_window_scores` on the
  raw `rd.system_rows` to produce the windowed scores. Status
  taxonomy now: `aligned` / `too_short` / `empty` / `no_data`.
- **B.4 `primary_disk_tier` Storage-namespace ground truth** —
  static collector now also queries `Get-PhysicalDisk` for the
  modern `MediaType` (SSD / HDD / Unspecified) and `BusType` (NVMe /
  SATA / …). The classifier prefers these over the legacy
  `Win32_DiskDrive` model heuristics. Tier values are lowercase
  (`nvme` / `ssd` / `hdd` / `unknown`); never silently defaults to
  `hdd`.
- **B.5 manifest cadence-truth (schema_version 3)** — top-level
  `interval_seconds` now reflects the OBSERVED median gap after
  finalisation, not the declared target. New sibling fields:
  `interval_seconds_target` (immutable record), `interval_seconds_observed_median`,
  `interval_seconds_observed_p95`, `samples_emitted`,
  `samples_target_estimate`. Schema bump from 2 → 3.
- **B.6 recommendation second-pass dedup** — `generate_recommendations`
  gains a `(category, recommendation_text)` merge pass that
  collapses identical recommendations across runs into a single
  entry with a `targets` list. Severity promoted to the highest
  seen across the merge group; evidence aggregated.
- **B.7 `comparison_manifest.input_runs` portability** — list of
  `{run_id, captured_path}` dicts instead of raw dev-time path
  strings. `run_id` is the canonical reference; `captured_path` is
  informational and may be stale on relocated data.
- **B.8 verdict suppression** — `comparison_scores.json` no longer
  publishes `best_*` / `lowest_*` keys when the underlying ranking
  is sample-density-sensitive AND `trusted == False`. Consumers who
  want the unfiltered ranking read `rankings_with_confidence` from
  `comparison_findings.json`. The cadence-immune `fewest_anomalies`
  always publishes.

### Phase C — regression suite

15 new tests in `tests/test_v1_3_0_regression.py` covering: streaming
JSONL atomic-rewrite contract; reservoir-sampling stability at
100k-gap scale; manifest cadence-truth (broken-cadence overwrite +
zero-sample preservation); input_runs portable shape; recommendation
dedup with `targets` aggregation; verdict suppression; peer-class
classifier (enterprise-managed-laptop, personal-desktop, unknown);
explicit `--machine-class` overrides classifier. Plus 4 new tests
in `test_comparer_same_host_rules.py` (excludes-list, dedup-within-run)
and 2 new tests in `test_comparer.py` (storage-namespace tiering).
**514 unit tests pass, ruff clean, bandit clean (0 medium / 0 high).**

## [1.2.1] — 2026-05-09

CI fix only — no functional changes from `v1.2.0`. The `v1.2.0` tag
was created but the release workflow failed at the
"Reproducible timestamp for PyInstaller" step (a long PowerShell
one-liner with mismatched parentheses inside the `$(...)`
subexpression). Tests passed, but the EXE build / smoke / asset-
upload steps were skipped, so no `v1.2.0` Release object was ever
published. `v1.2.1` is the first actual published release of the
v3 production-test review work — see the `[1.2.0]` heading below
for the full feature list.

The fix replaced the PowerShell parser-killer with
`git log -1 --format=%ct`, which returns the commit timestamp
directly as a Unix epoch.

## [1.2.0] — 2026-05-09

This release closes out the v3 production-test review (7/7 priorities
shipped). Per-PID handle-type breakdown, .NET CLR managed-heap
counters with native-vs-managed leak attribution, cap-window-aware
comparison scoring, same-host pattern detection (run-cluster,
regime-change, deterministic-deadlock signatures), cadence-quality
visibility (manifest block + CSV columns + `HIGH_PRIORITY_CLASS`),
peer-context awareness (machine-class mismatch warnings), and
running-vs-installed software-bloat distinction with confidence
scoring on every diagnosis hypothesis.

**Headlines:**

- **Per-PID handle counts by object type** (priority 4 / H1) — new
  `timeline_handles.csv` via `NtQuerySystemInformation`. RCW signature
  detection (Section + Event handles climbing together = textbook
  COM Runtime-Callable-Wrapper leak).
- **.NET CLR managed-heap counters** (priority 5 / H2) — new
  `timeline_managed_heap.csv` via PDH. Gen-2 leak detection +
  **native-vs-managed attribution** ("RSS grew but managed heap was
  flat → look in unmanaged code").
- **Cadence visibility + sampler priority** (priority 1 / S1+S3) —
  `manifest.cadence_quality` block, `sample_late_ms` + `gap_seconds`
  in `timeline_system.csv`, runner self-elevates to
  `HIGH_PRIORITY_CLASS`.
- **Comparison engine guards** (priorities 2, 3, 6, 7):
  - Cadence-quality awareness — refuses to compare metrics across
    runs with mismatched cadence.
  - Peer-context awareness — flags `machine_class` mismatches before
    the verdicts.
  - Cap-window-aware scoring — headline verdicts use `last_1h` /
    `last_8h` tail windows when all runs are long enough; falls
    back with an explicit length-bias caveat otherwise.
  - Seven same-host pattern rules (run-cluster, regime-change,
    deterministic-deadlock, cross-run invariants, top-N consistency,
    exclusion gates).
- **Tighter root-cause claims** (priority 3) — software-bloat rule
  splits installed-vs-running, every hypothesis now carries a
  `confidence` field (high / medium / low), CI fix for ruff E402.

**495 unit tests pass, ruff clean, bandit clean.** Single-file
portable Windows EXE at `dist\SysSpecter.exe`.

### Added (v3-priority-7: same-host comparison rules)

The v2 production review's most damning finding: the engine fired
**nothing** on the GPLT3923 7-run same-host corpus despite every run
reproducing the same MotoDB bug. The HTML literally said *"No
hypotheses triggered by the current rule set."* Framework existed,
rule set was empty in the most-needed mode.

This release adds the seven rule families the v3 plan called out as
the missing analytics for `Before/after (same host)` mode:

- **New `comparer/same_host_rules.py`** module with seven detectors:

  1. **`detect_run_clusters`** — groups runs whose memory-leak
     slopes cluster within ±5 % coefficient of variation. The exact
     pattern from GPLT3923: 4 of 6 runs leaked MotoDB at
     1716 / 1764 / 1781 / 1761 KB/s (CV ≈ 1.5 %) — same bug
     reproducing deterministically. Severity goes high when ≥ 50 %
     of runs are in the cluster.
  2. **`detect_regime_changes`** — process-count discontinuities for
     the same process name across runs. 1 → 68 → 114 PIDs of
     `MotoDB.exe` is a worker-pool resize, not jitter; threshold
     10× ratio. Surfaces per-run counts so the analyst sees the
     full distribution.
  3. **`detect_deterministic_deadlocks`** — RSS plateau + handles
     plateau + CPU → 0 in the last-30-samples window across ≥ 2
     runs on the same process name. The most-actionable signal in
     a same-host leak corpus — points at the deadlock minute for
     ETW capture on the next reproduction.
  4. **`detect_cross_run_invariants`** — metrics constant across
     all runs. Currently fires two patterns: `network_score = 0.0`
     everywhere → policy-block hypothesis (e.g. ICMP filtered by
     Zscaler / firewall — chasing per-run network anomalies won't
     resolve); GPU adapter idle drain (power > 5 W with utilisation
     < 1 %) → driver / power-state issue.
  5. **`detect_top_n_consistency`** — processes appearing in the
     top-N CPU/mem consumers across ≥ 50 % of runs. Surfaces the
     constant-baseline-cost contributors so per-run anomalies on
     them aren't mistaken for root cause.
  6. **`detect_excluded_runs`** — flags runs that should NOT appear
     in `best_*` rankings: zero samples (the v2 empty-run-wins-best-
     overall bug), short runs below the verdict floor (60 s), broken
     cadence (median gap > 3× nominal), too-few-samples runs.
  7. *(Confidence gates fold into rule 6 — the same exclusion
     check is what `best_*` rankings consult.)*

- **Top-level orchestrator `build_same_host_findings(loaded, mode)`**.
  Always-on: rules 4 + 6 (invariants + exclusions are useful in any
  mode). Same-host-only: rules 1, 2, 3, 5 (these only make sense
  comparing the same host across time).

- **`comparison_findings.json`** gains a top-level
  `same_host_findings` block. Findings are also folded into
  `root_causes` after cadence + peer-context layers, so the existing
  HTML/MD report renders them automatically with the standard
  finding shape (`severity`, `confidence`, `category`, `kind`,
  `run_id`, `peer_id`, `hypothesis`, `evidence`, `recommendation`,
  `affected_runs`).

- 21 new unit tests pinning each rule against hand-crafted cohorts
  that mimic the GPLT3923 patterns the v2 engine missed:
  - 4-of-6 cluster fires high severity
  - divergent slopes don't cluster
  - regime change fires on 1 → 68 PID jump
  - 1 → 2 PID jitter doesn't fire
  - deadlock fires on 2-of-3-runs match, doesn't fire on 1 run
  - short runs (< 30 samples) skip deadlock detection
  - network-zero invariant fires only when ALL runs match
  - GPU idle drain invariant on every run
  - top-5 consistency fires at ≥ 50 % share, not below
  - exclusion gates: zero-sample, short, broken-cadence runs
  - non-`before_after` mode skips same-host-only rules
  - cross-run invariants still fire in fleet mode

495 tests pass (was 474, +21 new), ruff clean, bandit clean.

### Added (v3-priority-6: cap-window-aware comparison alignment — A6)

The v2 production review made this priority urgent: the comparison
engine consumes raw scores computed over each run's full window.
ATLT4407 (902 s) vs MORGANA (1469 s) gave MORGANA a free advantage
on every "average over time" metric — it integrated over a 62 %
longer window. Any verdict like *"MORGANA is more efficient"* was
biased by length before it reflected behaviour.

The fix in v1.1.0 shipped per-run tail-window scores
(`last_1h` / `last_8h` via `analyzer/scores.compute_tail_window_scores`)
but the comparison engine never used them. This release closes that
loop:

- **New `comparer/window_alignment.py`** module with four primitives:
  - `detect_aligned_window(loaded)` — picks the widest tail window
    every loaded run can produce (`last_8h` preferred over `last_1h`),
    returns `None` when at least one run is too short.
  - `aligned_score(scores, window_label, key)` — single-cell lookup
    handling both flat (`overall`) and nested-with-`.score`
    (`stability.score`) shapes.
  - `build_aligned_view(loaded, window_label)` — per-run rows at the
    aligned window with explicit `alignment_status`
    (`aligned` / `too_short` / `no_data`) so the report can
    distinguish "ran but not long enough" from "legacy pre-A6 run".
  - `aligned_rankings(loaded, window_label)` — parallel rankings
    (`best_overall`, `best_stability`, etc.) computed against the
    aligned window. Skips runs that don't have it, returns empty
    dict when no common window exists so callers fall back cleanly.

- **Headline-verdict order of preference** in `compare_runs.py`:
  1. **Aligned-window ranking** (this priority) — length-fair.
  2. **Cadence-annotated raw ranking** (priority 2) — excludes
     broken-cadence runs from sample-density-sensitive metrics.

  This prevents ATLT4407 from winning "best efficiency" purely
  because its 902 s run integrated over a shorter window. The
  `comparison_scores.json` headline now also carries
  `chosen_window: "last_1h" | "last_8h" | "full_run"` so consumers
  can immediately see which frame the verdict was computed on.

- **`comparison_findings.json` gains** `window_aligned_view` (the
  per-run scores at the aligned window, mirrored from `cross_run_view`
  but enriched with per-row `alignment_status`) and
  `window_aligned_rankings` (the rankings used for headline verdicts).

- **HTML + Markdown reports** gain a "Cap-window-aligned scoring"
  banner above the verdicts:
  - **Aligned**: green `length-fair` pill + the chosen window label.
    Verdict pills also carry the chosen window (e.g. `on last_1h`).
  - **Unavailable**: amber banner explaining at least one run is
    shorter than 1 h, with an explicit "treat headline rankings as
    length-influenced" caveat.

  Plus a **per-run scoring table at the aligned window** showing
  status pill (`aligned` / `too short` / `no data`), the six score
  columns, and sample count in the window.

- 19 new unit tests pinning: widest-common-window selection (`last_8h`
  preferred over `last_1h`, falls back when only some runs have it);
  the ATLT4407-too-short pattern (no alignment possible); legacy
  back-compat (pre-A6 runs surface as `no_data`); aligned rankings
  prefer window scores over full-run; rankings skip runs missing the
  window; sub-score (`.score`) shape resolution; per-run
  `alignment_status` distinguishes `too_short` from `no_data`.

474 tests pass (was 455, +19 new), ruff clean, bandit clean.

### Added (v3-priority-5: .NET CLR managed-heap counters — H2)

The second-most-impactful missing-data item from the v3 plan. Without
it, the analyzer can't distinguish a native leak (RSS grows, managed
heap flat — C/C++/COM bug) from a managed leak (RSS grows, gen-2 also
grows — retained roots in .NET). Critical for any .NET / Matlab /
Office workload — most of enterprise.

- **New `collector/managed_heap_sampler.py`** module. Reads the
  `.NET CLR Memory` PerformanceCounter category via PDH (`win32pdh`,
  already a hard dependency through pywin32). Counters captured per
  .NET process: bytes-in-all-heaps, gen-0/1/2/LOH heap sizes, gen-0/1/2
  collection counts, % time in GC, pinned objects, allocated bytes/sec.
  Instance → PID mapping via the parallel `Process ID` counter, with
  fallback to parsing the `<exe>_p<pid>` suffix that modern .NET emits.
  Soft-degrades to `[]` on every error path: non-Windows, pywin32
  missing, no .NET apps running, locked-down host, .NET-Core-only
  runtime (where the category isn't populated).

- **New `timeline_managed_heap.csv`** with columns
  `[timestamp, rel_seconds, pid, name, bytes_in_all_heaps,
  gen0_heap_size, gen1_heap_size, gen2_heap_size,
  large_object_heap_size, gen0_collections, gen1_collections,
  gen2_collections, pct_time_in_gc, pinned_objects,
  allocated_bytes_per_sec]`. Sampled every 30 s by default.
  Runner stamps `mark_degraded("managed_heap_sampler", ...)` on the
  first empty probe so the report knows the data is missing.

- **New `analyzer/managed_heap.py` module + `findings.managed_heap_leaks`
  block.** Two outputs:

  - **`managed_leaks`**: per-PID gen-2 heap-size slope detection
    with thresholds at 50 KB / 500 KB / 5 MB per minute (low /
    medium / high severity). The `gen2_collections_observed` field
    surfaces "leak despite GC pressure" — the textbook retained-roots
    signature.
  - **`native_only_leaks`** — *the killer feature*: when RSS grows
    but the managed heap is flat (managed share < 20% of RSS growth),
    the leak is in unmanaged memory (C/C++/COM allocations, native
    handle stores). Emits `ratio_native_share` so the analyst can see
    "94% of this PID's RSS growth is unmanaged → look in native code".
    Without v3-priority-5 the prior MotoDB diagnosis was stuck at
    "consistent with COM RCW leak"; with it, the engine can say
    "verified native-only leak in MotoDB.exe — managed heap stable
    while RSS grew 10 MB/min".

- `paths.RunPaths.timeline_managed_heap_csv` and
  `RunData.managed_heap_rows`. Fully back-compat — pre-v3 runs
  without the CSV simply get an empty list.

- `config.MANAGED_HEAP_PROBE_INTERVAL = 30` for tuning.

- 23 new unit tests pinning: PDH wrapper soft-degrade (non-Windows,
  pywin32 missing, no .NET instances); instance-name parsing
  (`<exe>_p<pid>` suffix, PDH `#<n>` disambiguator, plain names,
  false-positive guard for names like `firefox_private`); CSV row
  shape against `MANAGED_HEAP_FIELDS`; gen-2 threshold ladder;
  `gen2_collections_observed` reporting; the native-only diff (fires
  when RSS grows + heap flat, doesn't fire when both grow together,
  skips PIDs with no RSS growth, skips when process_rows empty);
  multi-PID severity ordering; back-compat with empty/None inputs.

JVM and Python managed-heap counters are deferred to v3-priority-5b
in a follow-up round.

455 tests pass (was 432, +23 new), ruff clean, bandit clean.

### Added (v3-priority-4: per-PID handle counts by object type — H1)

The single most-impactful missing-data item from the v2 production
review. Without it, the prior MotoDB diagnosis was stuck at "consistent
with COM RCW leak" — a slow, opaque growth in `num_handles`. With this,
the engine can now say "15 000 Section + 12 000 Event handles vs a
baseline of 200 over a 10 min window — that's a COM Runtime-Callable-
Wrapper leak in N seconds, verified."

- **New `collector/handles_sampler.py` module.** Calls
  `NtQuerySystemInformation(SystemExtendedHandleInformation, …)` to
  walk the kernel's full handle table, then `NtQueryObject(NULL,
  ObjectAllTypesInformation, …)` once per process to resolve
  ObjectTypeIndex → human-readable type name (`File`, `Event`,
  `Mutant`, `Section`, `Thread`, `Process`, `Token`, etc.). Aggregates
  per (PID, type_name). Top-N gate (default 50 PIDs) keeps the CSV
  manageable on hosts with hundreds of PIDs. Soft-degrades to []
  on every error path: non-Windows, ntdll missing, sandboxed, or
  locked-down. Live smoke on a real Windows host: 73 object types
  resolved, 34k+ handles aggregated across top 5 PIDs.

- **New `timeline_handles.csv`** with columns
  `[timestamp, rel_seconds, pid, name, type_name, count]`. Sampled
  every 60 s by default — too cheap to skip, and per-second would
  burn CPU on hosts with > 500 k handles. The runner stamps a
  `mark_degraded("handles_sampler", …)` on the manifest when the
  first probe returns empty so consumers know the data is missing.

- **New `analyzer/handle_types.py` module + `findings.handle_leaks_by_type`
  block.** Per (PID, type) least-squares slope (handles per minute);
  thresholds at 5 / 30 / 200 handles/min for low / medium / high
  severity. Noisy types (`Job`, `Driver`, `Type`, `Adapter`) are
  excluded — they grow naturally and aren't actionable as "leaks".
  Findings sorted by severity then slope.

- **RCW signature detection.** When a PID is leaking BOTH `Section`
  AND `Event` handles in tandem (each crossing the medium threshold),
  emit a `rcw_signature_candidates` entry — the textbook COM Runtime-
  Callable-Wrapper leak signature. This is what would have moved the
  prior MotoDB diagnosis from "consistent with" to "verified."

- **`config.py`**: `HANDLES_PROBE_INTERVAL = 60`,
  `HANDLES_TOP_N_PIDS = 50` for tuning.

- **`paths.RunPaths.timeline_handles_csv`** and
  `RunData.handles_rows` (with `_coerce_handles_row`); fully
  back-compat — pre-v3 runs without the CSV simply get an empty
  list.

- 27 new unit tests pinning: ObjectTypeIndex resolution + cache
  reset; `_aggregate` against hand-crafted SystemExtendedHandleInfo
  buffers (groups by (pid, type), drops PID 0, falls back to
  `TypeIndex_<n>` when types unresolved); top-N PID capping;
  soft-degrade when query fails; CSV row shape; the analyzer's
  threshold ladder (low/medium/high); noisy-type exclusion; RCW
  signature firing only when Section+Event grow together; backward-
  compat with empty/None inputs; multi-PID ordering by severity.

432 tests pass (was 405), ruff clean, bandit clean.

### Added (v3-priority-3: tighter root-cause claims)

The v2 production review caught the engine making a confident causal
claim that didn't hold up: it attributed the 20-point efficiency gap
between ATLT4407 and MORGANA to "106 unused software programs."
Most of those programs (Adobe Reader, 7-Zip, Beyond Compare,
BeyondTrust, Check Point) were *installed* but not *running*; the
real gap was driven by RAM (16 vs 64 GB), cores (4 vs 16), and
active workload (Claude Code on ATLT4407 vs idle MORGANA).

Three concrete tightenings:

- **New `comparer/peer_context.py` module.** Lifts each run's
  `manifest.meta.machine_class` (per C3) into a peer-group taxonomy
  (`workstation` / `office` / `embedded` / `terminal-server`).
  When two runs are in different peer groups, emits a medium-
  severity `machine_class_mismatch` finding with high confidence
  (rule-based on declared metadata) so the report can flag
  non-peer comparisons before the verdicts. A low-severity
  completeness note suggests `--machine-class` for legacy runs.

- **Software-bloat rule split** into two paths in `diagnosis.py`:
  - `running_software_delta` (medium severity, medium confidence) —
    fires when at least one of the unique-to-A programs has a
    matching running process. Real causal mechanism. Wording uses
    "may contribute to" not "explains."
  - `installed_software_delta_candidate` (low severity, low
    confidence) — fires when the diff is installed-only with no
    running evidence. Surfaced as a candidate factor with explicit
    "Treat this as one of several plausible factors — RAM, core
    count, and active workload typically dominate" guidance.
  Per-pair de-duplication: only one of the two fires per pair.
  Helpers: `_running_process_names(run)` extracts lowercased,
  `.exe`-stripped process names from `rd.process_rows`;
  `_running_overlap(installed, running)` matches installed program
  strings to running process names with token-overlap fallback for
  multi-word names like "Microsoft Edge" matching `msedge`.

- **`confidence` field added to all diagnosis rules** (`high` /
  `medium` / `low`):
  - `disk_tier_mechanical` → high (direct mechanism, WMI-classified)
  - `memory_pressure_smaller_ram` → high (both sides observed)
  - `cpu_lower_clock` → medium (IPC + core count can dominate)
  - `non_high_performance_plan` → medium (workload-type-dependent)
  - `multiple_av_products` → medium (no per-product CPU breakdown)
  - `machine_class_mismatch` → high (rule-based on declared metadata)
  Each finding now also carries a stable `kind` field for
  downstream reasoning. `generate_recommendations` propagates
  `confidence` through to the report.

- **`comparison_findings.json` gains** `peer_classes` and
  `peer_mismatch_warnings`. Peer findings are prepended to
  `root_causes` after the cadence findings — order: cadence (data
  trust), peers (comparison fairness), then the rest.

- **HTML + Markdown reports** gain a "Peer context" section
  parallel to "Cadence quality" — banner when non-peers, per-run
  machine_class table. The hypotheses table gains a "confidence"
  column with colour-coded pills (good / degraded / unknown =
  high / medium / low). Recommendations show severity AND
  confidence side by side.

- 24 new unit tests pinning: `_running_process_names` /
  `_running_overlap` helpers; the running-vs-installed split (good
  case fires medium-confidence, no-running case fires
  low-confidence, never both); peer-context normalisation +
  alias handling; the ATLT4407↔MORGANA case (general-knowledge-worker
  vs developer-workstation → mismatch); legacy back-compat
  (undeclared machine_class doesn't trigger findings on its own).

405 unit tests pass (was 381), ruff clean, bandit clean.

### Added (v3-priority-2: comparison-engine cadence-quality awareness)

The v2 production review found the engine's biggest practical bug:
ATLT4407 (median sample gap 18 s) was matched against MORGANA
(median 1.1 s) on `cpu_avg`, `mem_avg`, `latency_p95_ms` etc. without
acknowledging that one side averaged over 55 samples and the other
over 504. Every "ATLT4407 vs anything" comparison silently misled.

This release closes that hole now that v3-priority-1 ships the
per-run `manifest.cadence_quality` block:

- New `comparer/cadence_quality.py` module:
  - `extract_per_run(loaded)` lifts each run's `cadence_quality` with
    a back-compat path for pre-v3 runs (surfaces them as
    `cadence_health="unknown"` / `back_compat=True`).
  - `classify_metric(name)` returns
    `sample_density_sensitive` / `event_count` / `static` so the
    engine knows which columns are apples-to-undersampled-apples.
  - `build_asymmetry_findings(per_run)` produces three patterns of
    cross-run findings: (1) any broken-cadence participant (high
    severity, lists affected metrics); (2) mixed-health comparison
    (medium); (3) pairwise gap-ratio > 2× even when both sides
    nominally good (medium). De-duplicated so a broken finding
    swallows a redundant ratio finding.
  - `annotate_rankings(rankings, per_run)` excludes broken/no_data
    runs from sample-density-sensitive `best_*` rankings — the
    headline guard. Event-count rankings (`fewest_anomalies`) are
    unaffected. Each ordered entry carries a per-cell confidence
    marker (`trusted` / `degraded`); each ranking has a top-level
    `trusted: bool` reflecting whether any participant is degraded.

- Comparison matrix (`matrix.py`) gains three columns:
  `cadence_health`, `median_gap_s`, `process_priority_class`.

- `comparison_findings.json` gains three new top-level fields:
  `cadence_quality_per_run`, `cadence_quality_warnings`,
  `rankings_with_confidence`. Cadence findings are also prepended
  to the `root_causes` list (they rank ahead of other hypotheses
  because if cadence is broken, every other inference downstream is
  built on shaky data).

- `comparison_scores.json` headline verdicts now read the cadence-
  annotated rankings instead of the raw ones — so an under-sampled
  run can no longer win a sample-density-sensitive `best_*` slot.

- HTML + Markdown reports gain a "Cadence quality" section at the
  top (above the verdicts). When all participants are healthy, a
  green confirmation banner. When asymmetric, a red banner listing
  the warnings + a per-run cadence table (health pill, median /
  p95 / max gap, samples, priority class). Cadence-degraded
  rankings get a visible pill in the verdicts list so the reader
  sees why the headline is qualified.

- 22 new unit tests pinning the ATLT4407-vs-MORGANA case end-to-end
  (broken finding fires; ATLT4407 excluded from `lowest_cpu_avg`;
  MORGANA wins; `fewest_anomalies` keeps both; back-compat path
  for pre-v3 runs surfaces as unknown without raising).

381 unit tests pass (was 359), ruff clean, bandit clean.

### Added (v3-priority-1: cadence visibility — S1 + S3)

The v2 production-test review on ATLT4407 (HP EliteBook 840 G8 / i5-1145G7
/ 16 GB) showed the sampler silently drifted from a nominal 1 Hz to a
**median 18 s gap** under a corporate-managed laptop's load profile,
while the manifest still claimed `interval_seconds: 1.0`. A consumer
reading the manifest would compute averages assuming 902 samples and
find 55. This release closes that trust-contract gap.

- **`sample_late_ms` and `gap_seconds` columns** added to
  `timeline_system.csv`. The `sample_late_ms` field had been computed
  on the dataclass since v1.1.0 (S3) but was silently dropped at the
  CSV writer because `SYSTEM_FIELDS` didn't list it. `gap_seconds` is
  the wall-clock between consecutive samples — answers a different
  question from `sample_late_ms` (drift vs. preemption).
- **Runner now passes `scheduled_at=next_tick`** to
  `collect_system_sample`. Without this, `sample_late_ms` was always
  0 even when ticks were chronically late.
- **`cadence_quality` block** added to `manifest.json` at run-end.
  Fields: `nominal_interval_seconds`, `samples_total`,
  `median_gap_seconds`, `p95_gap_seconds`, `max_gap_seconds`,
  `gaps_over_2x_nominal`, `gaps_over_5x_nominal`, `cadence_health`
  (`good` / `degraded` / `broken` / `no_data`),
  `ratio_median_to_nominal`. Comparison engines use this to refuse
  cross-run analyses across heterogeneous cadence quality.
- **HIGH_PRIORITY_CLASS** set on the SysSpecter process at runner
  start (Windows). Falls back to ABOVE_NORMAL, then NORMAL, then
  UNCHANGED if the OS denies the bump (e.g. EPM lockdown). Achieved
  level recorded as `process_priority_class` in the manifest.
- **`update_manifest_end`** gained two optional kwargs
  (`cadence_quality`, `process_priority_class`) — fully back-compat:
  callers that don't supply them get the v1.1.0 behaviour and the
  manifest stays free of stale keys.

Schema unchanged (`schema_version: 2` — purely additive). CSV loaders
unaffected (DictReader reads by header name). 359 unit tests, ruff
clean, bandit clean.

## [1.1.0] — 2026-05-08

This release closes out the production-use field-review audit
(26/26 items shipped). Headlines below; the per-item changelog
sits under each ID.

**Data correctness (B-block, 5/5)** — three-way duration ambiguity
resolved (B1), commit charge populated (B2), PDH counter rollover
guarded (B3), CPU frequency reads turbo via `CallNtPowerInformation`
(B4), `disk_active_pct_est` documented (B5).

**Schema additions (H-block, 5/5)** — `ppid` + `parent_name` in
process timeline (H3), `phase3_captured` reflects what actually
fired (H4/D3), per-core CPU as long-format CSV (H5),
`num_page_faults` per process (H9), `sample_late_ms` records
sampler back-pressure (S3).

**Engine reife (A-block, 6/6)** — sliding-window leak detection
(A1), deadlock-after-leak signature (A2), periodic-pattern
detection by autocorrelation (A3), process-tree visual (A4),
cross-run aggregation view (A5), cap-window-aware scoring (A6).

**Cross-domain (C-block, 5/5)** — stack-aware leak thresholds (C1),
process catalog with EDR/AV/VPN/MDM coverage (C2), machine-class
baselines (C3), capture profiles (C4), platform abstraction
layer (C5).

**Multi-tenant (M-block, 4/4)** — privacy redaction at capture
with stable hashes (M1), structured fleet metadata (M2), fleet
aggregation tool (M3), stable machine_id (M5 incl. SID tier).

**Foundations** — silent-except audit, dev-deps pinned,
SECURITY.md + CONTRIBUTING.md, pre-commit, E2E smoketest,
22 collector safety-net tests, JSON-Lines-ready heartbeat,
typography hierarchy, focus styles, progressive disclosure
in Monitor tab.

341 unit tests, ruff clean, bandit clean. Single-file portable
EXE under `dist/SysSpecter.exe`.

**Release-audit fix** — `process_catalog.catalog()` deadlocked on its
own first cold call because `Lock` was non-reentrant (caller already
held the lock when invoking `reload()`). Caught while running the
release-gate test suite; fixed by switching to `RLock` and pinned with
a regression test (`test_catalog_first_call_does_not_deadlock`).

See full per-ID detail below.



### Fixed (data correctness — from production-use review)

- **B4**: `cpu_freq_current_mhz` no longer reads WMI's nominal P-state
  (which capped at 1532 / 2500 MHz on an i7-13800H even at full turbo).
  The sampler now calls `CallNtPowerInformation(ProcessorInformation)`
  via ctypes, queries every logical CPU, and reports
  `max(CurrentMhz)` — so any single-core boost is captured. Falls
  back to `psutil.cpu_freq()` only on locked-down hosts where
  `powrprof.dll` is unavailable.

### Added

- **M3** (fleet aggregation): new `sysspecter aggregate` subcommand
  + `sysspecter/aggregator/` package answers fleet-wide questions
  that single-run analysis can't:
    - **Per-axis fleet distribution** (mean, p50, p95, std) across
      every run in the input tree.
    - **Outliers** — machines whose latest run is ≥ 2σ off the
      fleet mean, ranked by |z-score|.
    - **Per-machine longitudinal view** — runs grouped by M5
      `machine_id`, sorted by start time, with first-vs-last drift
      per score axis. Survives hostname renames thanks to M5.
    - **Common baseline-deviation rollup** — C3 deviations seen
      across multiple machines surface as fleet-wide problems
      (`machines_affected` / `machines_in_class`).
  Output: `<output-root>/Aggregations/AGG_<ts>/` containing
  `manifest.json`, `aggregated_findings.json`, `per_machine.csv`,
  `fleet_report.html`. CLI:
  `sysspecter aggregate --input C:\Temp\SysSpecter\Runs`. Builds
  on M5 (machine_id), M2 (meta), C3 (baselines), A6 (tail
  windows). 14 contract tests in `tests/test_aggregator.py`
  covering loader edge cases (broken folders, deep tree walks),
  fleet-stats math, outlier semantics (latest-run-per-machine,
  z-score threshold, recovery from old bad data), drift
  computation, and the full end-to-end CLI flow.

- **C5** (cross-platform abstraction): new `sysspecter/platforms/`
  package introduces a `Platform` ABC for OS-specific calls. Today
  it has one concrete implementation (`WindowsPlatform`) plus a
  stub (`PosixPlatform`) for Linux / macOS that returns `None` for
  Windows-only signals (SMBIOS UUID, Machine SID) and uses stdlib
  `os.geteuid` for admin detection. The four duplicated
  `IsUserAnAdmin()` blocks in `manifest.py`, `doctor.py`,
  `gui/components/status_bar.py`, `gui/tab_monitor.py` now all
  flow through `platforms.platform().is_admin()` — single point
  of truth instead of four. `compute_machine_id()` reaches its
  three primitives through the ABC, so a future POSIX collector
  tier can ship a real Linux / macOS machine_id without touching
  the resolver. Architecture pinned in
  [ADR-0006](docs/adr/0006-cross-platform-architecture.md). 17
  contract tests in `tests/test_platforms.py` cover factory caching,
  `set_platform` / `reset_platform`, Windows delegation, POSIX
  fallback semantics, and the M5 contract preservation.

- **A5** (cross-run aggregation view): `sysspecter compare` already
  shipped auto-mode-detection + HW/SW diff + evidence-based
  recommendations, but it didn't use any of the new schema fields
  (M5 machine_id, M2 meta, A6 tail_windows, C3 baseline_deviations,
  C4 capture_profile). New module
  `sysspecter/comparer/cross_run_view.py` lifts those fields into a
  single block in the comparison output:
    - `same_machine` flag (true when every run shares a machine_id)
    - `machine_ids` (per-run machine_id + source for inspection)
    - `shared_machine_class` / `shared_capture_profile` /
      `shared_meta` (entries every run agrees on — set only when
      all runs match)
    - `tail_window_view` with the LARGEST common A6 window all
      runs cover, plus per-run rows showing all 7 score axes in
      that window (length-comparable scores at last)
    - `baseline_deviations.common` — C3 deviations every run shares
      (the "fleet-wide problem" indicator), plus `per_run` for the
      run-specific ones
  HTML compare report adds a "Cross-run view" section between the
  matrix and the Hardware diff. 15 contract tests in
  `tests/test_cross_run_view.py` pin the same-machine /
  shared-meta / tail-window-alignment / common-baseline-deviations
  semantics.

- **C3** (machine-class baselines): new analyzer module
  `sysspecter/analyzer/machine_class_baselines.py` ships per-class
  baseline profiles (developer-workstation / engineering-workstation /
  general-knowledge-worker / kiosk / terminal-server / factory-floor)
  and a detector that flags metrics outside the class baseline.
  Reads the machine class from `manifest.meta.machine_class` (set
  via `monitor --machine-class X` from M2 or via a capture profile's
  suggested_meta from C4). Findings are distinct from absolute
  Thresholds — the absolute path catches acute problems on any
  class, the baseline path catches "this machine isn't behaving
  like a typical member of its declared class". Each finding
  carries `severity` (high / medium / low scaled by distance from
  band), `direction` (above / below), and a human-readable
  `description`. HTML report ships a dedicated "Baseline deviations"
  section. 18 contract tests covering catalog completeness, alias
  resolution, the motivating cases (15% CPU normal on dev /
  abnormal on kiosk), severity scaling, and back-compat
  (no-class-declared yields no findings).

- **M5** (stable machine_id): manifests now carry a hardware-derived
  identifier `machine_id` of the form `MACHINE-xxxxxxxx` (8 hex
  chars). Same hardware → same id, regardless of hostname renames,
  re-images, or fleet-wide rename campaigns — fixing the legacy
  longitudinal-trending bug where renaming a laptop wiped its run
  history. Fallback chain (most-stable first):
    1. SMBIOS UUID (`Win32_ComputerSystemProduct.UUID`) — survives
       OS reinstalls; tied to the hardware itself.
    2. Windows Machine SID (`S-1-5-21-X-Y-Z` prefix of any local
       account SID, queried via `Win32_UserAccount`) — survives
       hostname renames AND NIC swaps; only changes on full OS
       reinstall. The field-review's named "MAC + SID + something
       durable" recipe.
    3. Physical NIC MACs sorted + joined.
    4. Hostname (last-resort fallback, flagged as weak).
  The accompanying `machine_id_source` field tells consumers which
  tier was used so fleet aggregators can warn on the weak
  `hostname_fallback` tier. Pydantic schema accepts the new fields;
  v1/v2 manifests written before this commit still load. 19 contract
  tests in `tests/test_machine_id.py`.

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

[Unreleased]: /compare/v1.3.0...HEAD
[1.3.0]: /releases/tag/v1.3.0
[1.2.1]: /releases/tag/v1.2.1
[1.2.0]: /releases/tag/v1.2.0
[1.1.0]: /releases/tag/v1.1.0
[1.0.0]: /releases/tag/v1.0.0
