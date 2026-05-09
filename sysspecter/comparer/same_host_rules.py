"""v3-priority-7: same-host comparison rules.

The v2 production review found the engine fired NOTHING on the
GPLT3923 7-run same-host corpus despite every run reproducing the
same MotoDB bug. The HTML literally said "No hypotheses triggered by
the current rule set." This module is the missing rule layer for
the `before_after` (same-host across time) mode.

Seven rule families per the v3 plan:

1. **Run-cluster detection** — group runs whose memory-leak slopes,
   end-state RSS, and end-state handles cluster within ±5 % CV.
   Strong signal that the same bug reproduces deterministically.

2. **Regime-change detection** — process-count discontinuities for
   the same process name across runs (e.g. 1 → 68 → 114 MotoDB.exe
   when a worker pool gets reconfigured).

3. **Deterministic-deadlock signature** — RSS plateau + handles
   plateau + CPU → 0 in the same time window across ≥ 2 runs on
   the same process name. The most-actionable signal in a same-host
   leak corpus.

4. **Cross-run invariants** — metrics constant across all runs
   (e.g. `network_score = 0.0` everywhere → ICMP-block hypothesis;
   GPU idle drain everywhere → driver-side issue).

5. **Top-N process consistency** — processes that appear in the
   top-N CPU/mem consumers across ≥ 50 % of runs. Constant
   offenders worth surfacing as a finding rather than hiding in
   per-run offender lists.

6. **Exclusion gates** — runs with 0 samples or sampler-died-early
   are flagged `not_comparable` so they don't dominate `best_*`
   rankings (the empty-run-wins-best-overall bug from v2).

7. **Confidence gates** — `best_*` verdicts require minimum sample
   density and minimum run length. Pairs with `chosen_window` from
   v3-priority-6 to keep verdicts honest.

All rules emit findings with the standard shape (`severity`,
`confidence`, `category`, `kind`, `run_id`, `peer_id`, `hypothesis`,
`evidence`, `recommendation`) so they thread through the existing
report renderer without bespoke handling. Most fire only when
`mode == "before_after"` — comparing same-host runs across time —
because that's where the analytical leverage is.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any

# Rule 1: cluster runs whose leak slopes are within this coefficient
# of variation. CV ≤ 5 % is "tight" — same bug reproducing.
_CLUSTER_SLOPE_CV_MAX = 0.05

# Rule 2: process-count discontinuity. A 10× change in count for the
# same name indicates a regime change (e.g. worker pool resize), not
# normal jitter.
_REGIME_CHANGE_RATIO = 10.0

# Rule 3 (v1.3.0 B.1): deterministic-deadlock heuristic — TIGHTENED.
# v1.2 fired on Discord / svchost / msedgewebview2 / NVIDIA Overlay /
# steamwebhelper because the signature was too loose ("CPU≈0 + RSS at
# peak"). The v1.3 rule requires a full sequence: growth phase (linear
# RSS regression with R²≥0.85, slope≥50 KB/s, ≥180 s) → plateau phase
# (≥120 s, |slope|<10 KB/s, RSS within 5 % of growth max) → CPU-zero
# phase (CPU<1 % for ≥300 s). Plus a handle-RSS Pearson r > 0.7
# during growth. A normal idle browser worker doesn't show this.
_DEADLOCK_GROWTH_MIN_SECONDS = 180.0
_DEADLOCK_GROWTH_MIN_R2 = 0.85
_DEADLOCK_GROWTH_MIN_SLOPE_BPS = 50 * 1024  # 50 KB/s
_DEADLOCK_PLATEAU_MIN_SECONDS = 120.0
_DEADLOCK_PLATEAU_MAX_SLOPE_BPS = 10 * 1024  # 10 KB/s
_DEADLOCK_PLATEAU_RSS_TOLERANCE = 0.05  # 5 % below growth max
_DEADLOCK_CPU_ZERO_MIN_SECONDS = 300.0
_DEADLOCK_CPU_ZERO_PCT = 1.0
_DEADLOCK_HANDLE_CORR_MIN = 0.7

# Default-exclude list: processes whose normal idle behaviour
# resembles "CPU=0 + RSS plateau" because they spawn helpers that
# stay around. v1.2 fired on every one of these. Configurable via
# a future `sysspecter/domain/deadlock_excludes.yaml` override; the
# defaults live here so the EXE works without external files.
_DEADLOCK_DEFAULT_EXCLUDES: frozenset[str] = frozenset({
    # Kernel-resident pseudo-processes
    "system idle process", "system", "memcompression", "memory compression",
    "registry", "secure system",
    # Critical OS services
    "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "fontdrvhost.exe",
    "svchost.exe",  # canonical false-positive in v1.2 (503 of 6 reports)
    "dwm.exe",
    "explorer.exe",
    "runtimebroker.exe",
    "searchindexer.exe",
    "ctfmon.exe",
    "sihost.exe",
    "taskhostw.exe",
    # Common always-on helpers
    "msedgewebview2.exe", "discord.exe", "steamwebhelper.exe",
    "nvidia overlay.exe", "nvcontainer.exe", "nvidia share.exe",
    "spotify.exe", "teams.exe", "ms-teams.exe", "code.exe",
})

# Rule 5: a process appearing in the top-N consumers across this
# fraction of runs is itself a finding. 50 % = 4 of 8 runs.
_CONSISTENCY_THRESHOLD = 0.50

# Rule 7: minimum sample density for a "best_*" verdict to be
# trustworthy. 30 samples is a conservative floor — below that,
# any mean is dominated by jitter.
_MIN_SAMPLES_FOR_VERDICT = 30
_MIN_DURATION_SECONDS_FOR_VERDICT = 60.0


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _coerce_float(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _coerce_int(v: Any) -> int | None:
    if v is None:
        return None
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def _cv(values: list[float]) -> float | None:
    """Coefficient of variation = stdev / |mean|. None when mean=0."""
    if len(values) < 2:
        return None
    mean = sum(values) / len(values)
    if mean == 0.0:
        return None
    var = sum((v - mean) ** 2 for v in values) / len(values)
    stdev = math.sqrt(var)
    return stdev / abs(mean)


def _last_samples(rows: list[dict[str, Any]], n: int) -> list[dict[str, Any]]:
    """Last n rows by rel_seconds (assumes already sorted)."""
    if not rows:
        return []
    return rows[-n:]


def _process_rows_for_pid(
    process_rows: list[dict[str, Any]],
    pid: int,
) -> list[dict[str, Any]]:
    out = []
    for r in process_rows or []:
        try:
            rid = int(r.get("pid") or 0)
        except (TypeError, ValueError):
            continue
        if rid == pid:
            out.append(r)
    out.sort(key=lambda r: _coerce_float(r.get("rel_seconds")) or 0.0)
    return out


# ---------------------------------------------------------------------------
# Rule 1: run-cluster detection
# ---------------------------------------------------------------------------

def detect_run_clusters(loaded: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cluster runs that share a memory-leak signature.

    For each run, we read `findings.leaks.memory[*]` (already produced
    by the per-run leak detector). Two runs cluster when they:
    - leaked the same process name
    - have leak slopes within ±5 % CV of each other
    - have end-state RSS within ±10 % of each other

    The output finding lists the cluster members + slope CV so the
    analyst can see "4 of 6 runs share a 1716/1764/1781/1761 KB/s
    MotoDB leak — slope CV 1.5 %."
    """
    findings: list[dict[str, Any]] = []
    if len(loaded) < 2:
        return findings

    # Map (process_name) -> list of (run_id, slope_bps, end_rss_bytes)
    by_name: dict[str, list[tuple[str, float, int]]] = {}
    for r in loaded:
        f = r.get("findings") or {}
        leaks = (f.get("leaks") or {}).get("memory") or []
        run_id = (r.get("manifest") or {}).get("run_id") or "?"
        for leak in leaks:
            name = leak.get("name") or "?"
            slope = _coerce_float(
                leak.get("slope_bytes_per_second")
                or leak.get("slope_bps")
                or leak.get("slope")
            )
            end_rss = _coerce_int(
                leak.get("end_rss_bytes")
                or leak.get("last_rss_bytes")
                or leak.get("max_rss_bytes")
            )
            if slope is None or slope <= 0:
                continue
            by_name.setdefault(name.lower(), []).append(
                (run_id, slope, end_rss or 0),
            )

    for name_lower, members in by_name.items():
        if len(members) < 2:
            continue
        slopes = [s for _, s, _ in members]
        cv = _cv(slopes)
        if cv is None or cv > _CLUSTER_SLOPE_CV_MAX:
            continue
        # All members are clustered. Severity high if 50%+ of runs
        # are in the cluster — that's a deterministic reproduction.
        cluster_share = len(members) / len(loaded)
        severity = "high" if cluster_share >= 0.5 else "medium"
        rss_values = [r for _, _, r in members if r > 0]
        rss_min = min(rss_values) if rss_values else 0
        rss_max = max(rss_values) if rss_values else 0
        slope_min = min(slopes)
        slope_max = max(slopes)
        # Use the casing from the first leak row instead of lowering.
        display_name = members[0][0] and name_lower
        # Try to recover original casing from any one of the runs.
        for r in loaded:
            for leak in (
                ((r.get("findings") or {}).get("leaks") or {}).get("memory") or []
            ):
                if (leak.get("name") or "").lower() == name_lower:
                    display_name = leak.get("name") or display_name
                    break
        slope_kbps_min = slope_min / 1024.0
        slope_kbps_max = slope_max / 1024.0
        findings.append({
            "severity": severity,
            "confidence": "high",  # tight clustering = strong evidence
            "category": "same_host_cluster",
            "kind": "run_cluster_leak_signature",
            "run_id": members[0][0],
            "peer_id": members[-1][0],
            "hypothesis": (
                f"{len(members)} of {len(loaded)} runs share a memory-leak "
                f"signature on `{display_name}`. Slope coefficient of "
                f"variation across the cluster is {cv * 100:.1f} % — the "
                f"same bug is reproducing deterministically."
            ),
            "evidence": [
                f"cluster members: {', '.join(rid for rid, _, _ in members)}",
                f"leak slope range: {slope_kbps_min:.1f} – "
                f"{slope_kbps_max:.1f} KB/s (CV {cv * 100:.1f} %)",
                f"end-state RSS range: {rss_min // (1024 * 1024)} – "
                f"{rss_max // (1024 * 1024)} MB",
            ],
            "recommendation": (
                f"Treat `{display_name}` as the prime suspect. Pair this "
                f"finding with the v3-priority-4 handle-type breakdown and "
                f"v3-priority-5 native-vs-managed diff to verify whether "
                f"it's a COM RCW, a native handle store, or a managed "
                f"retained-roots leak."
            ),
            "affected_runs": [rid for rid, _, _ in members],
        })

    return findings


# ---------------------------------------------------------------------------
# Rule 2: regime-change detection
# ---------------------------------------------------------------------------

def detect_regime_changes(loaded: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect process-count discontinuities for the same process name.

    Example from the GPLT3923 corpus: MotoDB.exe goes from 1 PID
    (single-worker) to 68 / 114 PIDs (worker pool). Every other
    metric shifts in lockstep. Should fire one finding per name
    that crosses the threshold.
    """
    findings: list[dict[str, Any]] = []
    if len(loaded) < 2:
        return findings

    # Per-run unique-PID counts per process name.
    counts_per_run: dict[str, dict[str, int]] = {}
    for r in loaded:
        run_id = (r.get("manifest") or {}).get("run_id") or "?"
        rd = r.get("rd")
        rows = getattr(rd, "process_rows", None) or []
        pids_by_name: dict[str, set[int]] = {}
        for row in rows:
            name = (row.get("name") or "").lower()
            try:
                pid = int(row.get("pid") or 0)
            except (TypeError, ValueError):
                continue
            if not name or pid <= 0:
                continue
            pids_by_name.setdefault(name, set()).add(pid)
        counts_per_run[run_id] = {n: len(pids) for n, pids in pids_by_name.items()}

    # Pivot to name -> [counts across runs].
    all_names: set[str] = set()
    for r in counts_per_run.values():
        all_names.update(r.keys())

    for name in all_names:
        counts = [counts_per_run[rid].get(name, 0) for rid in counts_per_run]
        nonzero = [c for c in counts if c > 0]
        if len(nonzero) < 2:
            continue
        ratio = max(nonzero) / max(min(nonzero), 1)
        if ratio < _REGIME_CHANGE_RATIO:
            continue
        # Pretty-print: capture original casing.
        display_name = name
        for r in loaded:
            rd = r.get("rd")
            for row in getattr(rd, "process_rows", None) or []:
                if (row.get("name") or "").lower() == name:
                    display_name = row.get("name") or name
                    break
            if display_name != name:
                break
        per_run = ", ".join(
            f"{rid}={counts_per_run[rid].get(name, 0)}"
            for rid in counts_per_run
        )
        findings.append({
            "severity": "medium",
            "confidence": "high",
            "category": "same_host_cluster",
            "kind": "process_regime_change",
            "run_id": next(iter(counts_per_run.keys())),
            "peer_id": None,
            "hypothesis": (
                f"`{display_name}` process count varies by {ratio:.0f}× "
                f"across runs ({min(nonzero)} → {max(nonzero)}). "
                f"This is a regime change (worker-pool resize or app "
                f"reconfig), not jitter — interpret cross-run metrics "
                f"on this process accordingly."
            ),
            "evidence": [
                f"per-run counts: {per_run}",
                f"min nonzero: {min(nonzero)}, max: {max(nonzero)}, "
                f"ratio: {ratio:.0f}×",
            ],
            "recommendation": (
                "Identify the configuration delta that produced the "
                "regime change before drawing performance conclusions."
            ),
        })

    return findings


# ---------------------------------------------------------------------------
# Rule 3: deterministic-deadlock signature
# ---------------------------------------------------------------------------

def _linear_regression_r2(
    times: list[float], values: list[float],
) -> tuple[float, float]:
    """Return (slope_per_second, R²). Slope is bytes per second when
    values are RSS bytes; R² is the coefficient of determination."""
    n = len(times)
    if n < 2:
        return 0.0, 0.0
    mean_x = sum(times) / n
    mean_y = sum(values) / n
    num = sum((times[i] - mean_x) * (values[i] - mean_y) for i in range(n))
    den_x = sum((times[i] - mean_x) ** 2 for i in range(n))
    if den_x <= 0:
        return 0.0, 0.0
    slope = num / den_x
    intercept = mean_y - slope * mean_x
    ss_tot = sum((values[i] - mean_y) ** 2 for i in range(n))
    if ss_tot <= 0:
        # All values identical — perfect fit if slope==0, else degenerate
        return slope, 1.0 if slope == 0 else 0.0
    ss_res = sum(
        (values[i] - (slope * times[i] + intercept)) ** 2 for i in range(n)
    )
    r2 = max(0.0, 1.0 - ss_res / ss_tot)
    return slope, r2


def _pearson_correlation(xs: list[float], ys: list[float]) -> float:
    """Return Pearson correlation coefficient r. Empty / degenerate
    inputs return 0.0."""
    n = len(xs)
    if n < 2 or n != len(ys):
        return 0.0
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = sum((xs[i] - mean_x) * (ys[i] - mean_y) for i in range(n))
    den_x = math.sqrt(sum((xs[i] - mean_x) ** 2 for i in range(n)))
    den_y = math.sqrt(sum((ys[i] - mean_y) ** 2 for i in range(n)))
    if den_x <= 0 or den_y <= 0:
        return 0.0
    return num / (den_x * den_y)


def _has_deadlock_signature(
    prows: list[dict[str, Any]],
) -> tuple[bool, dict[str, Any]]:
    """v1.3.0 B.1: full sequence detector. Returns (matched, details)
    where details surfaces the four windows + correlation when matched.

    Sequence:
      1. Growth phase: RSS regression over a contiguous window
         ≥ 180 s with R² ≥ 0.85 and slope ≥ 50 KB/s.
      2. Plateau phase: ≥ 120 s immediately following growth with
         |slope| < 10 KB/s and RSS within 5 % of growth-phase max.
      3. CPU-zero phase: CPU < 1 % for ≥ 300 s contiguously WITHIN
         the plateau or immediately following it.
      4. Handle correlation: Pearson r > 0.7 between RSS and handles
         during the growth phase.
    """
    if len(prows) < 30:  # need at least ~30 samples for the math to mean anything
        return False, {}
    rels = [_coerce_float(p.get("rel_seconds")) or 0.0 for p in prows]
    rss = [_coerce_int(p.get("rss_bytes")) or 0 for p in prows]
    handles = [_coerce_int(p.get("num_handles")) or 0 for p in prows]
    cpus = [_coerce_float(p.get("cpu_pct")) or 0.0 for p in prows]

    # Step 1: find the growth phase. We scan candidate windows:
    # the LONGEST contiguous window starting at index 0 whose RSS
    # regression has slope ≥ threshold and R² ≥ threshold AND length
    # ≥ 180 s. We try shrinking from the end.
    best_growth: tuple[int, int, float, float, int] | None = None  # (start, end_excl, slope, r2, rss_max)
    n = len(prows)
    for end_excl in range(n, 0, -1):
        if rels[end_excl - 1] - rels[0] < _DEADLOCK_GROWTH_MIN_SECONDS:
            break
        slope, r2 = _linear_regression_r2(rels[:end_excl], [float(v) for v in rss[:end_excl]])
        if r2 >= _DEADLOCK_GROWTH_MIN_R2 and slope >= _DEADLOCK_GROWTH_MIN_SLOPE_BPS:
            best_growth = (0, end_excl, slope, r2, max(rss[:end_excl]))
            break
    if best_growth is None:
        return False, {}

    # Step 2: plateau phase starts at growth_end_excl, extends as long
    # as |slope| < threshold and RSS stays within 5 % of growth max.
    g_start, g_end, g_slope, g_r2, g_rss_max = best_growth
    plateau_end_excl = g_end
    for i in range(g_end, n):
        if abs(rss[i] - g_rss_max) > _DEADLOCK_PLATEAU_RSS_TOLERANCE * g_rss_max:
            break
        plateau_end_excl = i + 1
    if plateau_end_excl <= g_end:
        return False, {}
    plateau_len_s = rels[plateau_end_excl - 1] - rels[g_end]
    if plateau_len_s < _DEADLOCK_PLATEAU_MIN_SECONDS:
        return False, {}
    plateau_slope, _ = _linear_regression_r2(
        rels[g_end:plateau_end_excl],
        [float(v) for v in rss[g_end:plateau_end_excl]],
    )
    if abs(plateau_slope) >= _DEADLOCK_PLATEAU_MAX_SLOPE_BPS:
        return False, {}

    # Step 3: CPU-zero phase. Look for a contiguous run of ≥ 300 s
    # within or immediately following the plateau where every CPU
    # sample is < 1 %.
    cpu_zero_start: int | None = None
    cpu_zero_len_s = 0.0
    for i in range(g_end, n):
        if cpus[i] < _DEADLOCK_CPU_ZERO_PCT:
            if cpu_zero_start is None:
                cpu_zero_start = i
        else:
            if cpu_zero_start is not None:
                length = rels[i - 1] - rels[cpu_zero_start]
                if length >= _DEADLOCK_CPU_ZERO_MIN_SECONDS and length > cpu_zero_len_s:
                    cpu_zero_len_s = length
                cpu_zero_start = None
    if cpu_zero_start is not None:
        length = rels[n - 1] - rels[cpu_zero_start]
        if length >= _DEADLOCK_CPU_ZERO_MIN_SECONDS and length > cpu_zero_len_s:
            cpu_zero_len_s = length
    if cpu_zero_len_s < _DEADLOCK_CPU_ZERO_MIN_SECONDS:
        return False, {}

    # Step 4: handle correlation during growth phase.
    if any(h > 0 for h in handles[g_start:g_end]):
        corr = _pearson_correlation(
            [float(v) for v in rss[g_start:g_end]],
            [float(v) for v in handles[g_start:g_end]],
        )
        if corr < _DEADLOCK_HANDLE_CORR_MIN:
            return False, {"failed_step": "handle_correlation", "corr": corr}
    else:
        corr = None  # no handle data — proceed without this gate

    return True, {
        "growth_seconds": round(rels[g_end - 1] - rels[g_start], 1),
        "growth_slope_bps": round(g_slope, 1),
        "growth_r2": round(g_r2, 3),
        "plateau_seconds": round(plateau_len_s, 1),
        "plateau_slope_bps": round(plateau_slope, 1),
        "cpu_zero_seconds": round(cpu_zero_len_s, 1),
        "max_rss_bytes": int(g_rss_max),
        "handle_corr": round(corr, 3) if corr is not None else None,
    }


def detect_deterministic_deadlocks(
    loaded: list[dict[str, Any]],
    *,
    excludes: frozenset[str] | None = None,
) -> list[dict[str, Any]]:
    """Detect deadlocks that reproduce across runs.

    v1.3.0 B.1: tightened to require the full growth → plateau →
    CPU-zero → handle-correlation sequence (see _has_deadlock_signature
    above). Default-excludes a curated list of OS / browser / dev-tool
    processes whose normal idle behaviour matches the loose v1.2
    signature. The cross-run finding fires when ≥ 2 unique runs match
    the full signature on the same process name.

    Counting fix: dedup by `run_id` (a single run with two leaking
    PIDs of the same name is counted ONCE). The "12 of 6" report
    from v1.2 can never appear.
    """
    findings: list[dict[str, Any]] = []
    if len(loaded) < 2:
        return findings
    excl = excludes if excludes is not None else _DEADLOCK_DEFAULT_EXCLUDES

    # Per-process-name: which run_ids matched the signature?
    signatures: dict[str, set[str]] = {}  # name_lower -> {run_id, ...}
    details: dict[tuple[str, str], dict[str, Any]] = {}
    for r in loaded:
        run_id = (r.get("manifest") or {}).get("run_id") or "?"
        rd = r.get("rd")
        rows = getattr(rd, "process_rows", None) or []
        # Group by (pid, name)
        by_pid: dict[int, list[dict[str, Any]]] = {}
        names: dict[int, str] = {}
        for row in rows:
            try:
                pid = int(row.get("pid") or 0)
            except (TypeError, ValueError):
                continue
            if pid <= 0:
                continue
            by_pid.setdefault(pid, []).append(row)
            names[pid] = row.get("name") or "?"
        for pid, prows in by_pid.items():
            name = names.get(pid, "?")
            name_lower = name.lower().strip()
            if name_lower in excl:
                continue
            prows.sort(key=lambda x: _coerce_float(x.get("rel_seconds")) or 0.0)
            matched, info = _has_deadlock_signature(prows)
            if not matched:
                continue
            # v1.3.0 B.1 counting fix: dedup by run_id. Two PIDs of
            # the same name in one run count as ONE match.
            signatures.setdefault(name_lower, set()).add(run_id)
            # Keep the first matched detail per (name, run_id).
            details.setdefault((name_lower, run_id), {
                "pid": pid,
                "name": name,
                **info,
            })

    for name_lower, run_id_set in signatures.items():
        # v1.3.0 B.1 counting fix: number of UNIQUE runs that matched.
        # Cap at len(loaded) so the report can never claim "12 of 6".
        unique_runs = sorted(run_id_set)
        match_count = min(len(unique_runs), len(loaded))
        if match_count < 2:
            # Single-run match doesn't count as a deterministic
            # cross-run deadlock (the v1.3 plan classifies it `medium`
            # severity but not actionable as a fleet pattern).
            continue
        # Severity calibration per the v1.3 plan:
        #   match in ≥ 50 % of runs → high
        #   match in ≥ 2 runs but < 50 % → medium
        share = match_count / len(loaded)
        severity = "high" if share >= 0.5 else "medium"

        display_name = next(
            d["name"] for (n, _), d in details.items() if n == name_lower
        )
        rss_mb = [
            details[(name_lower, rid)]["max_rss_bytes"] // (1024 * 1024)
            for rid in unique_runs
        ]
        # Aggregate the per-run timing windows so the report can show
        # the analyst the signature evidence directly.
        avg_growth_s = sum(
            details[(name_lower, rid)]["growth_seconds"] for rid in unique_runs
        ) / match_count
        avg_plateau_s = sum(
            details[(name_lower, rid)]["plateau_seconds"] for rid in unique_runs
        ) / match_count
        avg_cpu_zero_s = sum(
            details[(name_lower, rid)]["cpu_zero_seconds"] for rid in unique_runs
        ) / match_count

        findings.append({
            "severity": severity,
            "confidence": "high",  # full-sequence detector → high confidence
            "category": "same_host_cluster",
            "kind": "deterministic_deadlock",
            "run_id": unique_runs[0],
            "peer_id": unique_runs[-1] if match_count > 1 else None,
            "hypothesis": (
                f"`{display_name}` shows a deterministic-deadlock "
                f"signature in {match_count} of {len(loaded)} runs: "
                f"linear RSS growth → plateau → CPU → 0 — work stopped, "
                f"resources never released."
            ),
            "evidence": [
                f"affected runs ({match_count}): {', '.join(unique_runs)}",
                f"end-state RSS (MB): {', '.join(str(m) for m in rss_mb)}",
                f"avg growth phase: {avg_growth_s:.0f} s",
                f"avg plateau phase: {avg_plateau_s:.0f} s",
                f"avg CPU-zero phase: {avg_cpu_zero_s:.0f} s",
            ],
            "recommendation": (
                "Compare the time-to-deadlock across the listed runs. "
                "If they're within 1 % CPU-time of each other, the "
                "trigger is workload-deterministic — capture an ETW "
                "trace at that timestamp on the next reproduction."
            ),
            "affected_runs": unique_runs,
        })

    return findings


# ---------------------------------------------------------------------------
# Rule 4: cross-run invariants
# ---------------------------------------------------------------------------

def detect_cross_run_invariants(
    loaded: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Surface metrics that are constant across all runs.

    Example: every run shows `network_score = 0.0` → the network is
    likely blocked at a policy level (e.g. ICMP filtered by a Zscaler
    /firewall), not a per-run network issue. Surface as a finding so
    the analyst doesn't chase per-run network anomalies that won't
    resolve.
    """
    findings: list[dict[str, Any]] = []
    if len(loaded) < 2:
        return findings

    # Network score = 0 across all runs.
    net_scores = [
        _coerce_float((r.get("scores") or {}).get("network_impact"))
        if not isinstance((r.get("scores") or {}).get("network_impact"), dict)
        else _coerce_float(
            ((r.get("scores") or {}).get("network_impact") or {}).get("score")
        )
        for r in loaded
    ]
    nonnull = [s for s in net_scores if s is not None]
    if len(nonnull) == len(loaded) and all(s == 0.0 for s in nonnull):
        findings.append({
            "severity": "medium",
            "confidence": "medium",
            "category": "same_host_invariant",
            "kind": "constant_network_zero",
            "run_id": (loaded[0].get("manifest") or {}).get("run_id"),
            "peer_id": None,
            "hypothesis": (
                "Network impact score is 0.0 across every run on "
                "this host — network probes returning no usable "
                "data. Often indicates a policy-level block "
                "(ICMP filtered upstream, SSL-inspecting proxy, "
                "firewall) rather than a per-run network issue."
            ),
            "evidence": [
                f"all {len(loaded)} runs report network_score = 0.0",
                "individual network anomalies will not resolve "
                "until the upstream policy is checked.",
            ],
            "recommendation": (
                "Verify ICMP egress from this host with `ping 8.8.8.8` "
                "outside SysSpecter. If blocked, treat network-impact "
                "scores as not informative on this fleet segment."
            ),
        })

    # GPU adapter idle drain: power > 0 with utilisation = 0.
    # Looks at scores.gpu_analysis if present.
    gpu_idle_drain_runs = []
    for r in loaded:
        f = r.get("findings") or {}
        gpu = f.get("gpu_analysis") or {}
        if not isinstance(gpu, dict) or not gpu.get("enabled"):
            continue
        adapters = gpu.get("adapters") or []
        for a in adapters:
            avg_util = _coerce_float(a.get("avg_utilization_pct")) or 0.0
            avg_power = _coerce_float(a.get("avg_power_w")) or 0.0
            if avg_util < 1.0 and avg_power > 5.0:
                gpu_idle_drain_runs.append(
                    (r.get("manifest") or {}).get("run_id"),
                )
                break
    if len(gpu_idle_drain_runs) == len(loaded) and len(loaded) >= 2:
        findings.append({
            "severity": "low",
            "confidence": "medium",
            "category": "same_host_invariant",
            "kind": "constant_gpu_idle_drain",
            "run_id": (loaded[0].get("manifest") or {}).get("run_id"),
            "peer_id": None,
            "hypothesis": (
                "GPU adapter idle drain on every run: average power "
                "draw above 5 W with average utilisation below 1 %. "
                "Likely a driver / power-state issue that doesn't "
                "follow workload."
            ),
            "evidence": [
                f"affected runs: {', '.join(gpu_idle_drain_runs)}",
            ],
            "recommendation": (
                "Check the GPU driver version + power-state policy "
                "(NVIDIA: prefer max performance / adaptive; AMD: "
                "check Radeon Software). Re-capture after the change."
            ),
        })

    return findings


# ---------------------------------------------------------------------------
# Rule 5: top-N process consistency
# ---------------------------------------------------------------------------

def detect_top_n_consistency(
    loaded: list[dict[str, Any]],
    *,
    metric: str = "cpu",
    top_n: int = 5,
) -> list[dict[str, Any]]:
    """Processes appearing in the top-N consumers across ≥ 50 % of runs.

    The aggregate offenders list is per-run; this rule lifts the
    cross-run regularity into a finding.
    """
    findings: list[dict[str, Any]] = []
    if len(loaded) < 2:
        return findings

    counter: Counter[str] = Counter()
    casing: dict[str, str] = {}
    for r in loaded:
        f = r.get("findings") or {}
        offenders = f.get("offenders") or {}
        bucket = offenders.get(metric) or offenders.get(f"top_{metric}") or []
        if isinstance(bucket, dict):
            bucket = bucket.get("rows") or bucket.get("entries") or []
        for entry in bucket[:top_n]:
            name = (entry.get("name") if isinstance(entry, dict)
                    else None) or "?"
            if not name or name == "?":
                continue
            n_lower = name.lower()
            counter[n_lower] += 1
            casing.setdefault(n_lower, name)

    threshold = max(2, math.ceil(len(loaded) * _CONSISTENCY_THRESHOLD))
    for name_lower, count in counter.most_common(20):
        if count < threshold:
            break
        findings.append({
            "severity": "low",
            "confidence": "medium",
            "category": "same_host_consistency",
            "kind": f"top_{metric}_consistency",
            "run_id": (loaded[0].get("manifest") or {}).get("run_id"),
            "peer_id": None,
            "hypothesis": (
                f"`{casing.get(name_lower, name_lower)}` is in the "
                f"top-{top_n} {metric} consumers in {count} of "
                f"{len(loaded)} runs. A consistent baseline cost on "
                f"this host."
            ),
            "evidence": [
                f"runs where it ranks top-{top_n}: {count}/{len(loaded)}",
                f"metric: {metric}",
            ],
            "recommendation": (
                f"Treat `{casing.get(name_lower, name_lower)}` as a "
                f"baseline-cost contributor when interpreting cross-"
                f"run deltas; per-run anomalies on this process are "
                f"less likely to be the root cause."
            ),
        })

    return findings


# ---------------------------------------------------------------------------
# Rule 6: exclusion gates
# ---------------------------------------------------------------------------

def detect_excluded_runs(
    loaded: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Flag runs that should not appear in `best_*` rankings.

    Causes:
    - 0 samples (sampler died at startup or the empty-run case)
    - sampler died early (cadence broken so badly that only a few
      samples were captured before the run ended)
    - run length below the verdict threshold

    Findings are low-severity but high-confidence — a 0-sample run
    objectively cannot be compared.
    """
    findings: list[dict[str, Any]] = []
    if not loaded:
        return findings

    for r in loaded:
        m = r.get("manifest") or {}
        rd = r.get("rd")
        run_id = m.get("run_id") or "?"
        sample_count = len(getattr(rd, "system_rows", None) or [])
        duration = _coerce_float(m.get("duration_actual_seconds")) or 0.0
        cq = m.get("cadence_quality") or {}
        health = cq.get("cadence_health")
        reasons: list[str] = []
        if sample_count == 0:
            reasons.append("zero system samples captured")
        elif sample_count < _MIN_SAMPLES_FOR_VERDICT:
            reasons.append(
                f"only {sample_count} samples (need >= "
                f"{_MIN_SAMPLES_FOR_VERDICT})"
            )
        if duration > 0 and duration < _MIN_DURATION_SECONDS_FOR_VERDICT:
            reasons.append(
                f"duration {duration:.0f} s below verdict floor "
                f"({_MIN_DURATION_SECONDS_FOR_VERDICT:.0f} s)"
            )
        if health == "broken":
            reasons.append(
                f"cadence broken (median gap "
                f"{cq.get('median_gap_seconds')} s vs nominal "
                f"{cq.get('nominal_interval_seconds')} s)"
            )
        if not reasons:
            continue
        findings.append({
            "severity": "low",
            "confidence": "high",
            "category": "same_host_exclusion",
            "kind": "not_comparable",
            "run_id": run_id,
            "peer_id": None,
            "hypothesis": (
                f"`{run_id}` should be excluded from cross-run "
                f"`best_*` rankings: " + "; ".join(reasons) + "."
            ),
            "evidence": reasons,
            "recommendation": (
                "Re-capture this run before drawing conclusions, or "
                "limit comparison to event-count metrics (anomalies, "
                "leaks) which don't depend on sample density."
            ),
        })
    return findings


# ---------------------------------------------------------------------------
# Top-level orchestrator
# ---------------------------------------------------------------------------

def build_same_host_findings(
    loaded: list[dict[str, Any]],
    mode: str,
) -> list[dict[str, Any]]:
    """Run the seven same-host rule families.

    Most rules require `mode == "before_after"`. The exclusion gate
    (rule 6) and cross-run invariants (rule 4) are useful in any mode
    so they're allowed everywhere.
    """
    out: list[dict[str, Any]] = []
    if not loaded:
        return out

    # Always-on rules.
    out.extend(detect_excluded_runs(loaded))
    out.extend(detect_cross_run_invariants(loaded))

    # Same-host-only rules. Comparing across hosts, these don't make
    # sense — a worker pool resize on one host vs another isn't a
    # regime change, it's a config difference.
    if mode == "before_after":
        out.extend(detect_run_clusters(loaded))
        out.extend(detect_regime_changes(loaded))
        out.extend(detect_deterministic_deadlocks(loaded))
        out.extend(detect_top_n_consistency(loaded, metric="cpu"))
        out.extend(detect_top_n_consistency(loaded, metric="memory"))

    return out
