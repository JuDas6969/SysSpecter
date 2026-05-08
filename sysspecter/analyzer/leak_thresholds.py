"""Stack-aware leak-detection thresholds (Field-review C1).

The default leak heuristic in `analyzer/leaks.py` (linear RSS slope +
R² + monotonic-nondecreasing ratio) was tuned for Matlab / .NET
desktop apps. On a customer running JVM / Chromium / .NET-server-GC
workloads, the same heuristic fires on EVERY long-running process —
not because they leak, but because they're SUPPOSED to grow:

- **JVM** apps grow toward `-Xmx` then plateau. By design.
- **.NET server-GC** processes have infrequent Gen 2 collections, so
  RSS rises in saw-tooth fashion.
- **Chromium-family** processes (browsers, Electron) habitually grow
  until the renderer GC kicks in; site instances aren't bounded.
- **Node.js** has a 1.4 GB V8 heap default; ramping toward it is
  expected.
- **CPython** with reference cycles reaches a steady state that
  isn't perfectly flat.

This module ships per-stack threshold *profiles* that the leak
detector applies before flagging a candidate. Same input → same
classification regardless of vendor; the customer who runs
CrowdStrike + Java + Chrome doesn't get a useless report full of
false positives.

Stack tags come from the C2 process catalog (
`sysspecter.process_catalog`). A process whose stack is unknown or
None falls back to the `native` profile — same as the legacy behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StackLeakProfile:
    """Per-stack tunables applied on top of the global Thresholds.

    All multipliers are >= 1.0 to TIGHTEN the bar (i.e. require more
    growth before flagging). A value of 1.0 = unchanged from the
    global default.
    """
    stack: str
    description: str

    # Multiplier on the slope-suspicious threshold. JVM / Chromium need
    # a much steeper slope before we even start considering a leak.
    slope_multiplier: float = 1.0

    # Absolute floor on RSS growth (MB) before considering a candidate.
    # Chromium starts at 200 MB+; JVM at 500 MB+. A 20 MB growth from
    # there is rounding noise.
    rss_min_growth_mb: float = 20.0

    # Relative growth ratio floor (e.g. 0.5 = 50%). Browsers/JVM grow
    # significantly during normal operation; require the trend to be
    # PROPORTIONALLY large before flagging.
    rss_min_growth_ratio: float = 0.0

    # Minimum monotonic-nondecreasing ratio. Saw-tooth GC patterns
    # need a much higher mono before they qualify as "growing".
    mono_min: float = 0.55

    # Minimum R² (linear fit quality). Saw-tooth runtimes tend to
    # have lower R² even when they ARE leaking, so we relax this.
    r2_min: float = 0.15

    # If True, a final-chunk plateau does NOT downgrade the finding.
    # JVM heaps reach -Xmx and STAY there; that's fine, not a leak,
    # so the plateau-fraction guard would mis-fire.
    plateau_is_normal: bool = False


# ---------- per-stack profiles --------------------------------------------

_PROFILES: dict[str, StackLeakProfile] = {
    "native": StackLeakProfile(
        stack="native",
        description=(
            "Default profile for unmanaged code (C/C++/Rust desktop apps, "
            "system services without a managed runtime). Tight thresholds — "
            "any sustained growth is suspicious."
        ),
    ),
    "chromium": StackLeakProfile(
        stack="chromium",
        description=(
            "Chrome / Edge / Brave / Opera / Vivaldi and Electron-based "
            "apps (VS Code, Slack, Teams, Discord, Cursor). Per-renderer "
            "GC cycles produce saw-tooth growth; per-tab caches accumulate. "
            "Empirical bar: only fire above ~200 KB/s sustained per-tab."
        ),
        slope_multiplier=4.0,
        rss_min_growth_mb=200.0,
        rss_min_growth_ratio=0.30,
        mono_min=0.65,
        r2_min=0.20,
    ),
    "gecko": StackLeakProfile(
        stack="gecko",
        description="Firefox / SeaMonkey / Thunderbird. Similar GC profile to Chromium.",
        slope_multiplier=4.0,
        rss_min_growth_mb=200.0,
        rss_min_growth_ratio=0.30,
        mono_min=0.65,
        r2_min=0.20,
    ),
    "jvm": StackLeakProfile(
        stack="jvm",
        description=(
            "OpenJDK / Oracle JVM / IntelliJ-platform IDEs. Heap commits "
            "grow toward -Xmx then plateau by design — that plateau is "
            "NOT a downgrade signal. Only flag if RSS grows ~50% past "
            "its post-warmup baseline."
        ),
        slope_multiplier=4.0,
        rss_min_growth_mb=500.0,
        rss_min_growth_ratio=0.50,
        mono_min=0.65,
        r2_min=0.20,
        plateau_is_normal=True,
    ),
    "dotnet": StackLeakProfile(
        stack="dotnet",
        description=(
            "Microsoft .NET runtimes (CLR / CoreCLR). Server-GC defers "
            "Gen 2 collections, which produces saw-tooth RSS until the "
            "GC catches up. Workstation-GC is closer to native but "
            "still less monotonic than C++."
        ),
        slope_multiplier=2.0,
        rss_min_growth_mb=100.0,
        rss_min_growth_ratio=0.20,
        mono_min=0.60,
        plateau_is_normal=True,
    ),
    "cpython": StackLeakProfile(
        stack="cpython",
        description=(
            "CPython. Reference cycles + small RSS baseline (50–200 MB) "
            "make even small absolute growth meaningful. Slightly "
            "MORE sensitive than native."
        ),
        slope_multiplier=0.7,
        rss_min_growth_mb=50.0,
    ),
    "nodejs": StackLeakProfile(
        stack="nodejs",
        description=(
            "Node.js / V8. Heap default 1.4 GB ceiling; ramping toward "
            "it is expected. Plateau at ceiling is normal."
        ),
        slope_multiplier=2.5,
        rss_min_growth_mb=150.0,
        rss_min_growth_ratio=0.30,
        mono_min=0.60,
        plateau_is_normal=True,
    ),
    "go": StackLeakProfile(
        stack="go",
        description="Go runtime — keeps freed memory available for re-use, "
                    "leading to a noisy plateau that isn't a leak.",
        slope_multiplier=2.0,
        rss_min_growth_mb=100.0,
        plateau_is_normal=True,
    ),
    "system": StackLeakProfile(
        stack="system",
        description=(
            "Windows kernel-side / system-service processes (svchost, "
            "lsass, dwm, …). These rarely leak in user-visible ways; a "
            "high bar prevents the report drowning in benign drift."
        ),
        slope_multiplier=5.0,
        rss_min_growth_mb=200.0,
        rss_min_growth_ratio=0.30,
    ),
}


_DEFAULT = _PROFILES["native"]


def for_stack(stack: str | None) -> StackLeakProfile:
    """Return the leak profile for a given stack tag, falling back to
    the `native` defaults when the stack is unknown or None."""
    if not stack:
        return _DEFAULT
    return _PROFILES.get(stack.lower(), _DEFAULT)


def known_stacks() -> list[str]:
    """The set of stacks the catalog can tag a process with. Used by
    tests to assert catalog values resolve to a real profile."""
    return list(_PROFILES.keys())
