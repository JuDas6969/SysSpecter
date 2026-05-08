"""Machine-class baseline profiles (Field-review C3).

Different machine classes have radically different "normal" baselines:

    A 15% idle CPU is fine on a developer laptop.
    A 15% idle CPU is *suspicious* on a kiosk.

This module ships per-class baseline profiles and a detector that
surfaces "outside class baseline" findings — distinct from the
absolute Thresholds (which catch acute problems on any class). A
healthy machine that happens to be in the wrong class still
produces a baseline-deviation finding, which is exactly the
operator's first hint that the machine isn't doing what its class
contract implies.

Class is read from `manifest.meta.machine_class` (the M2 structured
metadata field, set via `monitor --machine-class developer-workstation`
or via `--profile X` whose suggested_meta carries it).

Output schema (one entry per detected deviation):

    {
        "machine_class": "kiosk",
        "metric": "cpu_idle_pct",
        "expected_range": [90, 100],
        "actual": 75,
        "severity": "medium",
        "description": "Kiosk class expects idle CPU 90–100 %, observed 75 %"
    }
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .stats import mean

# Severity tiers (order matters in the report; higher first).
_SEVERITY_HIGH = "high"
_SEVERITY_MEDIUM = "medium"
_SEVERITY_LOW = "low"


@dataclass(frozen=True)
class BaselineProfile:
    """Per-class baseline: what each metric SHOULD look like during a
    run on this kind of machine. Ranges are inclusive (lo, hi). A
    metric value outside its range produces a finding.

    `severity_outside_high` controls how loudly the finding gets
    reported when the metric is well past the bound; the inner
    `cpu_idle_pct_warn_band` etc. fields define the soft warning
    ring around the hard bound. Defaults are tuned for "should rarely
    fire on a healthy machine of this class".
    """
    name: str
    description: str

    # Mean-CPU bounds are easier to reason about than idle bounds —
    # the operator says "this kiosk shouldn't be using > 15 % CPU"
    # rather than "this kiosk should be > 85 % idle".
    cpu_used_pct_lo: float = 0.0      # below this is "weirdly idle"
    cpu_used_pct_hi: float = 100.0    # above this is "off-class busy"

    # Memory usage band. Lower = unused machine, higher = leak suspect.
    mem_used_pct_lo: float = 0.0
    mem_used_pct_hi: float = 100.0

    # Whether the machine is expected to have meaningful network
    # activity. Kiosks / engineering boxes often don't; terminal
    # servers always do.
    expects_network_activity: bool = False
    network_min_bytes_per_sec: float = 0.0


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

_PROFILES: dict[str, BaselineProfile] = {
    "developer-workstation": BaselineProfile(
        name="developer-workstation",
        description=(
            "Domain-joined dev laptop / desktop. Compilers, IDEs, "
            "browsers, container runtimes — moderate-to-high CPU + "
            "RAM, persistent network. Idle 5–25 % CPU is normal."
        ),
        cpu_used_pct_lo=2.0,    # truly-zero CPU on a dev laptop = stuck
        cpu_used_pct_hi=70.0,   # > 70 % sustained = build / heavy task
        mem_used_pct_lo=20.0,
        mem_used_pct_hi=85.0,
        expects_network_activity=True,
        network_min_bytes_per_sec=200.0,
    ),
    "engineering-workstation": BaselineProfile(
        name="engineering-workstation",
        description=(
            "CAD / simulation / CFD workstation. High RAM utilisation "
            "is the norm; CPU bursts to 100 % during runs are expected. "
            "Often offline or on isolated networks."
        ),
        cpu_used_pct_lo=0.0,
        cpu_used_pct_hi=95.0,
        mem_used_pct_lo=20.0,
        mem_used_pct_hi=95.0,
        expects_network_activity=False,
    ),
    "general-knowledge-worker": BaselineProfile(
        name="general-knowledge-worker",
        description=(
            "Office / Outlook / Teams desktop. Low-to-moderate CPU + "
            "RAM, persistent but small network footprint."
        ),
        cpu_used_pct_lo=1.0,
        cpu_used_pct_hi=50.0,
        mem_used_pct_lo=15.0,
        mem_used_pct_hi=80.0,
        expects_network_activity=True,
        network_min_bytes_per_sec=100.0,
    ),
    "kiosk": BaselineProfile(
        name="kiosk",
        description=(
            "Single-purpose unattended box (info display, dispatch "
            "screen, signage). Should idle close to zero. Any sustained "
            "CPU > 15 % is suspicious; meaningful network is suspicious."
        ),
        cpu_used_pct_lo=0.0,
        cpu_used_pct_hi=15.0,
        mem_used_pct_lo=0.0,
        mem_used_pct_hi=60.0,
        expects_network_activity=False,
    ),
    "terminal-server": BaselineProfile(
        name="terminal-server",
        description=(
            "Multi-user RDP / Citrix host. Sustained moderate CPU + "
            "high RAM is normal; high network throughput is the whole "
            "point. Idle network or zero CPU on a populated TS = "
            "users disconnected unexpectedly."
        ),
        cpu_used_pct_lo=5.0,
        cpu_used_pct_hi=85.0,
        mem_used_pct_lo=30.0,
        mem_used_pct_hi=90.0,
        expects_network_activity=True,
        network_min_bytes_per_sec=2_000.0,
    ),
    "factory-floor": BaselineProfile(
        name="factory-floor",
        description=(
            "PLC HMI / line-monitor / shop-floor box. Steady very-low "
            "CPU, small constant network heartbeat to a controller. "
            "Sustained CPU > 30 % means something other than the HMI is "
            "running on it."
        ),
        cpu_used_pct_lo=0.0,
        cpu_used_pct_hi=30.0,
        mem_used_pct_lo=0.0,
        mem_used_pct_hi=70.0,
        expects_network_activity=True,
        network_min_bytes_per_sec=50.0,
    ),
    "default": BaselineProfile(
        name="default",
        description=(
            "Generic fallback for runs that did not declare a "
            "machine class. No class-baseline findings will fire — "
            "this is the back-compat profile."
        ),
        # All ranges left at 0..100 → never trips.
    ),
}


def for_class(machine_class: str | None) -> BaselineProfile:
    """Return the baseline profile for a given class name, falling
    back to the all-permissive `default` profile when unknown or
    None. Class-name lookup is case-insensitive and tolerates the
    common 'developer' shorthand for 'developer-workstation'."""
    if not machine_class or not isinstance(machine_class, str):
        return _PROFILES["default"]
    key = machine_class.strip().lower()
    if key in _PROFILES:
        return _PROFILES[key]
    # Tolerate shorthands.
    aliases = {
        "developer": "developer-workstation",
        "engineer": "engineering-workstation",
        "engineering": "engineering-workstation",
        "office": "general-knowledge-worker",
        "knowledge-worker": "general-knowledge-worker",
        "ts": "terminal-server",
        "rdp": "terminal-server",
        "citrix": "terminal-server",
        "plc": "factory-floor",
        "shop-floor": "factory-floor",
    }
    return _PROFILES.get(aliases.get(key, ""), _PROFILES["default"])


def known_classes() -> list[str]:
    """Names of all shipped machine-class profiles, in display order."""
    return [k for k in _PROFILES if k != "default"]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


def _aggregate_metric(
    rows: list[dict[str, Any]], key: str,
) -> float | None:
    """Mean of `key` across all rows that have it; None if no rows."""
    values: list[float] = []
    for r in rows:
        v = r.get(key)
        if v is None:
            continue
        try:
            values.append(float(v))
        except (TypeError, ValueError):
            continue
    if not values:
        return None
    return mean(values)


def _severity_for_distance(value: float, lo: float, hi: float) -> str:
    """How far outside the band? > 30 % off either bound = high,
    > 10 % off = medium, anything else = low."""
    if value < lo:
        gap = lo - value
        ref = max(lo, 1.0)
    else:
        gap = value - hi
        ref = max(hi, 1.0)
    pct_off = gap / ref
    if pct_off >= 0.30:
        return _SEVERITY_HIGH
    if pct_off >= 0.10:
        return _SEVERITY_MEDIUM
    return _SEVERITY_LOW


def detect_baseline_deviations(
    system_rows: list[dict[str, Any]],
    machine_class: str | None,
) -> list[dict[str, Any]]:
    """Compare run-aggregate system metrics against the machine's
    class baseline. Returns one finding per deviation; empty list
    when the run is in-class or when no class was declared."""
    profile = for_class(machine_class)
    if profile.name == "default":
        # No declared class → no baseline deviations to report.
        # This preserves back-compat for runs without --machine-class.
        return []
    if not system_rows:
        return []

    out: list[dict[str, Any]] = []

    cpu_used = _aggregate_metric(system_rows, "cpu_total_pct")
    if cpu_used is not None:
        if cpu_used < profile.cpu_used_pct_lo or cpu_used > profile.cpu_used_pct_hi:
            sev = _severity_for_distance(
                cpu_used, profile.cpu_used_pct_lo, profile.cpu_used_pct_hi,
            )
            direction = "below" if cpu_used < profile.cpu_used_pct_lo else "above"
            out.append({
                "machine_class": profile.name,
                "metric": "cpu_total_pct_mean",
                "expected_range": [
                    profile.cpu_used_pct_lo,
                    profile.cpu_used_pct_hi,
                ],
                "actual": round(cpu_used, 1),
                "severity": sev,
                "direction": direction,
                "description": (
                    f"{profile.name} class expects mean CPU use "
                    f"{profile.cpu_used_pct_lo:.0f}–"
                    f"{profile.cpu_used_pct_hi:.0f} %, observed "
                    f"{cpu_used:.1f} % ({direction} band)."
                ),
            })

    mem_used = _aggregate_metric(system_rows, "mem_percent")
    if mem_used is not None:
        if mem_used < profile.mem_used_pct_lo or mem_used > profile.mem_used_pct_hi:
            sev = _severity_for_distance(
                mem_used, profile.mem_used_pct_lo, profile.mem_used_pct_hi,
            )
            direction = "below" if mem_used < profile.mem_used_pct_lo else "above"
            out.append({
                "machine_class": profile.name,
                "metric": "mem_percent_mean",
                "expected_range": [
                    profile.mem_used_pct_lo,
                    profile.mem_used_pct_hi,
                ],
                "actual": round(mem_used, 1),
                "severity": sev,
                "direction": direction,
                "description": (
                    f"{profile.name} class expects mean RAM use "
                    f"{profile.mem_used_pct_lo:.0f}–"
                    f"{profile.mem_used_pct_hi:.0f} %, observed "
                    f"{mem_used:.1f} % ({direction} band)."
                ),
            })

    if profile.expects_network_activity:
        net_recv = _aggregate_metric(system_rows, "net_recv_bytes_per_sec") or 0.0
        net_sent = _aggregate_metric(system_rows, "net_sent_bytes_per_sec") or 0.0
        net_total = net_recv + net_sent
        if net_total < profile.network_min_bytes_per_sec:
            out.append({
                "machine_class": profile.name,
                "metric": "net_total_bytes_per_sec_mean",
                "expected_range": [profile.network_min_bytes_per_sec, None],
                "actual": round(net_total, 1),
                "severity": _SEVERITY_HIGH,
                "direction": "below",
                "description": (
                    f"{profile.name} class expects sustained network "
                    f"≥ {profile.network_min_bytes_per_sec:.0f} B/s, "
                    f"observed {net_total:.1f} B/s — possible "
                    "disconnected client / unattached node."
                ),
            })

    # Sort by severity descending so the report leads with the loudest.
    severity_rank = {_SEVERITY_HIGH: 3, _SEVERITY_MEDIUM: 2, _SEVERITY_LOW: 1}
    out.sort(key=lambda f: severity_rank.get(f["severity"], 0), reverse=True)
    return out
