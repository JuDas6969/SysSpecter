"""Capture profiles (Field-review C4).

A *profile* bundles the answer to "what kind of question are you trying
to answer with this run?" into a single named preset. Without it,
operators have to remember which combination of `--mode`, `--duration`,
`--gpu`, `--event-logs`, `--etw`, `--manual-stop`, `--latency-target`
fits each diagnostic case. With it:

    sysspecter monitor --profile leak-hunt
    sysspecter monitor --profile av-overhead
    sysspecter monitor --profile thermal

The same dictionary feeds the Monitor-tab preset dropdown, so the
GUI and CLI never drift apart.

Profile fields are *defaults* — every individual CLI flag still
overrides the profile. ``--profile thermal --duration 60`` runs the
thermal preset for 60 s instead of the default 300 s.

The active profile name is stamped into ``manifest.meta`` as
``capture_profile`` so downstream analyzers can specialise (e.g. an
``av-overhead`` run produces a more detailed security-overhead
section).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Profile:
    """A capture profile = preset answer to "what are we measuring?"."""

    name: str
    description: str
    # Defaults that map onto Config fields. None = use the existing
    # SysSpecter default (don't override).
    mode: str = "support"
    duration_seconds: int | None = None
    interval_seconds: float | None = None
    manual_stop: bool = False
    enable_gpu: bool = False
    enable_event_logs: bool = False
    enable_etw_disk: bool = False
    latency_targets: tuple[str, ...] | None = None
    suggested_meta: dict[str, str] = field(default_factory=dict)


_LOOPBACK_TARGETS = ("127.0.0.1", "8.8.8.8", "1.1.1.1")
_VPN_TARGETS = (
    "127.0.0.1", "8.8.8.8", "1.1.1.1",
    # Operator should add their VPN gateway via --latency-target on top.
)


PROFILES: dict[str, Profile] = {
    "support": Profile(
        name="support",
        description=(
            "Free-running 'my PC is slow' diagnosis. Manual stop; "
            "balanced sampling without Phase 3 overhead. Default."
        ),
        mode="support",
        manual_stop=True,
    ),
    "baseline": Profile(
        name="baseline",
        description=(
            "Idle-noise baseline measurement. 30 minutes, no targets, "
            "Phase 3 off. Compare against later 'support' runs to see "
            "what changed."
        ),
        mode="baseline",
        duration_seconds=30 * 60,
    ),
    "workload": Profile(
        name="workload",
        description=(
            "Measure a specific application. Requires --target-name / "
            "--target-pid / --target-path. 30 minutes default."
        ),
        mode="workload",
        duration_seconds=30 * 60,
    ),
    "leak-hunt": Profile(
        name="leak-hunt",
        description=(
            "Long-running run to surface RSS / handle / thread leaks. "
            "1 hour minimum, all Phase 3 collectors on, event-log "
            "correlation enabled. Pair with --target-name for a "
            "specific suspected-leaker."
        ),
        mode="workload",
        duration_seconds=60 * 60,
        enable_event_logs=True,
        enable_etw_disk=True,
        suggested_meta={"scenario": "leak-hunt"},
    ),
    "av-overhead": Profile(
        name="av-overhead",
        description=(
            "Quantify EDR / AV CPU + I/O overhead. 15 minutes, ETW "
            "disk capture on so per-process I/O attribution catches "
            "scanner reads. Cross-vendor — works for Defender, "
            "CrowdStrike, SentinelOne, Sophos, Cortex XDR."
        ),
        mode="baseline",
        duration_seconds=15 * 60,
        enable_etw_disk=True,
        enable_event_logs=True,
        suggested_meta={"scenario": "av-overhead"},
    ),
    "thermal": Profile(
        name="thermal",
        description=(
            "Thermal / power profile. 5 minutes, GPU metrics on (CPU "
            "RAPL still pending — see ROADMAP H7). Per-core CPU "
            "frequency captured via the new B4 path."
        ),
        mode="workload",
        duration_seconds=5 * 60,
        enable_gpu=True,
        suggested_meta={"scenario": "thermal"},
    ),
    "incident-snapshot": Profile(
        name="incident-snapshot",
        description=(
            "Short, dense capture for a 30-second window around a "
            "user-reported issue. All Phase 3 on. Run AFTER the user "
            "reproduces; the static snapshot still captures the host's "
            "current state."
        ),
        mode="support",
        duration_seconds=30,
        enable_gpu=True,
        enable_event_logs=True,
        enable_etw_disk=True,
        suggested_meta={"scenario": "incident-snapshot"},
    ),
    "vpn-troubleshoot": Profile(
        name="vpn-troubleshoot",
        description=(
            "VPN / network responsiveness. 10 minutes, latency probes "
            "+ event log. Add --latency-target your.vpn.gateway for "
            "the actual SASE/ZTNA endpoint."
        ),
        mode="support",
        duration_seconds=10 * 60,
        enable_event_logs=True,
        latency_targets=_VPN_TARGETS,
        suggested_meta={"scenario": "vpn-troubleshoot"},
    ),
    "security-audit": Profile(
        name="security-audit",
        description=(
            "Static-only audit: 1-minute capture but full static "
            "snapshot (autoruns, scheduled tasks, listening ports, "
            "installed programs, Defender state, BIOS). Tiny CSV "
            "footprint, big static_snapshot.json. Cheap to ship to "
            "compliance."
        ),
        mode="baseline",
        duration_seconds=60,
        enable_event_logs=True,
        suggested_meta={"scenario": "security-audit"},
    ),
}


def get(name: str) -> Profile | None:
    """Return a profile by name, or None if unknown."""
    return PROFILES.get(name)


def names() -> list[str]:
    """Return the list of valid profile names, in the order they should
    appear in CLI / GUI dropdowns."""
    return list(PROFILES.keys())


def describe_all() -> str:
    """Multi-line human-readable summary of every shipped profile.
    Consumed by the CLI ``--list-profiles`` helper and any docs page."""
    lines = []
    for n in names():
        p = PROFILES[n]
        lines.append(f"  {n:<20s} {p.description}")
    return "\n".join(lines)
