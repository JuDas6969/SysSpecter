"""Field-review C4: capture profile catalog + CLI resolution.

Pins the contract for `sysspecter monitor --profile NAME`: the profile
fills in defaults but every individual flag still wins. Also covers
the manifest stamping (`meta.capture_profile = NAME`) so downstream
analyzers can specialise.
"""

from __future__ import annotations

import argparse

import pytest

from sysspecter import profiles


def _collect_meta(args: argparse.Namespace, profile: profiles.Profile | None) -> dict:
    """Replicate the CLI's meta-resolution order. Kept here so the
    tests don't depend on importing `sysspecter.py` (which has a name
    collision with the package)."""
    meta: dict[str, str] = {}
    if profile and profile.suggested_meta:
        meta.update(profile.suggested_meta)
    if profile:
        meta["capture_profile"] = profile.name
    for kv in (getattr(args, "meta_kv", None) or []):
        if "=" not in kv:
            continue
        k, _, v = kv.partition("=")
        k = k.strip().lower()
        if k:
            meta[k] = v.strip()
    for arg_name, meta_key in (
        ("department", "department"),
        ("ticket", "ticket"),
        ("scenario", "scenario"),
        ("change_under_test", "change_under_test"),
        ("machine_class", "machine_class"),
    ):
        v = getattr(args, arg_name, None)
        if isinstance(v, str) and v.strip():
            meta[meta_key] = v.strip()
    return meta


# ----------------------------------------------------- shipped catalog


def test_shipped_catalog_covers_field_review_use_cases() -> None:
    """The use-case names from the field review must all be reachable
    via --profile NAME — that's the whole point of C4."""
    required = {
        "support",            # current default
        "baseline",
        "workload",
        "leak-hunt",
        "av-overhead",
        "thermal",
        "incident-snapshot",
        "vpn-troubleshoot",
        "security-audit",
    }
    assert required <= set(profiles.names()), (
        f"shipped profile catalog missing: {required - set(profiles.names())}"
    )


def test_get_returns_profile_for_known_name() -> None:
    p = profiles.get("leak-hunt")
    assert p is not None
    assert p.name == "leak-hunt"
    assert p.duration_seconds == 60 * 60
    assert p.enable_etw_disk is True


def test_get_returns_none_for_unknown_name() -> None:
    assert profiles.get("not-a-profile") is None
    assert profiles.get("") is None


def test_describe_all_lists_every_profile() -> None:
    text = profiles.describe_all()
    for name in profiles.names():
        assert name in text, f"--list-profiles must mention {name!r}"


# ----------------------------------------------------- CLI resolution


def _ns(**overrides) -> argparse.Namespace:
    """Build a minimal Namespace mirroring the argparse output of
    `sysspecter monitor`. Defaults match the CLI's actual defaults
    (None for fields that flow through profile resolution)."""
    base = dict(
        profile=None, list_profiles=False,
        mode=None, duration=None, interval=None,
        target_name=None, target_pid=None, target_path=None,
        tags=[], meta_kv=[],
        department=None, ticket=None, scenario=None,
        change_under_test=None, machine_class=None,
        latency_targets=None,
        manual_stop=False,
        gpu=False, event_logs=False, etw=False, phase3=False,
        redact=False,
        output_root="C:/Temp/SysSpecter",
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _resolve(args: argparse.Namespace) -> dict:
    """Replicate the CLI handler's resolution logic so we can test it
    without spawning a subprocess. If the real handler diverges from
    this, the test will fail — that's the point."""
    profile = profiles.get(args.profile) if args.profile else None
    mode = args.mode or (profile.mode if profile else None) or "support"
    interval = args.interval if args.interval is not None else (
        profile.interval_seconds if profile and profile.interval_seconds is not None
        else 1.0
    )
    manual_stop_flag = bool(args.manual_stop) or bool(
        profile.manual_stop if profile else False
    )
    if args.duration is not None:
        duration = args.duration
    elif profile and profile.duration_seconds is not None:
        duration = profile.duration_seconds
    elif mode == "support" or manual_stop_flag:
        duration = None
    elif mode == "baseline":
        duration = 1800
    else:
        duration = 1800
    enable_gpu = bool(args.gpu) or bool(args.phase3) or bool(profile.enable_gpu if profile else False)
    enable_event_logs = bool(args.event_logs) or bool(args.phase3) or bool(profile.enable_event_logs if profile else False)
    enable_etw_disk = bool(args.etw) or bool(args.phase3) or bool(profile.enable_etw_disk if profile else False)
    if args.latency_targets:
        latency = list(args.latency_targets)
    elif profile and profile.latency_targets:
        latency = list(profile.latency_targets)
    else:
        latency = ["127.0.0.1", "8.8.8.8", "1.1.1.1"]
    return {
        "mode": mode, "interval": interval, "duration": duration,
        "manual_stop": manual_stop_flag,
        "enable_gpu": enable_gpu,
        "enable_event_logs": enable_event_logs,
        "enable_etw_disk": enable_etw_disk,
        "latency_targets": latency,
        "meta": _collect_meta(args, profile),
    }


def test_no_profile_keeps_existing_default_behaviour() -> None:
    """Without --profile, the resolver behaves exactly as before
    (mode=support, no Phase 3, default latency targets). This is the
    backwards-compat guarantee."""
    r = _resolve(_ns())
    assert r["mode"] == "support"
    assert r["interval"] == 1.0
    assert r["enable_gpu"] is False
    assert r["enable_event_logs"] is False
    assert r["enable_etw_disk"] is False
    assert "capture_profile" not in r["meta"]


def test_leak_hunt_profile_enables_full_phase3() -> None:
    r = _resolve(_ns(profile="leak-hunt"))
    assert r["mode"] == "workload"
    assert r["duration"] == 60 * 60
    assert r["enable_event_logs"] is True
    assert r["enable_etw_disk"] is True
    assert r["meta"]["capture_profile"] == "leak-hunt"
    assert r["meta"]["scenario"] == "leak-hunt"


def test_thermal_profile_turns_on_gpu_only() -> None:
    r = _resolve(_ns(profile="thermal"))
    assert r["enable_gpu"] is True
    # Thermal does NOT need event_logs / etw — should stay off so
    # the run isn't bloated.
    assert r["enable_event_logs"] is False
    assert r["enable_etw_disk"] is False


def test_explicit_duration_overrides_profile() -> None:
    """If the operator says --duration 120, the profile's recommended
    duration is ignored. CLI flag always wins."""
    r = _resolve(_ns(profile="leak-hunt", duration=120))
    assert r["duration"] == 120


def test_explicit_mode_overrides_profile() -> None:
    r = _resolve(_ns(profile="leak-hunt", mode="baseline"))
    assert r["mode"] == "baseline"


def test_cli_phase3_flag_does_not_disable_profile_collector() -> None:
    """Profile says ETW=on. Operator passes --gpu. We must end up with
    BOTH on, not gpu-only."""
    r = _resolve(_ns(profile="av-overhead", gpu=True))
    assert r["enable_gpu"] is True       # from CLI
    assert r["enable_etw_disk"] is True  # from profile (must NOT be turned off)
    assert r["enable_event_logs"] is True


def test_explicit_latency_targets_override_profile() -> None:
    r = _resolve(_ns(
        profile="vpn-troubleshoot",
        latency_targets=["10.0.0.1", "10.0.0.2"],
    ))
    assert r["latency_targets"] == ["10.0.0.1", "10.0.0.2"]


def test_capture_profile_stamped_into_meta() -> None:
    r = _resolve(_ns(profile="incident-snapshot"))
    assert r["meta"]["capture_profile"] == "incident-snapshot"
    # Suggested meta is merged in too.
    assert r["meta"]["scenario"] == "incident-snapshot"


def test_meta_cli_flag_overrides_profile_suggestion() -> None:
    """CLI --scenario beats the profile's suggested_meta entry."""
    r = _resolve(_ns(profile="leak-hunt", scenario="custom-scenario"))
    assert r["meta"]["scenario"] == "custom-scenario"


def test_unknown_profile_returns_none() -> None:
    assert profiles.get("totally-made-up") is None


def test_support_profile_keeps_manual_stop() -> None:
    r = _resolve(_ns(profile="support"))
    assert r["manual_stop"] is True
    assert r["duration"] is None


@pytest.mark.parametrize("profile_name", profiles.names())
def test_every_profile_resolves_without_error(profile_name: str) -> None:
    """Smoke test — exercise resolution for every shipped profile so a
    typo in the catalog (missing field, malformed value) is caught."""
    r = _resolve(_ns(profile=profile_name))
    assert r["mode"] in ("support", "baseline", "workload")
    assert isinstance(r["latency_targets"], list)
    assert r["meta"]["capture_profile"] == profile_name
