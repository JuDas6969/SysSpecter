"""Field-review C3: machine-class baseline detection.

Pins the contract that a 15 % CPU is normal on a developer
laptop, suspicious on a kiosk. Tests cover:

- Each shipped class has a sensible profile (CPU + mem ranges
  defined; fixed-purpose classes mark expects_network_activity)
- A run inside its class baseline produces NO deviation finding
- A run that's outside the class band produces a finding with
  severity scaled by how far out of band
- Class lookup is case-insensitive and tolerates common shorthands
- Unknown class falls back to `default` which never trips
- A run without a declared class (manifest.meta.machine_class missing)
  doesn't produce baseline findings — back-compat
- Network-deficiency triggers high-severity for terminal-server
  (the field-review's "users disconnected unexpectedly" case)
"""

from __future__ import annotations

import pytest

from sysspecter.analyzer.machine_class_baselines import (
    detect_baseline_deviations,
    for_class,
    known_classes,
)

# ----------------------------------------------------- catalog


def test_shipped_classes_cover_field_review_examples() -> None:
    """The five classes the field review explicitly named must all
    be reachable via for_class()."""
    required = {
        "developer-workstation",
        "engineering-workstation",
        "general-knowledge-worker",
        "kiosk",
        "terminal-server",
    }
    assert required <= set(known_classes())


def test_for_class_unknown_returns_default() -> None:
    """Unknown / None / empty → the all-permissive default profile."""
    for bad in (None, "", "made-up-class"):
        p = for_class(bad)
        assert p.name == "default"


def test_class_lookup_case_insensitive() -> None:
    a = for_class("KIOSK")
    b = for_class("kiosk")
    assert a == b


def test_class_aliases_resolve() -> None:
    """Common shorthand → canonical class. Operators won't always
    type the full machine-class string; aliases reduce friction."""
    cases = (
        ("developer", "developer-workstation"),
        ("engineering", "engineering-workstation"),
        ("ts", "terminal-server"),
        ("citrix", "terminal-server"),
        ("plc", "factory-floor"),
    )
    for alias, canonical in cases:
        assert for_class(alias).name == canonical


def test_kiosk_class_has_low_cpu_ceiling() -> None:
    """A kiosk should refuse to be busy — its baseline must cap
    CPU well below the developer-workstation cap."""
    kiosk = for_class("kiosk")
    dev = for_class("developer-workstation")
    assert kiosk.cpu_used_pct_hi < dev.cpu_used_pct_hi
    assert kiosk.cpu_used_pct_hi <= 20


def test_terminal_server_expects_network() -> None:
    ts = for_class("terminal-server")
    assert ts.expects_network_activity is True
    assert ts.network_min_bytes_per_sec > 0


def test_engineering_workstation_does_not_expect_network() -> None:
    eng = for_class("engineering-workstation")
    assert eng.expects_network_activity is False


# ----------------------------------------------------- detector


def _system_row(rel: float, cpu: float = 5.0, mem: float = 40.0,
                net_recv: float = 0.0, net_sent: float = 0.0) -> dict:
    return {
        "rel_seconds": rel,
        "cpu_total_pct": cpu,
        "mem_percent": mem,
        "net_recv_bytes_per_sec": net_recv,
        "net_sent_bytes_per_sec": net_sent,
    }


def test_no_class_declared_yields_no_findings() -> None:
    """Back-compat: runs without --machine-class don't suddenly
    start producing baseline-deviation findings."""
    rows = [_system_row(t, cpu=80.0) for t in range(60)]
    assert detect_baseline_deviations(rows, None) == []
    assert detect_baseline_deviations(rows, "") == []


def test_unknown_class_falls_back_to_default_no_findings() -> None:
    rows = [_system_row(t, cpu=80.0) for t in range(60)]
    assert detect_baseline_deviations(rows, "made-up") == []


def test_kiosk_in_baseline_produces_no_finding() -> None:
    """Kiosk at 5 % mean CPU, 30 % mem — well inside band."""
    rows = [_system_row(t, cpu=5.0, mem=30.0) for t in range(120)]
    assert detect_baseline_deviations(rows, "kiosk") == []


def test_kiosk_with_high_cpu_produces_finding() -> None:
    """The motivating case: a kiosk averaging 25 % CPU is FAR off
    its 0–15 % band."""
    rows = [_system_row(t, cpu=25.0, mem=40.0) for t in range(120)]
    findings = detect_baseline_deviations(rows, "kiosk")
    cpu_findings = [f for f in findings if "cpu" in f["metric"]]
    assert cpu_findings, "high-CPU kiosk must produce a CPU deviation"
    f = cpu_findings[0]
    assert f["machine_class"] == "kiosk"
    assert f["direction"] == "above"
    assert f["actual"] == pytest.approx(25.0)
    assert f["expected_range"][1] == pytest.approx(15.0)


def test_severity_scales_with_distance_from_band() -> None:
    """A 25 % CPU on a kiosk (10 pp over a 15 % cap) is more than
    a 20 % CPU on the same class. Severity should grow with the
    distance."""
    rows_close = [_system_row(t, cpu=16.0, mem=40.0) for t in range(120)]
    rows_far = [_system_row(t, cpu=50.0, mem=40.0) for t in range(120)]
    close_findings = detect_baseline_deviations(rows_close, "kiosk")
    far_findings = detect_baseline_deviations(rows_far, "kiosk")
    severity_rank = {"low": 1, "medium": 2, "high": 3}
    assert close_findings and far_findings
    assert severity_rank[far_findings[0]["severity"]] > \
           severity_rank[close_findings[0]["severity"]]


def test_developer_with_15pct_cpu_is_normal() -> None:
    """The motivating field-review claim, pinned: 15 % CPU on a
    developer laptop is INSIDE the band (5–70 %), so no finding."""
    rows = [_system_row(t, cpu=15.0, mem=50.0,
                        net_recv=500.0) for t in range(120)]
    findings = detect_baseline_deviations(rows, "developer-workstation")
    assert findings == [], (
        f"15% CPU on a dev laptop must be normal, got {findings}"
    )


def test_terminal_server_with_zero_network_is_high_severity() -> None:
    """A TS where users disconnected — net activity below the
    expected threshold must produce a HIGH-severity finding."""
    rows = [
        _system_row(t, cpu=20.0, mem=50.0, net_recv=0.0, net_sent=0.0)
        for t in range(120)
    ]
    findings = detect_baseline_deviations(rows, "terminal-server")
    net_findings = [f for f in findings if "net" in f["metric"]]
    assert net_findings, "TS with no network must produce a deviation"
    assert net_findings[0]["severity"] == "high"


def test_engineering_does_not_complain_about_network_silence() -> None:
    """Engineering workstations are often offline — the network-
    expectation guard must NOT fire on them."""
    rows = [
        _system_row(t, cpu=40.0, mem=70.0, net_recv=0.0)
        for t in range(120)
    ]
    findings = detect_baseline_deviations(rows, "engineering-workstation")
    net_findings = [f for f in findings if "net" in f["metric"]]
    assert not net_findings


def test_findings_sorted_by_severity_desc() -> None:
    """Reports lead with the loudest deviation, regardless of which
    metric produced it."""
    rows = [
        _system_row(t,
                    cpu=80.0,            # far above kiosk's 0–15 (high)
                    mem=65.0,            # slight bit above 0–60 (low)
                    net_recv=0.0)
        for t in range(120)
    ]
    findings = detect_baseline_deviations(rows, "kiosk")
    severities = [f["severity"] for f in findings]
    severity_rank = {"low": 1, "medium": 2, "high": 3}
    ranked = [severity_rank[s] for s in severities]
    assert ranked == sorted(ranked, reverse=True), (
        f"findings not sorted by severity desc: {severities}"
    )


def test_empty_system_rows_yields_no_findings() -> None:
    assert detect_baseline_deviations([], "kiosk") == []


def test_finding_carries_machine_class_metric_and_actual() -> None:
    rows = [_system_row(t, cpu=99.0, mem=50.0) for t in range(60)]
    findings = detect_baseline_deviations(rows, "kiosk")
    assert findings
    f = findings[0]
    for required_key in ("machine_class", "metric", "expected_range",
                         "actual", "severity", "direction", "description"):
        assert required_key in f, (
            f"finding missing required key {required_key!r}: {f}"
        )
