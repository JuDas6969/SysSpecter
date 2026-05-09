"""v3-priority-4 (H1): per-(pid, type) handle-leak analyzer tests.

The aggregate handle-leak rule already exists; this layer adds the
missing per-type breakdown that makes COM RCW diagnosis possible.
Pinned cases:

- Linear growth in File handles over a 30-min run -> finding fires
  with severity proportional to slope.
- Section + Event growing together on the same PID -> RCW signature
  finding fires.
- A run with no handles_rows (legacy / locked-down host) returns the
  empty result skeleton without raising.
- Noisy types (Job, Driver) are excluded by design.
- Below-threshold drift doesn't fire.
"""

from __future__ import annotations

from sysspecter.analyzer.handle_types import detect_handle_type_leaks


def _samples(
    pid: int,
    type_name: str,
    *,
    name: str = "leaky.exe",
    start: int = 100,
    growth_per_minute: float = 0.0,
    n: int = 30,
    interval_seconds: float = 60.0,
) -> list[dict]:
    """Generate a series of handle-count samples with a controlled slope."""
    out = []
    for i in range(n):
        rel = i * interval_seconds
        count = start + int((growth_per_minute / 60.0) * rel)
        out.append({
            "rel_seconds": rel,
            "pid": pid,
            "name": name,
            "type_name": type_name,
            "count": count,
            "timestamp": 1000.0 + rel,
        })
    return out


# --- empty / back-compat ------------------------------------------

def test_empty_input_returns_empty_skeleton() -> None:
    out = detect_handle_type_leaks([])
    assert out == {
        "samples_seen": 0,
        "per_type_findings": [],
        "rcw_signature_candidates": [],
    }


def test_none_input_returns_empty_skeleton() -> None:
    """Defensive: legacy run loaders may pass None instead of []."""
    out = detect_handle_type_leaks(None)
    assert out["per_type_findings"] == []


# --- threshold + classification ----------------------------------

def test_low_growth_below_threshold_does_not_fire() -> None:
    """3 handles/minute is normal jitter — must not fire."""
    rows = _samples(pid=100, type_name="File", growth_per_minute=3.0)
    out = detect_handle_type_leaks(rows)
    assert out["per_type_findings"] == []


def test_medium_growth_fires_medium_severity() -> None:
    """50 handles/minute crosses the medium threshold."""
    rows = _samples(pid=100, type_name="File", growth_per_minute=50.0)
    out = detect_handle_type_leaks(rows)
    findings = out["per_type_findings"]
    assert len(findings) == 1
    f = findings[0]
    assert f["pid"] == 100
    assert f["type_name"] == "File"
    assert f["severity"] == "medium"
    assert 40.0 <= f["slope_per_minute"] <= 60.0


def test_high_growth_fires_high_severity() -> None:
    """500 handles/minute is a definite leak."""
    rows = _samples(pid=100, type_name="Section", growth_per_minute=500.0)
    out = detect_handle_type_leaks(rows)
    findings = out["per_type_findings"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["confidence"] == "high"


def test_too_few_samples_does_not_fire() -> None:
    """A run with only 2 snapshots can't support a slope claim."""
    rows = _samples(pid=100, type_name="File", growth_per_minute=500.0, n=2)
    out = detect_handle_type_leaks(rows)
    assert out["per_type_findings"] == []


# --- noisy types excluded ----------------------------------------

def test_job_type_excluded_even_when_growing() -> None:
    """Job handles grow naturally in container workloads — ignore."""
    rows = _samples(pid=100, type_name="Job", growth_per_minute=500.0)
    out = detect_handle_type_leaks(rows)
    assert out["per_type_findings"] == []


def test_driver_type_excluded() -> None:
    rows = _samples(pid=4, type_name="Driver", growth_per_minute=500.0)
    out = detect_handle_type_leaks(rows)
    assert out["per_type_findings"] == []


# --- RCW signature ------------------------------------------------

def test_rcw_signature_fires_when_section_and_event_grow_together() -> None:
    """The classic COM Runtime-Callable-Wrapper leak: Section AND
    Event handles climbing in tandem on the same PID."""
    section_rows = _samples(
        pid=200, type_name="Section", name="motodb.exe",
        growth_per_minute=200.0,
    )
    event_rows = _samples(
        pid=200, type_name="Event", name="motodb.exe",
        growth_per_minute=180.0,
    )
    out = detect_handle_type_leaks(section_rows + event_rows)
    rcw = out["rcw_signature_candidates"]
    assert len(rcw) == 1
    candidate = rcw[0]
    assert candidate["pid"] == 200
    assert candidate["name"] == "motodb.exe"
    assert candidate["section_slope_per_minute"] >= 150
    assert candidate["event_slope_per_minute"] >= 150


def test_rcw_signature_does_not_fire_when_only_section_grows() -> None:
    """Section alone isn't enough — RCW leaks correlate Section + Event."""
    rows = _samples(pid=200, type_name="Section", growth_per_minute=500.0)
    out = detect_handle_type_leaks(rows)
    assert out["rcw_signature_candidates"] == []


def test_rcw_signature_does_not_fire_when_event_below_medium() -> None:
    """If Event growth is below the medium threshold, no RCW claim."""
    rows = _samples(pid=200, type_name="Section", growth_per_minute=500.0) + \
           _samples(pid=200, type_name="Event", growth_per_minute=10.0)
    out = detect_handle_type_leaks(rows)
    assert out["rcw_signature_candidates"] == []


# --- ordering + multi-pid ----------------------------------------

def test_findings_sorted_by_severity_then_slope() -> None:
    rows = (
        _samples(pid=100, type_name="File", name="a", growth_per_minute=50.0)
        + _samples(pid=200, type_name="File", name="b", growth_per_minute=300.0)
        + _samples(pid=300, type_name="File", name="c", growth_per_minute=10.0)
    )
    findings = detect_handle_type_leaks(rows)["per_type_findings"]
    severities = [f["severity"] for f in findings]
    # Order: high (PID 200) > medium (PID 100) > low (PID 300)
    assert severities == ["high", "medium", "low"]


def test_samples_seen_counts_unique_timestamps() -> None:
    """If we have 3 PIDs each with 5 snapshots at the same 5 rel_seconds,
    samples_seen should be 5 (count of unique snapshot times) — not 15."""
    rows = (
        _samples(pid=100, type_name="File", growth_per_minute=50.0, n=5)
        + _samples(pid=200, type_name="File", growth_per_minute=50.0, n=5)
        + _samples(pid=300, type_name="File", growth_per_minute=50.0, n=5)
    )
    out = detect_handle_type_leaks(rows)
    assert out["samples_seen"] == 5
