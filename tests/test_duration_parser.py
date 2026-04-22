"""Unit tests for the GUI duration parser.

The parser feeds the Monitor tab's "Duration" field, so it must cope with
the shapes a human would actually type (German + English, decimal comma,
mixed units) and REJECT obvious junk.
"""

from __future__ import annotations

import pytest

from sysspecter.gui.duration import (
    DurationParseError,
    format_duration,
    parse_duration,
)


@pytest.mark.parametrize(
    ("text", "default_unit", "expected"),
    [
        ("1800", "s", 1800),
        ("30", "min", 1800),
        ("30 min", "s", 1800),
        ("30min", "s", 1800),
        ("1.5h", "s", 5400),
        ("1,5 min", "s", 90),
        ("2 hrs", "s", 7200),
        ("1 day", "s", 86400),
        ("45s", "s", 45),
        ("2h 30min", "s", 9000),
        ("90s", "s", 90),
        ("1 Minute", "s", 60),
        ("1,5 Std", "s", 5400),
        ("2 Tage", "s", 172800),
    ],
)
def test_parse_accepts_common_shapes(text: str, default_unit: str, expected: float) -> None:
    assert parse_duration(text, default_unit=default_unit) == pytest.approx(expected)


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "abc", "5 fortnights", "10 h xyz", "m"],
)
def test_parse_rejects_junk(bad: str) -> None:
    with pytest.raises(DurationParseError):
        parse_duration(bad)


def test_repeated_bare_numbers_sum() -> None:
    # "5 5" is legal: both tokens take the default unit and are summed.
    # Not the typical human shape but predictable and harmless.
    assert parse_duration("5 5", default_unit="s") == pytest.approx(10)


def test_format_round_trips() -> None:
    assert format_duration(0) == "0s"
    assert format_duration(45) == "45s"
    assert format_duration(90) == "1m 30s"
    assert format_duration(3600) == "1h"
    assert format_duration(3661) == "1h 1m 1s"
    assert format_duration(86400) == "1d"
    assert format_duration(90061) == "1d 1h 1m 1s"
