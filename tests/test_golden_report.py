"""Golden-file regression test for the HTML report.

Renders `tests/data/reference_run/` through `build_report()` and
compares against the committed `tests/golden/final_report.html`.

When the template intentionally changes, rebuild the golden:

    python tests/data/build_reference_run.py

And review the diff before committing.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
REFERENCE_RUN = REPO / "tests" / "data" / "reference_run"
GOLDEN = REPO / "tests" / "golden" / "final_report.html"


# Strip ISO-style timestamps + anything that can drift across renderers
# (the <title> may carry the run_id which is stable, so we keep it).
_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
_DURATION_RE = re.compile(r"\d+\.\d+\s*s\b")


def _normalise(html: str) -> str:
    html = _TIMESTAMP_RE.sub("<ts>", html)
    html = _DURATION_RE.sub("<dur>", html)
    return html


@pytest.fixture
def rendered_html(tmp_path: Path) -> str:
    # Copy the checked-in fixture so we render into a writable scratch dir
    # (build_report rewrites findings.json / scores.json).
    dst = tmp_path / "ref"
    shutil.copytree(REFERENCE_RUN, dst)
    (dst / "logs").mkdir(exist_ok=True)
    from sysspecter.reporter.html_report import build_report
    build_report(str(dst))
    return (dst / "final_report.html").read_text(encoding="utf-8")


def test_golden_matches(rendered_html: str) -> None:
    golden = GOLDEN.read_text(encoding="utf-8")
    if _normalise(rendered_html) == _normalise(golden):
        return
    # Produce a readable diff when the test fails
    import difflib
    diff = "\n".join(difflib.unified_diff(
        _normalise(golden).splitlines(),
        _normalise(rendered_html).splitlines(),
        fromfile="golden/final_report.html",
        tofile="rendered",
        lineterm="",
        n=3,
    )[:200])
    pytest.fail(
        "Rendered report differs from golden fixture.\n"
        "If this is intentional, rebuild the golden:\n"
        "    python tests/data/build_reference_run.py\n\n"
        f"First diffs (normalised):\n{diff}"
    )


def test_golden_has_expected_anchors() -> None:
    golden = GOLDEN.read_text(encoding="utf-8")
    for needle in (
        "SysSpecter v1.0.0",
        "REFHOST",
        "Reference CPU",
        "brand-bar",
        "Primary bottleneck",
    ):
        assert needle in golden, f"missing {needle!r} in golden HTML"


def test_reference_run_has_deterministic_timeline() -> None:
    # If someone accidentally rewrites the fixture with non-deterministic
    # data, golden diffs become useless.
    csv_path = REFERENCE_RUN / "timeline_system.csv"
    lines = csv_path.read_text(encoding="utf-8").splitlines()
    # Header plus 300 rows
    assert len(lines) == 301
    assert lines[0].startswith("timestamp,rel_seconds")
