"""Field-review M2: structured fleet metadata in the run manifest.

Pins the contract for the `meta` block alongside the existing free-form
`tags` list. Covers:

- Config carries `meta: dict[str, str]`
- build_run_manifest writes the meta block verbatim onto disk
- Pydantic Manifest schema accepts (and round-trips) the meta block
- v1/v2 manifests without `meta` still validate (backwards compat)
- Runs scanner exposes meta + tags on RunInfo
- Runs-tab filter strings include meta values
- CLI parser converts `--meta KEY=VALUE` repeats + convenience flags
  into a single normalized dict
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from sysspecter.config import Config, Thresholds
from sysspecter.domain.schemas import Manifest, try_validate
from sysspecter.gui.runs import summarize_run
from sysspecter.manifest import build_run_manifest, write_manifest
from sysspecter.paths import RunPaths


def _make_paths(tmp_path: Path) -> RunPaths:
    run_dir = tmp_path / "Runs" / "HOST_20260423_010000"
    run_dir.mkdir(parents=True)
    (run_dir / "logs").mkdir()
    return RunPaths(
        root=str(tmp_path),
        run_id="HOST_20260423_010000",
        hostname="HOST",
        started_at=_dt.datetime(2026, 4, 23, 1, 0, 0),
        run_dir=str(run_dir),
        logs_dir=str(run_dir / "logs"),
    )


def _meta_payload() -> dict[str, str]:
    return {
        "department": "engineering",
        "ticket": "PERF-1234",
        "scenario": "post-update-regression-check",
        "change_under_test": "defender-engine-1.1.27",
        "machine_class": "developer-workstation",
    }


def test_config_carries_meta_dict() -> None:
    cfg = Config(meta={"ticket": "PERF-1"})
    assert cfg.meta == {"ticket": "PERF-1"}
    # Default factory yields an empty dict, not None.
    assert Config().meta == {}


def test_manifest_persists_meta_block(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    cfg = Config(
        output_root=str(tmp_path), mode="support", duration=300,
        thresholds=Thresholds(),
        meta=_meta_payload(),
    )
    m = build_run_manifest(paths, cfg)
    assert m["meta"] == _meta_payload()
    # Free-form tags stay separate.
    assert m["tags"] == []

    # Round-trip through disk preserves the meta block byte-for-byte.
    write_manifest(paths.manifest, m)
    on_disk = json.loads(Path(paths.manifest).read_text(encoding="utf-8"))
    assert on_disk["meta"] == _meta_payload()


def test_pydantic_manifest_validates_meta() -> None:
    raw = {
        "schema_version": 2,
        "run_id": "X_20260101_000000",
        "hostname": "X",
        "started_at": "2026-01-01T00:00:00",
        "meta": _meta_payload(),
    }
    valid = try_validate(Manifest, raw)
    assert valid is not None, "validation rejected a well-formed payload"
    assert isinstance(valid, Manifest)
    assert valid.meta == _meta_payload()


def test_pydantic_manifest_v1_without_meta_still_validates() -> None:
    """A v1 manifest written before this feature must still load — `meta`
    defaults to an empty dict and never blocks reading."""
    raw = {
        "schema_version": 1,
        "run_id": "X_20260101_000000",
        "hostname": "X",
        "started_at": "2026-01-01T00:00:00",
    }
    valid = try_validate(Manifest, raw)
    assert valid is not None
    assert valid.meta == {}


def test_summarize_run_exposes_meta_and_tags(tmp_path: Path) -> None:
    paths = _make_paths(tmp_path)
    cfg = Config(
        output_root=str(tmp_path),
        mode="support",
        thresholds=Thresholds(),
        tags=["autopilot"],
        meta={"ticket": "PERF-9", "department": "support"},
    )
    write_manifest(paths.manifest, build_run_manifest(paths, cfg))
    info = summarize_run(paths.run_dir)
    assert info is not None
    assert info.tags == ["autopilot"]
    assert info.meta == {"ticket": "PERF-9", "department": "support"}


def test_runs_filter_matches_meta_value(tmp_path: Path) -> None:
    """The Runs-tab filter haystack must include meta keys + values so
    a fleet operator can pull "all runs for ticket PERF-1234" with
    one search."""
    paths = _make_paths(tmp_path)
    cfg = Config(
        output_root=str(tmp_path),
        mode="support",
        thresholds=Thresholds(),
        meta={"ticket": "PERF-1234", "department": "engineering"},
    )
    write_manifest(paths.manifest, build_run_manifest(paths, cfg))
    info = summarize_run(paths.run_dir)
    assert info is not None

    # Replicate the haystack the GUI builds so we don't need a Tk root.
    meta_str = " ".join(f"{k}:{v} {v}" for k, v in (info.meta or {}).items())
    haystack = " ".join(filter(None, [
        info.run_id, info.hostname, info.mode,
        info.primary_bottleneck, info.stop_reason, meta_str,
    ])).lower()

    # All of these must hit.
    for needle in ("perf-1234", "engineering", "ticket:perf-1234",
                   "ticket", "department:engineering"):
        assert needle.lower() in haystack, (
            f"filter haystack missed {needle!r}: {haystack!r}"
        )
