"""Tests for sysspecter.settings: round-trip save/load and MRU behaviour."""

from __future__ import annotations

from pathlib import Path

from sysspecter.settings import UserPrefs, load_prefs, push_output_root, save_prefs


def test_defaults_are_sensible() -> None:
    p = UserPrefs()
    assert p.default_mode == "support"
    assert p.default_duration_seconds == 1800
    assert p.default_manual_stop is True
    assert "8.8.8.8" in p.default_latency_targets
    assert p.theme in {"light", "dark"}
    assert p.output_root_mru == []


def test_load_missing_file_returns_defaults(tmp_path: Path) -> None:
    prefs = load_prefs(str(tmp_path / "absent.toml"))
    assert prefs == UserPrefs()


def test_roundtrip_preserves_all_fields(tmp_path: Path) -> None:
    path = str(tmp_path / "config.toml")
    original = UserPrefs(
        output_root_mru=["C:\\Temp\\A", "C:\\Temp\\B"],
        default_mode="workload",
        default_duration_seconds=600,
        default_manual_stop=False,
        default_latency_targets=["1.1.1.1"],
        default_phase3_gpu=True,
        default_phase3_event_logs=True,
        default_phase3_etw_disk=False,
        theme="dark",
        show_admin_banner=False,
        check_updates_on_start=False,
    )
    save_prefs(original, path)
    loaded = load_prefs(path)
    assert loaded == original


def test_save_creates_directory(tmp_path: Path) -> None:
    nested = tmp_path / "dir_that_does_not_exist"
    path = str(nested / "config.toml")
    save_prefs(UserPrefs(default_mode="baseline"), path)
    assert (nested / "config.toml").exists()


def test_string_with_quotes_and_backslashes_roundtrips(tmp_path: Path) -> None:
    path = str(tmp_path / "cfg.toml")
    p = UserPrefs(output_root_mru=[r"C:\Users\max\My \"Data\""])
    save_prefs(p, path)
    loaded = load_prefs(path)
    assert loaded.output_root_mru == p.output_root_mru


def test_push_output_root_moves_existing_to_front() -> None:
    p = UserPrefs(output_root_mru=[r"C:\A", r"C:\B", r"C:\C"])
    out = push_output_root(p, r"C:\B")
    assert out.output_root_mru[0].endswith("B")
    # Duplicates are removed, not kept
    assert len([x for x in out.output_root_mru
                if x.endswith("B")]) == 1


def test_push_output_root_caps_at_max_mru() -> None:
    p = UserPrefs(output_root_mru=[rf"C:\Dir{i}" for i in range(10)])
    out = push_output_root(p, r"C:\New")
    assert len(out.output_root_mru) <= 5
    assert out.output_root_mru[0].endswith("New")


def test_corrupt_toml_returns_defaults(tmp_path: Path) -> None:
    path = tmp_path / "broken.toml"
    path.write_text("this is not valid toml = = =", encoding="utf-8")
    prefs = load_prefs(str(path))
    assert prefs == UserPrefs()


def test_unknown_keys_do_not_break_load(tmp_path: Path) -> None:
    path = tmp_path / "future.toml"
    path.write_text(
        "default_mode = \"support\"\n"
        "future_feature = true\n",
        encoding="utf-8",
    )
    # If we decide to be strict we would drop unknown keys; currently
    # unknown keys cause TypeError and we fall back to defaults.
    prefs = load_prefs(str(path))
    assert isinstance(prefs, UserPrefs)
