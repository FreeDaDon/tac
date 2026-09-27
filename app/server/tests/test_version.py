from __future__ import annotations

from pathlib import Path

from dashboard.version import load_version


def test_load_version_normal(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "9.9.9"\n')
    assert load_version(tmp_path) == {"version": "9.9.9"}


def test_load_version_missing_file(tmp_path: Path) -> None:
    assert load_version(tmp_path) == {"version": "unknown"}


def test_load_version_missing_key(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
    assert load_version(tmp_path) == {"version": "unknown"}


def test_load_version_malformed_toml(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("not = [valid toml")
    assert load_version(tmp_path) == {"version": "unknown"}
