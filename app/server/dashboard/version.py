"""Read project.version from pyproject.toml (read once, cached by the caller)."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any


def load_version(root: Path) -> dict[str, str]:
    path = root / "pyproject.toml"
    try:
        with path.open("rb") as f:
            data: dict[str, Any] = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return {"version": "unknown"}
    project = data.get("project", {})
    version = project.get("version") if isinstance(project, dict) else None
    return {"version": version if isinstance(version, str) and version else "unknown"}
