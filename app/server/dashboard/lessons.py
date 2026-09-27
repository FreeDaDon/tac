"""Read agent/lessons/*.md: YAML frontmatter (name, description, tags) + markdown body."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

MAX_BODY_CHARS = 20_000
MAX_LESSONS = 500


def _tags(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(t).strip() for t in value if str(t).strip()]
    if isinstance(value, str):
        return [t.strip() for t in value.strip("[]").split(",") if t.strip()]
    return []


def _fallback_frontmatter(block: str) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    for line in block.splitlines():
        if ":" in line and not line.startswith((" ", "-")):
            key, _, value = line.partition(":")
            meta[key.strip()] = value.strip().strip("'\"")
    return meta


def parse_lesson(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---"):
        return {}, text
    parts = text.split("\n---", 1)
    if len(parts) != 2:
        return {}, text
    block = parts[0][3:]
    body = parts[1].lstrip("-").lstrip("\n")
    try:
        meta = yaml.safe_load(block)
    except yaml.YAMLError:
        meta = None
    if not isinstance(meta, dict):
        meta = _fallback_frontmatter(block)
    return meta, body


def list_lessons(root: Path) -> list[dict[str, Any]]:
    base = root / "agent" / "lessons"
    if not base.is_dir():
        return []
    resolved_base = base.resolve()
    out: list[dict[str, Any]] = []
    for path in sorted(base.glob("*.md"))[:MAX_LESSONS]:
        try:
            real = path.resolve()
            if not real.is_relative_to(resolved_base) or not real.is_file():
                continue  # symlink escaping the lessons dir: never read it
            text = real.read_text(encoding="utf-8", errors="replace")
            mtime = datetime.fromtimestamp(real.stat().st_mtime, UTC).isoformat(timespec="seconds")
        except OSError:
            continue
        meta, body = parse_lesson(text)
        out.append(
            {
                "file": path.name,
                "name": str(meta.get("name") or path.stem),
                "description": str(meta.get("description") or ""),
                "tags": _tags(meta.get("tags")),
                "body": body[:MAX_BODY_CHARS],
                "updated": mtime,
            }
        )
    out.sort(key=lambda lesson: lesson["updated"], reverse=True)
    return out
