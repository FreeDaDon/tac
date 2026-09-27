"""Small shared file loaders (JSON / YAML / JSON-lines)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


def load_structured(path: Path) -> Any:
    """Parse a JSON or YAML file (by extension; JSON first for anything else)."""
    text = Path(path).read_text(encoding="utf-8")
    if Path(path).suffix.lower() in {".yml", ".yaml"}:
        return yaml.safe_load(text)
    return json.loads(text)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Parse JSON-lines, skipping blank lines; non-object lines raise ValueError."""
    records: list[dict[str, Any]] = []
    for line_no, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError(f"{path}:{line_no}: expected a JSON object")
        records.append(record)
    return records


def get_field(record: dict[str, Any], dotted: str) -> Any:
    """Look up `a.b.c` as a flat key first, then as a nested path. Missing -> None."""
    if dotted in record:
        return record[dotted]
    current: Any = record
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
