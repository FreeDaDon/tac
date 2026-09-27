"""Parse agent/agentic_kpis.md (markdown tables under ## headings) into JSON."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_SEP_RE = re.compile(r"^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")


def _cells(line: str) -> list[str]:
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|"):
        body = body[:-1]
    return [c.strip() for c in body.split("|")]


def parse_tables(text: str) -> dict[str, list[dict[str, str]]]:
    tables: dict[str, list[dict[str, str]]] = {}
    section = "default"
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("#"):
            section = line.lstrip("#").strip() or section
            i += 1
            continue
        if line.strip().startswith("|") and i + 1 < len(lines) and _SEP_RE.match(lines[i + 1].strip()):
            header = _cells(line)
            rows: list[dict[str, str]] = []
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = _cells(lines[i])
                rows.append({h: (cells[j] if j < len(cells) else "") for j, h in enumerate(header)})
                i += 1
            tables.setdefault(section, []).extend(rows)
            continue
        i += 1
    return tables


def _first_number(value: str | None) -> float | None:
    if not value:
        return None
    m = re.search(r"-?\d+(?:\.\d+)?", value)
    return float(m.group()) if m else None


def load_kpis(root: Path) -> dict[str, Any]:
    path = root / "agent" / "agentic_kpis.md"
    if not path.is_file():
        return {"exists": False, "summary": {}, "tables": {}, "highlights": {}}
    tables = parse_tables(path.read_text(encoding="utf-8", errors="replace"))
    summary: dict[str, str] = {}
    for rows in tables.values():
        for row in rows:
            if "Metric" in row and "Value" in row and row["Metric"]:
                summary[row["Metric"]] = row["Value"]
    run_rows = next((rows for rows in tables.values() if rows and "Attempts" in rows[0]), [])
    attempts = [a for a in (_first_number(r.get("Attempts")) for r in run_rows) if a is not None]
    highlights = {
        "current_streak": _first_number(summary.get("Current Streak")),
        "longest_streak": _first_number(summary.get("Longest Streak")),
        "average_presence": _first_number(summary.get("Average Presence")),
        "average_attempts": round(sum(attempts) / len(attempts), 2) if attempts else None,
        "runs_tracked": len(run_rows),
    }
    return {"exists": True, "summary": summary, "tables": tables, "highlights": highlights}
