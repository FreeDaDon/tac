"""JSON export of analysis reports."""

from __future__ import annotations

import json
from typing import Any

from core.common import AnalysisReport


def to_dict(reports: list[AnalysisReport]) -> dict[str, Any]:
    return {
        "reports": [r.model_dump(mode="json") | {"max_severity": r.max_severity} for r in reports],
        "total_findings": sum(len(r.findings) for r in reports),
    }


def to_json(reports: list[AnalysisReport], indent: int = 2) -> str:
    return json.dumps(to_dict(reports), indent=indent, sort_keys=True, ensure_ascii=False, default=str)
