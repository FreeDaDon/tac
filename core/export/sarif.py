"""SARIF 2.1.0 export (one run per report) for GitHub code scanning and other SARIF consumers."""

from __future__ import annotations

import json
import re
from typing import Any

from core.common import AnalysisReport, Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
_PATH_LINE = re.compile(r"^(?P<path>[^\s#]+?):(?P<line>\d+)$")


def level_for(severity: str) -> str:
    return LEVELS[severity]


def parse_location(location: str) -> tuple[str, int] | None:
    """`path:line` -> (path, line); anything else (addresses, ARNs, IPs) -> None."""
    m = _PATH_LINE.match(location)
    if not m or int(m.group("line")) < 1:
        return None
    return m.group("path"), int(m.group("line"))


def _rules(findings: list[Finding]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    for f in findings:
        if f.rule_id in index:
            continue
        index[f.rule_id] = len(rules)
        rules.append({
            "id": f.rule_id,
            "name": f.rule_id.replace("-", "_"),
            "shortDescription": {"text": f.title[:200]},
            "defaultConfiguration": {"level": level_for(f.severity)},
            "properties": {"category": f.category, "security-severity": SECURITY_SEVERITY[f.severity]},
        })
    return rules, index


def _result(f: Finding, rule_index: int) -> dict[str, Any]:
    text = f.title + (f" | {f.recommendation}" if f.recommendation else "")
    result: dict[str, Any] = {
        "ruleId": f.rule_id,
        "ruleIndex": rule_index,
        "level": level_for(f.severity),
        "message": {"text": text},
        "properties": {"severity": f.severity, "category": f.category, "resource": f.resource},
    }
    parsed = parse_location(f.location)
    if parsed:
        path, line = parsed
        result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": path},
                                                     "region": {"startLine": line}}}]
    return result


def report_to_run(report: AnalysisReport) -> dict[str, Any]:
    rules, index = _rules(report.findings)
    return {
        "tool": {"driver": {"name": f"tac-core-{report.tool}", "rules": rules}},
        "results": [_result(f, index[f.rule_id]) for f in report.findings],
        "properties": {"pack": report.pack, "input": report.input, "summary": report.summary},
    }


def to_sarif(reports: list[AnalysisReport]) -> dict[str, Any]:
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [report_to_run(r) for r in reports]}


def to_sarif_json(reports: list[AnalysisReport], indent: int = 2) -> str:
    return json.dumps(to_sarif(reports), indent=indent, ensure_ascii=False, default=str)
