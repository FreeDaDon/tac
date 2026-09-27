"""Markdown rendering. Every string that came from analyzed input is escaped (untrusted)."""

from __future__ import annotations

import json
from collections import Counter

from core.common import SEVERITY_ORDER, AnalysisReport, Finding
from core.security.sanitize import escape_markdown, markdown_code

SEVERITIES = sorted(SEVERITY_ORDER, key=lambda s: -SEVERITY_ORDER[s])
MAX_EVIDENCE_CHARS = 600


def _severity_counts(findings: list[Finding]) -> Counter[str]:
    return Counter(f.severity for f in findings)


def _evidence(finding: Finding) -> str:
    text = json.dumps(finding.evidence, sort_keys=True, ensure_ascii=False, default=str)
    return markdown_code(text, max_len=MAX_EVIDENCE_CHARS)


def render_finding(finding: Finding) -> str:
    lines = [f"- **{escape_markdown(finding.rule_id)}**: {escape_markdown(finding.title)}"]
    if finding.resource:
        lines.append(f"  - Resource: {markdown_code(finding.resource)}")
    if finding.location and finding.location != finding.resource:
        lines.append(f"  - Location: {markdown_code(finding.location)}")
    if finding.evidence:
        lines.append(f"  - Evidence: {_evidence(finding)}")
    if finding.recommendation:
        lines.append(f"  - Recommendation: {escape_markdown(finding.recommendation)}")
    return "\n".join(lines)


def render_report(report: AnalysisReport, heading_level: int = 2) -> str:
    h = "#" * heading_level
    counts = _severity_counts(report.findings)
    out = [
        f"{h} {escape_markdown(report.pack)} / {escape_markdown(report.tool)}",
        "",
        f"Input: {markdown_code(report.input)}",
        "",
        escape_markdown(report.summary) if report.summary else "",
        "",
        "| Severity | Count |",
        "|---|---|",
        *(f"| {s} | {counts.get(s, 0)} |" for s in SEVERITIES),
        "",
    ]
    for severity in SEVERITIES:
        group = [f for f in report.findings if f.severity == severity]
        if group:
            out += [f"{h}# {severity.capitalize()} ({len(group)})", "", *(render_finding(f) for f in group), ""]
    if not report.findings:
        out += ["No findings.", ""]
    return "\n".join(out)


def render_reports(reports: list[AnalysisReport], title: str = "Analysis Report") -> str:
    """One Markdown document: overall summary table, then one section per report."""
    all_findings = [f for r in reports for f in r.findings]
    counts = _severity_counts(all_findings)
    out = [
        f"# {escape_markdown(title)}",
        "",
        f"{len(reports)} report(s), {len(all_findings)} finding(s).",
        "",
        "| Pack | Tool | Input | Findings | Max severity | Summary |",
        "|---|---|---|---|---|---|",
        *(f"| {escape_markdown(r.pack)} | {escape_markdown(r.tool)} | {escape_markdown(r.input)} | {len(r.findings)} "
          f"| {r.max_severity} | {escape_markdown(r.summary)} |" for r in reports),
        "",
        "| Severity | Count |",
        "|---|---|",
        *(f"| {s} | {counts.get(s, 0)} |" for s in SEVERITIES),
        "",
    ]
    out += [render_report(r) for r in reports]
    return "\n".join(out).rstrip() + "\n"
