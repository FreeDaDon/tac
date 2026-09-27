"""Shared result contract for every deterministic domain tool (no LLM calls anywhere in core/)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

FindingSeverity = Literal["critical", "high", "medium", "low", "info"]
SEVERITY_ORDER: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class Finding(BaseModel):
    rule_id: str                      # stable id, e.g. "IAM001", "TF-DESTROY", "SOC-BRUTEFORCE"
    title: str
    severity: FindingSeverity
    category: str                     # e.g. "privilege", "drift", "detection", "secret"
    resource: str = ""                # file, ARN, host, user, resource address
    location: str = ""                # "path:line" when applicable
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommendation: str = ""


class AnalysisReport(BaseModel):
    pack: Literal["swe", "devops", "soc", "iam"]
    tool: str                         # e.g. "tfplan", "auth_log", "iam_policy"
    input: str                        # input path or description
    findings: list[Finding] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    summary: str = ""

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    def blocking(self, threshold: str = "high") -> list[Finding]:
        return [f for f in self.findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[threshold]]
