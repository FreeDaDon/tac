"""Typed contracts shared by all ADW modules, workflows, the dashboard and domain packs."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ModelSet = Literal["base", "heavy"]
ModelName = Literal["haiku", "sonnet", "opus"]
IssueClass = Literal["/feature", "/bug", "/chore", "/patch"]
DomainPack = Literal["swe", "devops", "soc", "iam"]
ShipPolicy = Literal["zte_allowed", "pr_only", "report_only"]
Severity = Literal["blocker", "tech_debt", "skippable"]
GateStatus = Literal["passed", "failed", "skipped", "error"]


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class RetryCode(StrEnum):
    NONE = "none"
    CLAUDE_CODE_ERROR = "claude_code_error"
    TIMEOUT_ERROR = "timeout_error"
    EXECUTION_ERROR = "execution_error"
    ERROR_DURING_EXECUTION = "error_during_execution"
    BUDGET_EXCEEDED = "budget_exceeded"


RETRYABLE = {
    RetryCode.CLAUDE_CODE_ERROR,
    RetryCode.TIMEOUT_ERROR,
    RetryCode.EXECUTION_ERROR,
    RetryCode.ERROR_DURING_EXECUTION,
}


class Usage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cost_usd: float = 0.0

    def add(self, other: Usage) -> Usage:
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cache_read_input_tokens=self.cache_read_input_tokens + other.cache_read_input_tokens,
            cache_creation_input_tokens=self.cache_creation_input_tokens + other.cache_creation_input_tokens,
            cost_usd=round(self.cost_usd + other.cost_usd, 6),
        )


class AgentRequest(BaseModel):
    """One focused agent call: one agent, one prompt, one purpose."""

    adw_id: str
    agent_name: str
    slash_command: str
    args: list[str] = Field(default_factory=list)
    working_dir: str | None = None
    model: ModelName | None = None  # None -> model router decides
    allow_cache: bool = False
    timeout_s: int | None = None
    max_budget_usd: float | None = None  # set by execute_template from the run's remaining budget


class AgentResponse(BaseModel):
    output: str
    success: bool
    session_id: str | None = None
    retry_code: RetryCode = RetryCode.NONE
    model: str = ""
    usage: Usage = Field(default_factory=Usage)
    cached: bool = False


class TestResult(BaseModel):
    __test__ = False  # not a pytest class
    test_name: str
    passed: bool
    execution_command: str
    test_purpose: str = ""
    error: str | None = None


class E2ETestResult(BaseModel):
    __test__ = False
    test_name: str
    status: Literal["passed", "failed"]
    test_path: str
    screenshots: list[str] = Field(default_factory=list)
    error: str | None = None

    @property
    def passed(self) -> bool:
        return self.status == "passed"


class ReviewIssue(BaseModel):
    review_issue_number: int
    screenshot_path: str = ""
    issue_description: str
    issue_resolution: str
    issue_severity: Severity


class ReviewResult(BaseModel):
    success: bool
    review_summary: str
    review_issues: list[ReviewIssue] = Field(default_factory=list)
    screenshots: list[str] = Field(default_factory=list)

    @property
    def blockers(self) -> list[ReviewIssue]:
        return [i for i in self.review_issues if i.issue_severity == "blocker"]


class RedTeamFinding(BaseModel):
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    file: str = ""
    line: int | None = None
    category: str = "security"
    detail: str = ""
    source: Literal["agent", "scanner"] = "agent"


class RedTeamResult(BaseModel):
    findings: list[RedTeamFinding] = Field(default_factory=list)
    summary: str = ""

    @property
    def blocking(self) -> list[RedTeamFinding]:
        return [f for f in self.findings if f.severity in ("critical", "high")]


class GateResult(BaseModel):
    name: str
    status: GateStatus
    detail: str = ""
    duration_s: float = 0.0
    required_for_zte: bool = True


class GateReport(BaseModel):
    adw_id: str
    created: str = Field(default_factory=utcnow)
    gates: list[GateResult] = Field(default_factory=list)

    def upsert(self, result: GateResult) -> None:
        self.gates = [g for g in self.gates if g.name != result.name] + [result]

    def get(self, name: str) -> GateResult | None:
        return next((g for g in self.gates if g.name == name), None)

    @property
    def all_green(self) -> bool:
        required = [g for g in self.gates if g.required_for_zte]
        return bool(required) and all(g.status == "passed" for g in required)

    def missing(self, names: list[str]) -> list[str]:
        present = {g.name for g in self.gates if g.status == "passed"}
        return [n for n in names if n not in present]


class ADWStateData(BaseModel):
    """Persisted workflow state. Unknown keys are kept (never silently dropped)."""

    model_config = ConfigDict(extra="allow")

    adw_id: str
    domain: DomainPack = "swe"
    issue_number: str | None = None
    issue_title: str | None = None
    issue_class: IssueClass | None = None
    branch_name: str | None = None
    plan_file: str | None = None
    patch_file: str | None = None
    worktree_path: str | None = None
    backend_port: int | None = None
    frontend_port: int | None = None
    model_set: ModelSet = "base"
    all_adws: list[str] = Field(default_factory=list)
    phases: dict[str, str] = Field(default_factory=dict)  # phase -> passed|failed|running
    e2e_skipped: bool = False
    usage: Usage = Field(default_factory=Usage)
    budget_usd: float = 5.0
    gate_report: GateReport | None = None
    created: str = Field(default_factory=utcnow)
    updated: str = Field(default_factory=utcnow)


class TelemetryEvent(BaseModel):
    adw_id: str
    event_type: str  # phase_start | phase_end | agent_call | gate | budget | error | lesson | hook
    phase: str = ""
    message: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    source: str = "adw"
    timestamp: str = Field(default_factory=utcnow)


class IssuePayload(BaseModel):
    number: str
    title: str
    body: str = ""
    author: str = ""
    labels: list[str] = Field(default_factory=list)
