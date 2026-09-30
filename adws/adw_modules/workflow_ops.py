"""Agent-backed SDLC steps with strict output validation, plus phase bookkeeping."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import get_args

from pydantic import BaseModel, Field

from . import github, telemetry
from .agent import execute_template, write_input_file
from .budget import record_usage
from .data_types import AgentRequest, IssueClass, IssuePayload
from .git_ops import commit_all, has_remote, push_branch
from .jev import JevClient, JevError, cost_of
from .memory import format_for_prompt, relevant
from .security import SecurityError, fence_untrusted, resolve_inside, sanitize_untrusted, validate_branch_name
from .state import ADWState
from .utils import extract_json_text

LOCAL_ISSUE_NUMBER = "0"

# Below this Jev confidence, classify_issue falls back to the full agent classifier rather than
# trusting a low-confidence advisory answer. Reviewable here, not buried in the call site.
JEV_CLASSIFY_CONFIDENCE_THRESHOLD = 0.7


class WorkflowError(RuntimeError):
    pass


# ----------------------------------------------------------------------------- phases
@contextmanager
def phase(state: ADWState, name: str) -> Iterator[None]:
    """Record phase start/end in state + telemetry. Exceptions mark the phase failed and propagate."""
    state.reload()
    state.set_phase(name, "running")
    state.save()
    telemetry.emit(state.adw_id, "phase_start", phase=name)
    started = time.monotonic()
    try:
        yield
    except BaseException as exc:
        state.reload()
        state.set_phase(name, "failed")
        state.save()
        telemetry.emit(state.adw_id, "phase_end", phase=name, message=f"failed: {exc}"[:500], status="failed",
                       duration_s=round(time.monotonic() - started, 2))
        raise
    state.reload()
    if state.data.phases.get(name) == "running":
        state.set_phase(name, "passed")
    state.save()
    telemetry.emit(state.adw_id, "phase_end", phase=name, status=state.data.phases[name],
                   duration_s=round(time.monotonic() - started, 2))


def fail_phase(state: ADWState, name: str) -> None:
    state.reload()
    state.set_phase(name, "failed")
    state.save()


# ----------------------------------------------------------------------------- issues
def load_issue_file(path: str | Path) -> IssuePayload:
    """Local issue markdown: first '# ' line is the title, the rest is the body."""
    text = Path(path).read_text()
    lines = text.strip().splitlines()
    title = lines[0].lstrip("# ").strip() if lines else "untitled"
    body = "\n".join(lines[1:]).strip()
    return IssuePayload(number=LOCAL_ISSUE_NUMBER, title=sanitize_untrusted(title, 300),
                        body=sanitize_untrusted(body), author="local")


def load_issue(issue_number: str | None, issue_file: str | None) -> IssuePayload:
    if issue_file:
        return load_issue_file(issue_file)
    if issue_number:
        return github.fetch_issue(issue_number)
    raise WorkflowError("provide --issue or --issue-file")


def write_issue_input(adw_id: str, issue: IssuePayload) -> str:
    """Issue content is persisted fenced as untrusted data; prompts receive only the path."""
    payload = json.dumps(issue.model_dump(), indent=2)
    return write_input_file(adw_id, "issue.md", fence_untrusted(payload, label="github_issue"))


# ----------------------------------------------------------------------------- agent steps
def _run(state: ADWState, agent_name: str, command: str, args: list[str], cwd: str | None = None,
         cache: bool = False) -> str:
    resp = execute_template(AgentRequest(adw_id=state.adw_id, agent_name=agent_name, slash_command=command,
                                         args=args, working_dir=cwd, allow_cache=cache))
    if not resp.success:
        raise WorkflowError(f"{command} failed: {resp.output[:500]}")
    return resp.output.strip()


def _jev_classify_issue(state: ADWState, issue_file: str) -> IssueClass | None:
    """Advisory fast path: a typed Jev decision instead of a full agent subprocess. Returns
    None (never raises) on anything that isn't a confident, valid classification, so the
    caller always has a clean fallback to the full agent classifier."""
    try:
        payload = IssuePayload.model_validate_json(extract_json_text(Path(issue_file).read_text()))
        answer = JevClient().classify_issue(payload.title, payload.body, payload.labels)
    except (JevError, ValueError, OSError):
        return None
    record_usage(state.adw_id, cost_of(answer), command=f"/classify_issue:jev:{answer.backend}")
    telemetry.emit(state.adw_id, "agent_call", phase="plan", message="jev classify_issue",
                   model=f"jev:{answer.backend}", cost_usd=cost_of(answer).cost_usd,
                   choice=answer.choice, confidence=answer.confidence)
    if answer.confidence < JEV_CLASSIFY_CONFIDENCE_THRESHOLD:
        return None
    if answer.choice not in get_args(IssueClass):
        return None  # choice was "0" (not actionable) or otherwise outside the workflow's classes
    return answer.choice  # type: ignore[return-value]


def classify_issue(state: ADWState, issue_file: str) -> IssueClass:
    jev_result = _jev_classify_issue(state, issue_file)
    if jev_result is not None:
        return jev_result
    out = _run(state, "issue_classifier", "/classify_issue", [issue_file], cache=True)
    match = re.search(r"(/feature|/bug|/chore|/patch)\b", out)
    if not match or match.group(1) not in get_args(IssueClass):
        raise WorkflowError(f"unclassifiable issue (agent said {out[:80]!r})")
    return match.group(1)  # type: ignore[return-value]


def make_branch_name(state: ADWState, issue_class: str, issue_file: str, issue_number: str) -> str:
    out = _run(state, "branch_generator", "/generate_branch_name", [issue_class, issue_file], cache=True)
    slug = re.sub(r"[^a-z0-9-]+", "-", out.strip().splitlines()[-1].lower()).strip("-")[:40] or "change"
    return validate_branch_name(f"{issue_class.lstrip('/')}-issue-{issue_number}-adw-{state.adw_id}-{slug}")


def plan_path_for(branch: str) -> str:
    return f"specs/{branch}.md"


def build_plan(state: ADWState, issue_class: str, issue_file: str, plan_rel: str) -> str:
    wt = state.working_dir()
    lessons = relevant(Path(issue_file).read_text(), tags=[state.data.domain, issue_class.lstrip("/")])
    lesson_note = format_for_prompt(lessons)
    args = [state.data.issue_number or LOCAL_ISSUE_NUMBER, state.adw_id, issue_file, plan_rel]
    if lesson_note:
        args.append(write_input_file(state.adw_id, "lessons.md", lesson_note))
    _run(state, "sdlc_planner", issue_class, args, cwd=wt)
    plan_abs = resolve_inside(wt, plan_rel)
    if not plan_abs.exists() or plan_abs.stat().st_size == 0:
        raise WorkflowError(f"planner did not write the plan at {plan_rel}")
    return plan_rel


def implement_plan(state: ADWState, plan_rel: str, agent_name: str = "sdlc_implementor") -> str:
    wt = state.working_dir()
    resolve_inside(wt, plan_rel)
    return _run(state, agent_name, "/implement", [plan_rel], cwd=wt)


def commit(state: ADWState, agent_name: str, fallback: str) -> bool:
    """Commit worktree changes with an agent-written (validated) message."""
    wt = state.working_dir()
    issue_file = str(Path(state.dir) / "inputs" / "issue.md")
    try:
        msg = _run(state, f"{agent_name}_committer", "/commit",
                   [agent_name, state.data.issue_class or "/chore", issue_file])
        msg = re.sub(r"[^\w .,:()/'-]", "", msg.splitlines()[0])[:72] or fallback
    except WorkflowError:
        msg = fallback
    cls = (state.data.issue_class or "/chore").lstrip("/")
    return commit_all(f"{agent_name}: {cls}: {msg}\n\nADW-ID: {state.adw_id}", wt)


def publish(state: ADWState, title: str, body: str) -> str | None:
    """Push the branch and open/update a PR when a GitHub remote exists."""
    wt = state.working_dir()
    branch = state.data.branch_name
    if not branch or not has_remote(wt):
        return None
    push_branch(branch, wt)
    try:
        return github.create_pr(branch, title, body)
    except (github.GitHubError, SecurityError) as exc:
        telemetry.emit(state.adw_id, "error", message=f"PR creation failed: {exc}")
        return None


def notify(state: ADWState, message: str) -> None:
    if state.data.issue_number and state.data.issue_number != LOCAL_ISSUE_NUMBER:
        github.comment(state.data.issue_number, state.adw_id, message)


def pr_body(state: ADWState) -> str:
    s = state.public_summary()
    gates = "\n".join(f"- {k}: **{v}**" for k, v in s["gates"].items()) or "- (not run yet)"
    closes = f"Closes #{state.data.issue_number}\n\n" if state.data.issue_number not in (None, LOCAL_ISSUE_NUMBER) else ""
    return (
        f"{closes}ADW `{state.adw_id}` · domain `{s['domain']}` · class `{s['issue_class']}` · "
        f"model set `{s['model_set']}`\n\nPlan: `{state.data.plan_file}`\n\n### Gates\n{gates}\n\n"
        f"Cost so far: ${s['cost_usd']:.4f}\n\n🤖 Generated by the TAC ADW toolkit"
    )


# ----------------------------------------------------------------------------- domain assessment
class DomainAction(BaseModel):
    title: str
    priority: str = Field(pattern=r"^P[1-4]$")
    rationale: str
    finding_refs: list[str] = Field(default_factory=list)
    requires_human_approval: bool = True
    proposed_change: str = ""


class FalsePositive(BaseModel):
    finding_ref: str
    reason: str


class DomainAssessment(BaseModel):
    risk_rating: str = Field(pattern=r"^(critical|high|medium|low)$")
    summary: str
    prioritized_actions: list[DomainAction] = Field(default_factory=list)
    false_positives: list[FalsePositive] = Field(default_factory=list)
