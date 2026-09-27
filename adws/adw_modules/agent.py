"""Agent execution: render a slash-command template, route a model, enforce budget, run, record.

Two runners:
  ClaudeRunner - the real `claude -p` CLI (stream-json output, timeout, process-group kill)
  MockRunner   - deterministic offline runner (TAC_AGENT_RUNNER=mock) used by tests and dry runs
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from . import telemetry
from .budget import Budget, BudgetExceeded, default_budget_usd, record_usage, spent
from .cache import PromptCache
from .data_types import RETRYABLE, AgentRequest, AgentResponse, RetryCode, Usage
from .model_router import route
from .security import safe_subprocess_env, skip_permissions_allowed, validate_adw_id
from .state import ADWState
from .utils import project_root, run_dir

CLAUDE_PATH = os.getenv("CLAUDE_CODE_PATH", "claude")
DEFAULT_TIMEOUT_S = int(os.getenv("TAC_AGENT_TIMEOUT_S", "1800"))
RETRY_DELAYS = [2, 5, 10]


# ----------------------------------------------------------------------------- templates
def command_file(slash_command: str, root: Path | None = None) -> Path:
    name = slash_command.lstrip("/")
    if not re.fullmatch(r"[a-z0-9_]+", name):
        raise ValueError(f"invalid slash command {slash_command!r}")
    return (root or project_root()) / ".claude" / "commands" / f"{name}.md"


def render_template(slash_command: str, args: list[str], root: Path | None = None) -> str:
    """Substitute $1..$9 and $ARGUMENTS deterministically (no shell-style word splitting)."""
    path = command_file(slash_command, root)
    if not path.exists():
        raise FileNotFoundError(f"slash command template not found: {path}")
    text = path.read_text()
    # strip YAML frontmatter; it configures interactive use only
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            text = text[end + 5 :]
    for i in range(9, 0, -1):
        text = text.replace(f"${i}", args[i - 1] if i <= len(args) else "")
    return text.replace("$ARGUMENTS", "\n".join(args))


# ----------------------------------------------------------------------------- output parsing
def parse_stream_json(raw: str) -> tuple[dict | None, list[dict]]:
    messages: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            messages.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    result = next((m for m in reversed(messages) if m.get("type") == "result"), None)
    return result, messages


def usage_from_result(result: dict) -> Usage:
    u = result.get("usage") or {}
    return Usage(
        input_tokens=int(u.get("input_tokens", 0) or 0),
        output_tokens=int(u.get("output_tokens", 0) or 0),
        cache_read_input_tokens=int(u.get("cache_read_input_tokens", 0) or 0),
        cache_creation_input_tokens=int(u.get("cache_creation_input_tokens", 0) or 0),
        cost_usd=float(result.get("total_cost_usd", result.get("cost_usd", 0.0)) or 0.0),
    )


# ----------------------------------------------------------------------------- runners
class Runner(Protocol):
    def run(self, request: AgentRequest, prompt: str, model: str, output_dir: Path) -> AgentResponse: ...


class ClaudeRunner:
    def run(self, request: AgentRequest, prompt: str, model: str, output_dir: Path) -> AgentResponse:
        cmd = [CLAUDE_PATH, "-p", "--model", model, "--output-format", "stream-json", "--verbose"]
        cwd = request.working_dir or str(project_root())
        mcp = Path(cwd) / ".mcp.json"
        if mcp.exists():
            cmd += ["--mcp-config", str(mcp)]
        # the run's own artifact dir (inputs, screenshots) lives in the main checkout, outside the worktree
        cmd += ["--add-dir", str(run_dir(request.adw_id))]
        if request.max_budget_usd is not None:
            cmd += ["--max-budget-usd", f"{max(request.max_budget_usd, 0.01):.2f}"]
        if skip_permissions_allowed(request.working_dir, request.adw_id):
            cmd.append("--dangerously-skip-permissions")
        else:
            cmd += ["--permission-mode", "acceptEdits"]

        raw_path = output_dir / "raw_output.jsonl"
        timeout = request.timeout_s or DEFAULT_TIMEOUT_S
        with open(raw_path, "w") as out:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=out,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                env=safe_subprocess_env(include_github=True),
                start_new_session=True,
            )
            try:
                _, stderr = proc.communicate(input=prompt, timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                return AgentResponse(
                    output=f"agent timed out after {timeout}s", success=False,
                    retry_code=RetryCode.TIMEOUT_ERROR, model=model,
                )

        result, _ = parse_stream_json(raw_path.read_text())
        if result is None:
            return AgentResponse(
                output=f"no result message from claude (exit {proc.returncode}): {stderr[-500:]}",
                success=False, retry_code=RetryCode.CLAUDE_CODE_ERROR, model=model,
            )
        usage = usage_from_result(result)
        is_error = bool(result.get("is_error"))
        code = RetryCode.NONE
        if is_error:
            subtype = str(result.get("subtype", ""))
            if "budget" in subtype:
                code = RetryCode.BUDGET_EXCEEDED  # never retried
            elif subtype == "error_during_execution":
                code = RetryCode.ERROR_DURING_EXECUTION
            else:
                code = RetryCode.EXECUTION_ERROR
        return AgentResponse(
            output=str(result.get("result", "")), success=not is_error, session_id=result.get("session_id"),
            retry_code=code, model=model, usage=usage,
        )


MockHandler = Callable[[AgentRequest, str], str]


class MockRunner:
    """Deterministic runner. Handlers map slash command -> function(request, prompt) -> output text.

    Handlers may perform file edits in request.working_dir to simulate an agent's effects.
    """

    handlers: dict[str, MockHandler] = {}

    @classmethod
    def register(cls, slash_command: str, handler: MockHandler) -> None:
        cls.handlers[slash_command] = handler

    def run(self, request: AgentRequest, prompt: str, model: str, output_dir: Path) -> AgentResponse:
        from . import mock_agent  # noqa: F401 - registers default handlers

        handler = self.handlers.get(request.slash_command)
        if handler is None:
            output = f"mock: no handler for {request.slash_command}"
        else:
            output = handler(request, prompt)
        (output_dir / "raw_output.jsonl").write_text(
            json.dumps({"type": "result", "result": output, "is_error": False, "total_cost_usd": 0.0}) + "\n"
        )
        return AgentResponse(output=output, success=True, model=f"mock-{model}", usage=Usage())


def get_runner() -> Runner:
    return MockRunner() if os.getenv("TAC_AGENT_RUNNER", "claude") == "mock" else ClaudeRunner()


# ----------------------------------------------------------------------------- orchestration
def _output_dir(adw_id: str, agent_name: str) -> Path:
    if not re.fullmatch(r"[a-z0-9_]{1,64}", agent_name):
        raise ValueError(f"invalid agent name {agent_name!r}")
    path = run_dir(adw_id) / agent_name
    path.mkdir(parents=True, exist_ok=True)
    return path


def execute_template(request: AgentRequest, runner: Runner | None = None) -> AgentResponse:
    """Run one slash command as a focused agent with routing, budget, cache, retry and telemetry."""
    validate_adw_id(request.adw_id)
    runner = runner or get_runner()
    state = ADWState.load(request.adw_id)
    model_set = state.data.model_set if state else "base"
    budget = Budget(state.data.budget_usd if state else default_budget_usd(), spent(request.adw_id))

    try:
        budget.check()
    except BudgetExceeded as exc:
        telemetry.emit(request.adw_id, "budget", message=str(exc), exceeded=True)
        return AgentResponse(output=str(exc), success=False, retry_code=RetryCode.BUDGET_EXCEEDED)

    model = request.model or route(request.slash_command, model_set, budget.under_pressure)
    # Templates always come from the main checkout, never the worktree: an agent that edits
    # .claude/commands inside its worktree must not be able to rewrite its own future prompts.
    prompt = render_template(request.slash_command, request.args)

    out_dir = _output_dir(request.adw_id, request.agent_name)
    (out_dir / "prompt.md").write_text(prompt)

    cache = PromptCache() if (request.allow_cache and PromptCache.enabled_for(request.slash_command)) else None
    cache_key = (PromptCache.key(request.slash_command, prompt, model, request.working_dir, request.args,
                                 runner=type(runner).__name__) if cache else "")
    if cache:
        hit = cache.get(cache_key)
        if hit:
            telemetry.emit(request.adw_id, "agent_call", message=f"{request.slash_command} cache hit",
                           agent=request.agent_name, model=model, cached=True)
            return hit

    if budget.limit_usd > 0:
        request = request.model_copy(update={"max_budget_usd": round(budget.limit_usd - budget.spent.cost_usd, 4)})
    started = time.monotonic()
    response = runner.run(request, prompt, model, out_dir)
    for delay in RETRY_DELAYS:
        if response.success or response.retry_code not in RETRYABLE:
            break
        time.sleep(delay if os.getenv("TAC_AGENT_RUNNER") != "mock" else 0)
        record_usage(request.adw_id, response.usage, request.slash_command)
        response = runner.run(request, prompt, model, out_dir)

    record_usage(request.adw_id, response.usage, request.slash_command)
    telemetry.emit(
        request.adw_id, "agent_call", message=f"{request.slash_command} -> {'ok' if response.success else 'fail'}",
        agent=request.agent_name, model=response.model or model, success=response.success,
        duration_s=round(time.monotonic() - started, 2), cost_usd=response.usage.cost_usd,
        tokens_in=response.usage.input_tokens, tokens_out=response.usage.output_tokens,
    )
    if cache and response.success:
        cache.put(cache_key, request.slash_command, response)
    return response


def write_input_file(adw_id: str, name: str, content: str) -> str:
    """Large/untrusted payloads go to a file; the prompt receives the path, not the raw text."""
    if not re.fullmatch(r"[a-z0-9_.-]{1,64}", name):
        raise ValueError(f"invalid input file name {name!r}")
    path = run_dir(adw_id) / "inputs" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return str(path)
