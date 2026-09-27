from __future__ import annotations

import json
from pathlib import Path

import pytest

from adws.adw_modules import agent
from adws.adw_modules.agent import (
    MockRunner,
    execute_template,
    parse_stream_json,
    render_template,
    usage_from_result,
)
from adws.adw_modules.budget import Budget
from adws.adw_modules.cache import PromptCache, normalize_prompt
from adws.adw_modules.data_types import AgentRequest, RetryCode, Usage
from adws.adw_modules.model_router import route
from adws.adw_modules.state import ADWState


def test_render_template_keeps_args_intact(tac_root: Path) -> None:
    """tac-7 regression: space-joined args split issue JSON across $3/$4."""
    out = render_template("/feature", ["12", "ab12cd34", "path with spaces/issue.md", "specs/x.md"])
    assert out.strip() == "Plan issue 12 adw ab12cd34 from path with spaces/issue.md into specs/x.md"


def test_render_template_rejects_traversal(tac_root: Path) -> None:
    with pytest.raises(ValueError):
        render_template("/../../etc/passwd", [])


def test_stream_json_usage() -> None:
    raw = "\n".join([
        json.dumps({"type": "system"}),
        "not json",
        json.dumps({"type": "result", "result": "done", "is_error": False, "session_id": "s1",
                    "total_cost_usd": 0.42, "usage": {"input_tokens": 100, "output_tokens": 20}}),
    ])
    result, messages = parse_stream_json(raw)
    assert result and result["result"] == "done" and len(messages) == 2
    u = usage_from_result(result)
    assert u.cost_usd == 0.42 and u.input_tokens == 100


def test_router_and_budget_downgrade() -> None:
    assert route("/classify_issue", "heavy") == "haiku"
    assert route("/implement", "heavy") == "opus"
    assert route("/implement", "base") == "sonnet"
    assert route("/implement", "heavy", budget_pressure=True) == "sonnet"
    b = Budget(1.0, Usage(cost_usd=0.85))
    assert b.under_pressure and not b.exhausted
    b.record(Usage(cost_usd=0.2))
    assert b.exhausted


def test_budget_exhaustion_blocks_agent_calls(tac_root: Path) -> None:
    s = ADWState("ab12cd34", budget_usd=1.0)
    s.add_usage(Usage(cost_usd=1.5))
    s.save()
    resp = execute_template(AgentRequest(adw_id="ab12cd34", agent_name="x", slash_command="/implement", args=["p"]))
    assert not resp.success and resp.retry_code == RetryCode.BUDGET_EXCEEDED


def test_usage_accumulates_into_state(tac_root: Path) -> None:
    class Costly(MockRunner):
        def run(self, request, prompt, model, output_dir):
            r = super().run(request, prompt, model, output_dir)
            r.usage = Usage(cost_usd=0.1, input_tokens=5)
            return r

    ADWState("ab12cd34").save()
    execute_template(AgentRequest(adw_id="ab12cd34", agent_name="a1", slash_command="/commit", args=["a", "b", "c"]),
                     runner=Costly())
    execute_template(AgentRequest(adw_id="ab12cd34", agent_name="a2", slash_command="/commit", args=["a", "b", "c"]),
                     runner=Costly())
    st = ADWState.load("ab12cd34")
    assert st and abs(st.data.usage.cost_usd - 0.2) < 1e-9


def test_retry_on_retryable_errors(tac_root: Path) -> None:
    calls = {"n": 0}

    class Flaky(MockRunner):
        def run(self, request, prompt, model, output_dir):
            calls["n"] += 1
            r = super().run(request, prompt, model, output_dir)
            if calls["n"] < 3:
                r.success, r.retry_code = False, RetryCode.CLAUDE_CODE_ERROR
            return r

    resp = execute_template(AgentRequest(adw_id="ab12cd34", agent_name="f", slash_command="/commit", args=[]),
                            runner=Flaky())
    assert resp.success and calls["n"] == 3


def test_invalid_agent_name_rejected(tac_root: Path) -> None:
    with pytest.raises(ValueError):
        execute_template(AgentRequest(adw_id="ab12cd34", agent_name="../x", slash_command="/commit"))


def test_cache_only_read_only_commands(tac_root: Path) -> None:
    assert PromptCache.enabled_for("/classify_issue")
    assert not PromptCache.enabled_for("/implement")
    assert normalize_prompt("adw ab12cd34  at 2026-01-01T00:00:00Z") == normalize_prompt("adw ffff0000 at 2025-02-02 11:11:11")


def test_cache_hit_and_tree_invalidation(tac_root: Path) -> None:
    calls = {"n": 0}

    class Counting(MockRunner):
        def run(self, request, prompt, model, output_dir):
            calls["n"] += 1
            return super().run(request, prompt, model, output_dir)

    req = AgentRequest(adw_id="ab12cd34", agent_name="c", slash_command="/classify_issue", args=["i.md"],
                       working_dir=str(tac_root), allow_cache=True)
    first = execute_template(req, runner=Counting())
    second = execute_template(req, runner=Counting())
    assert calls["n"] == 1 and second.cached and not first.cached
    (tac_root / "new.txt").write_text("x")
    import subprocess

    subprocess.run(["git", "add", "-A"], cwd=tac_root, check=True)
    subprocess.run(["git", "commit", "-qm", "c"], cwd=tac_root, check=True)
    execute_template(req, runner=Counting())
    assert calls["n"] == 2


def test_claude_runner_timeout_kills(tac_root: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """tac-7 regression: agent calls had no timeout."""
    fake = tmp_path / "fake_claude.sh"
    fake.write_text("#!/bin/sh\nsleep 30\n")
    fake.chmod(0o755)
    monkeypatch.setattr(agent, "CLAUDE_PATH", str(fake))
    out = tmp_path / "out"
    out.mkdir()
    req = AgentRequest(adw_id="ab12cd34", agent_name="t", slash_command="/commit", timeout_s=1)
    resp = agent.ClaudeRunner().run(req, "hi", "haiku", out)
    assert not resp.success and resp.retry_code == RetryCode.TIMEOUT_ERROR


def test_claude_runner_no_skip_permissions_outside_worktree(
    tac_root: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    argv_file = tmp_path / "argv.txt"
    fake = tmp_path / "fake_claude.sh"
    fake.write_text(f'#!/bin/sh\necho "$@" > {argv_file}\n'
                    'echo \'{"type":"result","result":"ok","is_error":false,"total_cost_usd":0.01}\'\n')
    fake.chmod(0o755)
    monkeypatch.setattr(agent, "CLAUDE_PATH", str(fake))
    monkeypatch.setenv("TAC_ALLOW_SKIP_PERMISSIONS", "1")
    out = tmp_path / "o"
    out.mkdir()
    resp = agent.ClaudeRunner().run(
        AgentRequest(adw_id="ab12cd34", agent_name="t", slash_command="/commit", working_dir=str(tac_root)),
        "hi", "haiku", out)
    assert resp.success and resp.usage.cost_usd == 0.01
    argv = argv_file.read_text()
    assert "--dangerously-skip-permissions" not in argv and "acceptEdits" in argv


def test_cache_key_tracks_file_content_and_runner(tac_root: Path, tmp_path: Path) -> None:
    """Live-run regression: prompts carry file PATHS, so two issues at the same path shared a cache entry,
    and mock answers were served to the real runner."""
    issue = tmp_path / "issue.md"
    issue.write_text("issue A")
    k1 = PromptCache.key("/classify_issue", "Classify x", "haiku", None, [str(issue)], runner="ClaudeRunner")
    issue.write_text("issue B")
    k2 = PromptCache.key("/classify_issue", "Classify x", "haiku", None, [str(issue)], runner="ClaudeRunner")
    k3 = PromptCache.key("/classify_issue", "Classify x", "haiku", None, [str(issue)], runner="MockRunner")
    assert len({k1, k2, k3}) == 3


def test_claude_runner_grants_run_dir(tac_root: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Live-run regression: agents in a worktree could not read their inputs in agent/runs/<id>/."""
    argv_file = tmp_path / "argv.txt"
    fake = tmp_path / "fake_claude.sh"
    fake.write_text(f'#!/bin/sh\necho "$@" > {argv_file}\n'
                    'echo \'{"type":"result","result":"ok","is_error":false}\'\n')
    fake.chmod(0o755)
    monkeypatch.setattr(agent, "CLAUDE_PATH", str(fake))
    out = tmp_path / "o"
    out.mkdir()
    agent.ClaudeRunner().run(AgentRequest(adw_id="ab12cd34", agent_name="t", slash_command="/commit"), "hi", "haiku", out)
    assert f"--add-dir {tac_root / 'agent' / 'runs' / 'ab12cd34'}" in argv_file.read_text()
