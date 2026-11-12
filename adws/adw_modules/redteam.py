"""Adversarial red-team gate: deterministic scanners + a hostile reviewer agent.

The gate fails on any critical/high finding. Deterministic checks run first and are
passed to the agent as evidence; the agent cannot suppress them.
"""

from __future__ import annotations

import json
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any, Literal

from .agent import execute_template, write_input_file
from .data_types import AgentRequest, GateResult, GateStatus, RedTeamFinding, RedTeamResult
from .git_ops import base_ref, branch_diff, changed_files
from .jev import triage_findings
from .security import fence_untrusted, untrusted_code_env
from .utils import parse_json

_SKIP_MARKERS = re.compile(
    r"^\+.*(@pytest\.mark\.(skip|xfail)|@unittest\.skip|pytest\.skip\(|\.skip\(|it\.skip\(|describe\.skip\(|"
    r"#\s*type:\s*ignore|#\s*noqa|eslint-disable|@ts-ignore|--no-verify)"
)
_TEST_FILE = re.compile(r"(^|/)(tests?/|test_[^/]*\.py$|[^/]*_test\.py$|[^/]*\.(test|spec)\.[jt]s$)")
_COLLECTION_HOOKS = re.compile(
    r"^\+.*\b(pytest_collection_modifyitems|pytest_ignore_collect|pytest_deselected|collect_ignore(_glob)?)\b")
# Guardrails an agent must never edit: its own prompts/hooks/settings, agent instructions, MCP
# servers, and CI (lock 5 trusts CI). The documenter's conditional_docs entry is the one exception.
PROTECTED_PATHS = re.compile(
    r"^(\.claude/(?!commands/conditional_docs\.md$)|\.github/|\.mcp\.json$|(.*/)?(CLAUDE|AGENTS)\.md$|\.secretsallow$)")
GATE_CONFIG_SECTIONS = ("pytest", "ruff", "mypy", "tac", "coverage")
GATE_SCRIPTS = ("build", "test", "typecheck", "lint")


def detect_test_tampering(diff: str) -> list[RedTeamFinding]:
    """Flag diffs that weaken tests: removed assertions, added skips, deleted test files."""
    findings: list[RedTeamFinding] = []
    current = ""
    removed_asserts: dict[str, int] = {}
    added_asserts: dict[str, int] = {}
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            parts = line.split(" b/", 1)
            current = parts[1] if len(parts) == 2 else ""
            continue
        if line.startswith("deleted file mode") and _TEST_FILE.search(current):
            findings.append(RedTeamFinding(title="Test file deleted", severity="high", file=current,
                                           category="spec_cheating", detail="A test file was removed.",
                                           source="scanner"))
        if _COLLECTION_HOOKS.search(line):
            findings.append(RedTeamFinding(title="Test collection hook added", severity="high", file=current,
                                           category="spec_cheating", detail=line[:200], source="scanner"))
        if _SKIP_MARKERS.search(line):
            findings.append(RedTeamFinding(title="Check suppressed or test skipped", severity="high", file=current,
                                           category="spec_cheating", detail=line[:200], source="scanner"))
        if _TEST_FILE.search(current):
            if line.startswith("-") and not line.startswith("---") and "assert" in line:
                removed_asserts[current] = removed_asserts.get(current, 0) + 1
            if line.startswith("+") and not line.startswith("+++") and "assert" in line:
                added_asserts[current] = added_asserts.get(current, 0) + 1
    for path, removed in removed_asserts.items():
        if removed > added_asserts.get(path, 0):
            findings.append(RedTeamFinding(
                title="Net assertions removed from tests", severity="high", file=path, category="spec_cheating",
                detail=f"{removed} assertion lines removed vs {added_asserts.get(path, 0)} added", source="scanner"))
    return findings


def detect_protected_changes(files: list[str]) -> list[RedTeamFinding]:
    return [RedTeamFinding(title="Protected guardrail file modified", severity="high", file=f, category="spec_cheating",
                           detail="Agents may not edit prompts, hooks, settings, agent instructions, MCP config or CI.",
                           source="scanner") for f in files if PROTECTED_PATHS.match(f)]


def _show(cwd: str | Path, ref: str, path: str) -> str | None:
    proc = subprocess.run(["git", "show", f"{ref}:{path}"], cwd=str(cwd), capture_output=True, text=True, timeout=60)
    return proc.stdout if proc.returncode == 0 else None


def _toml_tool(text: str | None) -> dict[str, Any]:
    try:
        return dict(tomllib.loads(text or "").get("tool", {}))
    except tomllib.TOMLDecodeError:
        return {"<unparseable>": True}


def _json_scripts(text: str | None) -> dict[str, Any]:
    try:
        return dict(json.loads(text or "{}").get("scripts", {}))
    except (json.JSONDecodeError, AttributeError):
        return {"<unparseable>": True}


def detect_gate_config_drift(cwd: str | Path, files: list[str]) -> list[RedTeamFinding]:
    """Gate commands come from the main checkout, but pytest, ruff, mypy and npm read the worktree's
    own config. A branch that changes how its checks run is judging itself."""
    base = base_ref(cwd)
    findings = []
    for f in files:
        name = f.rsplit("/", 1)[-1]
        if name == "pyproject.toml":
            old, new = _toml_tool(_show(cwd, base, f)), _toml_tool(_show(cwd, "HEAD", f))
            changed = [k for k in GATE_CONFIG_SECTIONS if old.get(k) != new.get(k)]
        elif name == "package.json":
            old, new = _json_scripts(_show(cwd, base, f)), _json_scripts(_show(cwd, "HEAD", f))
            changed = [k for k in sorted(set(old) | set(new)) if any(g in k for g in GATE_SCRIPTS) and old.get(k) != new.get(k)]
        else:
            continue
        if changed:
            findings.append(RedTeamFinding(title="Gate configuration changed", severity="high", file=f,
                                           category="spec_cheating", detail=f"changed: {changed}", source="scanner"))
    return findings


def ruff_security_scan(cwd: str | Path, files: list[str]) -> list[RedTeamFinding]:
    py = [f for f in files if f.endswith(".py") and (Path(cwd) / f).exists()]
    if not py:
        return []
    proc = subprocess.run(
        ["uv", "run", "ruff", "check", "--select", "S", "--output-format", "json", "--exit-zero", *py],
        cwd=str(cwd), capture_output=True, text=True, timeout=300, env=untrusted_code_env(),
    )
    try:
        items = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return [RedTeamFinding(title="Security linter output unreadable", severity="high", category="tooling",
                               detail=proc.stderr[-500:], source="scanner")]
    out = []
    for it in items:
        code = it.get("code") or ""
        sev: Literal["high", "medium"] = "high" if code in {"S102", "S307", "S602", "S604", "S605", "S608", "S301", "S506"} else "medium"
        out.append(RedTeamFinding(
            title=f"{code}: {it.get('message', '')}"[:200], severity=sev,
            file=str(Path(it.get("filename", "")).resolve().relative_to(Path(cwd).resolve()))
            if it.get("filename") else "",
            line=(it.get("location") or {}).get("row"), category="static_analysis", source="scanner"))
    return out


def run_redteam(adw_id: str, working_dir: str, spec_file: str, use_agent: bool = True) -> tuple[GateResult, RedTeamResult]:
    diff = branch_diff(working_dir)
    files = changed_files(working_dir)
    scanner = (detect_test_tampering(diff) + detect_protected_changes(files)
               + detect_gate_config_drift(working_dir, files) + ruff_security_scan(working_dir, files))
    # Advisory only: re-orders what the agent reads first, never adds/drops/reclassifies a
    # finding. Falls back to original order if Jev triage errors (jev.triage_findings no-ops safely).
    scanner = [f for f, _ in triage_findings(scanner)]
    result = RedTeamResult(findings=list(scanner), summary="")

    if use_agent and diff.strip():
        diff_path = write_input_file(adw_id, "redteam_diff.patch",
                                     fence_untrusted(diff, "branch_diff", max_chars=len(diff) + 1))
        scan_path = write_input_file(adw_id, "redteam_scanner.json",
                                     json.dumps([f.model_dump() for f in scanner], indent=2))
        resp = execute_template(AgentRequest(
            adw_id=adw_id, agent_name="red_team", slash_command="/redteam",
            args=[adw_id, diff_path, spec_file or "", scan_path], working_dir=working_dir, allow_cache=True,
        ))
        if not resp.success:
            return GateResult(name="redteam", status="error", detail=f"red-team agent failed: {resp.output[:500]}"), result
        try:
            agent_result = parse_json(resp.output, RedTeamResult)
        except ValueError as exc:
            return GateResult(name="redteam", status="failed", detail=f"unparseable red-team output: {exc}"), result
        result.summary = agent_result.summary
        result.findings += [f.model_copy(update={"source": "agent"}) for f in agent_result.findings]

    blocking = result.blocking
    status: GateStatus = "failed" if blocking else "passed"
    detail = f"{len(result.findings)} findings, {len(blocking)} blocking"
    if blocking:
        detail += ": " + "; ".join(f"[{f.severity}] {f.title} ({f.file})" for f in blocking[:10])
    return GateResult(name="redteam", status=status, detail=detail), result
