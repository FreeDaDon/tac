"""Deterministic validation gates. A gate that cannot produce a trustworthy verdict FAILS.

Gate commands are loaded from the main checkout's pyproject.toml ([tool.tac.gates]) and
executed inside the worktree. Unit-test results come from pytest's JUnit XML, not from
an agent's self-report.
"""

from __future__ import annotations

import subprocess
import time
import tomllib
import xml.etree.ElementTree as ET  # noqa: S405 - parsing our own pytest output
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from .data_types import GateReport, GateResult, GateStatus, TestResult
from .git_ops import git
from .security import untrusted_code_env
from .utils import project_root

GATE_TIMEOUT_S = 1800
ZTE_REQUIRED_GATES = ["lint", "types", "unit", "client", "e2e", "spec_review", "redteam", "secret_scan"]
TEST_GATES = ("lint", "types", "unit", "client", "e2e")
# Files the document phase writes after the code gates ran; a gate stays fresh across these.
DEFAULT_POST_GATE_PATHS = ["docs/features/*", ".claude/commands/conditional_docs.md"]


def tac_config() -> dict[str, Any]:
    data = tomllib.loads((project_root() / "pyproject.toml").read_text())
    return dict(data.get("tool", {}).get("tac", {}))


def gate_commands() -> dict[str, list[str]]:
    gates = tac_config().get("gates", {})
    return {name: list(cmd) for name, cmd in gates.items()}


def head_sha(cwd: str | Path) -> str:
    return git("rev-parse", "HEAD", cwd=cwd, check=False)


def stamp(gate: GateResult, cwd: str | Path) -> GateResult:
    """Bind a verdict to the commit it judged, so a later commit makes it stale. Call it after the
    phase commits whatever it tested; a verdict on a dirty tree belongs to the commit that records it."""
    return gate.model_copy(update={"head_sha": head_sha(cwd)})


def stale_gates(report: GateReport, cwd: str | Path, names: list[str] | tuple[str, ...]) -> list[str]:
    """Gates whose verdict predates a code change. Changes confined to post_gate_paths don't count."""
    head = head_sha(cwd)
    allowed = list(tac_config().get("post_gate_paths", DEFAULT_POST_GATE_PATHS))
    stale = []
    for name in names:
        gate = report.get(name)
        if gate is None or gate.status not in ("passed", "skipped") or gate.head_sha == head:
            continue
        if not gate.head_sha:
            stale.append(name)
            continue
        proc = subprocess.run(["git", "diff", "--name-only", gate.head_sha, "HEAD"], cwd=str(cwd),
                              capture_output=True, text=True, timeout=60)
        changed = proc.stdout.split()
        if proc.returncode != 0 or any(not any(fnmatch(f, pat) for pat in allowed) for f in changed):
            stale.append(name)
    return stale


def run_command_gate(name: str, argv: list[str], cwd: str | Path, timeout: int = GATE_TIMEOUT_S) -> tuple[GateResult, str]:
    started = time.monotonic()
    try:
        proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True, timeout=timeout,
                              env=untrusted_code_env())
        output = (proc.stdout + "\n" + proc.stderr).strip()
        status: GateStatus = "passed" if proc.returncode == 0 else "failed"
        detail = "" if status == "passed" else output[-4000:]
    except subprocess.TimeoutExpired:
        output, status, detail = "", "failed", f"timed out after {timeout}s"
    except OSError as exc:
        output, status, detail = "", "error", f"could not run {argv[0]}: {exc}"
    return GateResult(name=name, status=status, detail=detail, duration_s=round(time.monotonic() - started, 2)), output


def parse_junit(xml_text: str) -> list[TestResult]:
    """JUnit XML -> TestResult list. Raises ValueError when the report is unusable."""
    try:
        root = ET.fromstring(xml_text)  # noqa: S314 - generated locally by pytest
    except ET.ParseError as exc:
        raise ValueError(f"unparseable junit xml: {exc}") from exc
    results: list[TestResult] = []
    for case in root.iter("testcase"):
        classname = case.get("classname", "")
        name = case.get("name", "")
        node = f"{classname.replace('.', '/')}.py::{name}" if classname else name
        failure = case.find("failure")
        if failure is None:
            failure = case.find("error")
        skipped = case.find("skipped")
        error = None
        if failure is not None:
            error = ((failure.get("message") or "") + "\n" + (failure.text or ""))[-3000:]
        elif skipped is not None:
            error = f"skipped ({skipped.get('message') or 'no reason'}); a skip is not a pass unless listed in " \
                    "[tool.tac].allowed_skips of the main checkout"
        results.append(
            TestResult(
                test_name=node,
                passed=failure is None and skipped is None,
                execution_command=f"uv run pytest -q '{node}'",
                test_purpose="skipped" if skipped is not None else "",
                error=error,
            )
        )
    if not results:
        raise ValueError("junit report contains no test cases")
    return results


def run_unit_tests(cwd: str | Path, report_dir: Path) -> tuple[GateResult, list[TestResult]]:
    argv = gate_commands().get("unit")
    if not argv:
        return GateResult(name="unit", status="error", detail="no [tool.tac.gates].unit configured"), []
    report_dir.mkdir(parents=True, exist_ok=True)
    junit = report_dir / "junit.xml"
    junit.unlink(missing_ok=True)
    gate, output = run_command_gate("unit", [*argv, f"--junitxml={junit}"], cwd)
    if not junit.exists():
        # no report = no verdict = failure (tac-7 treated this as a pass)
        gate.status = "failed"
        gate.detail = "pytest produced no junit report\n" + output[-3000:]
        return gate, [TestResult(test_name="unit_suite", passed=False, execution_command=" ".join(argv),
                                 error=gate.detail)]
    try:
        results = parse_junit(junit.read_text())
    except ValueError as exc:
        gate.status = "failed"
        gate.detail = str(exc)
        return gate, [TestResult(test_name="unit_suite", passed=False, execution_command=" ".join(argv), error=str(exc))]
    allowed_skips = set(tac_config().get("allowed_skips", []))
    results = [r.model_copy(update={"passed": True, "error": None})
               if r.test_purpose == "skipped" and r.test_name in allowed_skips else r for r in results]
    failed = [r for r in results if not r.passed]
    if failed and gate.status == "passed":
        gate.status = "failed"
    if not failed and gate.status == "failed":
        # suite exited non-zero without a failing case (collection error, etc.)
        results.append(TestResult(test_name="unit_suite", passed=False, execution_command=" ".join(argv),
                                  error=output[-3000:]))
    gate.detail = f"{len(results) - len(failed)}/{len(results)} passed" + (
        "" if not failed else "; failing: " + ", ".join(r.test_name for r in failed[:10]))
    return gate, results


def run_secret_scan(cwd: str | Path) -> GateResult:
    """Scan the worktree with the deterministic secret scanner (core.security.secret_scan)."""
    try:
        from core.registry import run_pack
    except ImportError as exc:
        return GateResult(name="secret_scan", status="error", detail=f"secret scanner unavailable: {exc}")
    # The worktree's own .secretsallow is agent-editable; only the main checkout's allowlist is trusted.
    trusted = project_root() / ".secretsallow"
    opts: dict[str, Any] = ({"allowlist": str(trusted), "allowlist_root": str(cwd)} if trusted.is_file()
                            else {"use_allowlist": False})
    reports = run_pack("swe", Path(cwd), tool="secret_scan", **opts)
    findings = [f for r in reports for f in r.findings]
    if findings:
        lines = [f"{f.rule_id} {f.location or f.resource}: {f.title}" for f in findings[:20]]
        return stamp(GateResult(name="secret_scan", status="failed", detail="\n".join(lines)), cwd)
    return stamp(GateResult(name="secret_scan", status="passed", detail="no secrets found"), cwd)
