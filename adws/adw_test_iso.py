#!/usr/bin/env -S uv run
"""Test phase (isolated): deterministic gates + narrow repair loops, then E2E with repair.

Gates (from the main checkout's [tool.tac.gates]): lint, types, unit (JUnit-parsed), client.
Every failing check becomes one focused /resolve_failed_test call; loops stop on no progress.
E2E runs by default; --skip-e2e is recorded and blocks Zero-Touch shipping.

Usage: uv run adws/adw_test_iso.py --adw-id ab12cd34 [--skip-e2e]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from adws.adw_modules import telemetry
from adws.adw_modules import workflow_ops as ops
from adws.adw_modules.agent import execute_template, write_input_file
from adws.adw_modules.app_runner import running_app
from adws.adw_modules.cli import main_wrapper, require_state
from adws.adw_modules.data_types import AgentRequest, E2ETestResult, GateResult, TestResult
from adws.adw_modules.gates import gate_commands, run_command_gate, run_unit_tests, tac_config
from adws.adw_modules.repair import repair_loop
from adws.adw_modules.state import ADWState
from adws.adw_modules.utils import parse_json, project_root
from adws.adw_modules.worktree_ops import validate_worktree

WORKFLOW = "adw_test_iso"
STATIC_GATES = ("lint", "types", "client")


def _check_suite(state: ADWState) -> tuple[list[TestResult], dict[str, GateResult]]:
    """Run every configured gate once; return per-check results for the repair loop plus gate verdicts."""
    wt = state.working_dir()
    results: list[TestResult] = []
    verdicts: dict[str, GateResult] = {}
    commands = gate_commands()
    for name in STATIC_GATES:
        argv = commands.get(name)
        if not argv:
            continue
        if name == "client" and not (Path(wt) / "app" / "client" / "package.json").exists():
            verdicts[name] = GateResult(name=name, status="skipped", detail="no client app", required_for_zte=False)
            continue
        gate, _ = run_command_gate(name, argv, wt)
        verdicts[name] = gate
        results.append(TestResult(test_name=f"gate:{name}", passed=gate.status == "passed",
                                  execution_command=" ".join(argv), test_purpose=f"{name} gate", error=gate.detail or None))
    unit_gate, unit_results = run_unit_tests(wt, state.dir / "test_reports")
    verdicts["unit"] = unit_gate
    results.extend(unit_results)
    return results, verdicts


def run_checks_with_repair(state: ADWState) -> bool:
    cfg = tac_config()
    latest: dict[str, GateResult] = {}

    def run_once() -> list[TestResult]:
        results, verdicts = _check_suite(state)
        latest.clear()
        latest.update(verdicts)
        return results

    passed, _ = repair_loop(state.adw_id, state.working_dir(), run_once, "/resolve_failed_test",
                            int(cfg.get("max_test_repairs", 4)), label="test")
    state.reload()
    report = state.gate_report()
    for gate in latest.values():
        report.upsert(gate)
    state.save()
    return passed and all(g.status in ("passed", "skipped") for g in latest.values())


def _e2e_specs() -> list[Path]:
    spec_dir = project_root() / str(tac_config().get("e2e_specs", ".claude/commands/e2e"))
    return sorted(spec_dir.glob("test_*.md")) if spec_dir.exists() else []


def run_e2e_with_repair(state: ADWState) -> GateResult:
    specs = _e2e_specs()
    if not specs:
        return GateResult(name="e2e", status="skipped", detail="no e2e specs", required_for_zte=False)
    if not state.data.backend_port:
        return GateResult(name="e2e", status="error", detail="no port allocated for this run")
    wt = state.working_dir()
    max_repairs = int(tac_config().get("max_e2e_repairs", 2))

    def run_all(url: str, attempt: int) -> list[E2ETestResult]:
        out = []
        for i, spec in enumerate(specs):
            resp = execute_template(AgentRequest(
                adw_id=state.adw_id, agent_name=f"e2e_runner_{attempt}_{i}", slash_command="/test_e2e",
                args=[state.adw_id, f"e2e_runner_{attempt}_{i}", str(spec), url], working_dir=wt))
            try:
                if not resp.success:
                    raise ValueError(resp.output[:500])
                out.append(parse_json(resp.output, E2ETestResult))
            except ValueError as exc:
                out.append(E2ETestResult(test_name=spec.stem, status="failed", test_path=str(spec),
                                         error=f"no valid result: {exc}"))
        return out

    results: list[E2ETestResult] = []
    with running_app(wt, state.data.backend_port, state.dir / "app.log") as url:
        for attempt in range(max_repairs + 1):
            results = run_all(url, attempt)
            failed = [r for r in results if not r.passed]
            telemetry.emit(state.adw_id, "repair", phase="e2e", message=f"attempt {attempt}: {len(failed)} failing")
            if not failed or attempt == max_repairs:
                break
            for i, r in enumerate(failed):
                path = write_input_file(state.adw_id, f"e2e_failure_{attempt}_{i}.json",
                                        json.dumps(r.model_dump(), indent=2))
                execute_template(AgentRequest(adw_id=state.adw_id, agent_name=f"e2e_resolver_{attempt}_{i}",
                                              slash_command="/resolve_failed_e2e_test", args=[path], working_dir=wt))
    failed = [r for r in results if not r.passed]
    return GateResult(name="e2e", status="failed" if failed else "passed",
                      detail=f"{len(results) - len(failed)}/{len(results)} passed"
                      + ("" if not failed else ": " + ", ".join(r.test_name for r in failed)))


def run(adw_id: str, skip_e2e: bool = False) -> bool:
    state = require_state(adw_id)
    state.append_adw(WORKFLOW)
    state.save()
    ok, err = validate_worktree(state)
    if not ok:
        raise ops.WorkflowError(err)

    with ops.phase(state, "test"):
        checks_ok = run_checks_with_repair(state)
        ops.commit(state, "test_resolver", "fix failing checks")
        if skip_e2e:
            e2e = GateResult(name="e2e", status="skipped", detail="skipped by operator (--skip-e2e)")
        else:
            e2e = run_e2e_with_repair(state)
            ops.commit(state, "e2e_resolver", "fix failing e2e tests")
        state.reload()
        state.gate_report().upsert(e2e)
        state.update(e2e_skipped=skip_e2e)
        passed = checks_ok and e2e.status in ("passed", "skipped")
        if not passed:
            state.set_phase("test", "failed")
        state.save()
        summary = ", ".join(f"{g.name}={g.status}" for g in state.gate_report().gates)
        ops.notify(state, f"tests {'passed' if passed else 'FAILED'}: {summary}")
        ops.publish(state, f"{(state.data.issue_class or '/chore').lstrip('/')}: {state.data.issue_title or ''}"[:120],
                    ops.pr_body(state))
    return passed


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--adw-id", required=True)
    p.add_argument("--skip-e2e", action="store_true")
    a = p.parse_args()
    main_wrapper(lambda: run(a.adw_id, a.skip_e2e), lambda: a.adw_id)


if __name__ == "__main__":
    main()
