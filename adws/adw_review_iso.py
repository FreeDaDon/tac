#!/usr/bin/env -S uv run
"""Review phase (isolated): "is what we built what we planned?"

Review against the spec -> patch each blocker -> re-review. A final review always runs after
the last patch, and unresolved blockers FAIL the phase (tac-7 exited 0 here).

Usage: uv run adws/adw_review_iso.py --adw-id ab12cd34 [--skip-resolution]
"""

from __future__ import annotations

import argparse
import json

from adws.adw_modules import workflow_ops as ops
from adws.adw_modules.agent import execute_template, write_input_file
from adws.adw_modules.cli import main_wrapper, require_state
from adws.adw_modules.data_types import AgentRequest, GateResult, ReviewResult
from adws.adw_modules.gates import tac_config
from adws.adw_modules.git_ops import branch_diff
from adws.adw_modules.jev import triage_findings
from adws.adw_modules.state import ADWState
from adws.adw_modules.utils import parse_json
from adws.adw_modules.worktree_ops import validate_worktree

WORKFLOW = "adw_review_iso"


def review_once(state: ADWState, attempt: int) -> ReviewResult:
    wt = state.working_dir()
    diff_path = write_input_file(state.adw_id, f"review_diff_{attempt}.patch", branch_diff(wt))
    agent = f"reviewer_{attempt}"
    resp = execute_template(AgentRequest(adw_id=state.adw_id, agent_name=agent, slash_command="/review",
                                         args=[state.adw_id, state.data.plan_file or "", agent, diff_path],
                                         working_dir=wt, allow_cache=True))
    if not resp.success:
        raise ops.WorkflowError(f"review agent failed: {resp.output[:300]}")
    try:
        return parse_json(resp.output, ReviewResult)
    except ValueError as exc:
        raise ops.WorkflowError(f"unparseable review output: {exc}") from exc


def run(adw_id: str, skip_resolution: bool = False) -> bool:
    state = require_state(adw_id)
    state.append_adw(WORKFLOW)
    state.save()
    ok, err = validate_worktree(state)
    if not ok:
        raise ops.WorkflowError(err)
    max_patches = 0 if skip_resolution else int(tac_config().get("max_review_patches", 2))

    with ops.phase(state, "review"):
        result: ReviewResult | None = None
        gate: GateResult | None = None
        for attempt in range(max_patches + 1):
            try:
                result = review_once(state, attempt)
            except ops.WorkflowError as exc:
                gate = GateResult(name="spec_review", status="failed", detail=str(exc))
                break
            # Advisory only: re-orders blocker/tech_debt/skippable for the persisted JSON and
            # dashboard (worst first). Never changes which issues exist or the blocker gate verdict.
            result.review_issues = [i for i, _ in triage_findings(result.review_issues, severity_of=lambda i: i.issue_severity)]
            (state.dir / f"review_{attempt}.json").write_text(result.model_dump_json(indent=2))
            if not result.blockers:
                break
            if attempt == max_patches:
                break
            for n, issue in enumerate(result.blockers):
                req = write_input_file(state.adw_id, f"review_issue_{attempt}_{n}.json",
                                       json.dumps(issue.model_dump(), indent=2))
                patch_rel = f"specs/patch/{state.data.branch_name}-review-{attempt}-{n}.md"
                resp = execute_template(AgentRequest(
                    adw_id=state.adw_id, agent_name=f"review_patch_planner_{attempt}_{n}", slash_command="/patch",
                    args=[state.adw_id, req, state.data.plan_file or "", patch_rel], working_dir=state.working_dir()))
                if not resp.success:
                    continue
                state.update(patch_file=patch_rel)
                state.save()
                ops.implement_plan(state, patch_rel, agent_name=f"review_patcher_{attempt}_{n}")
                ops.commit(state, f"review_patcher_{attempt}_{n}", f"resolve review blocker {issue.review_issue_number}")
        if gate is None and result is not None:
            blockers = result.blockers
            gate = GateResult(
                name="spec_review", status="failed" if blockers else "passed",
                detail=result.review_summary[:1000] + ("" if not blockers else
                       f"\nUnresolved blockers: {[b.issue_description[:100] for b in blockers]}"))
        if gate is None:
            gate = GateResult(name="spec_review", status="error", detail="review produced no result")
        state.reload()
        state.gate_report().upsert(gate)
        if gate.status != "passed":
            state.set_phase("review", "failed")
        state.save()
        ops.notify(state, f"review {gate.status}: {gate.detail[:500]}")
    return gate is not None and gate.status == "passed"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--adw-id", required=True)
    p.add_argument("--skip-resolution", action="store_true")
    a = p.parse_args()
    main_wrapper(lambda: run(a.adw_id, a.skip_resolution), lambda: a.adw_id)


if __name__ == "__main__":
    main()
