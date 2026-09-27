#!/usr/bin/env -S uv run
"""Document phase (isolated): feature docs + conditional_docs entry, then KPIs and lessons.

Usage: uv run adws/adw_document_iso.py --adw-id ab12cd34
"""

from __future__ import annotations

import argparse
import json

from adws.adw_modules import telemetry
from adws.adw_modules import workflow_ops as ops
from adws.adw_modules.agent import execute_template, write_input_file
from adws.adw_modules.cli import main_wrapper, require_state
from adws.adw_modules.data_types import AgentRequest
from adws.adw_modules.git_ops import diff_stat
from adws.adw_modules.kpis import row_from_state, upsert
from adws.adw_modules.memory import Lesson, write_lesson
from adws.adw_modules.security import resolve_inside
from adws.adw_modules.state import ADWState
from adws.adw_modules.utils import parse_json
from adws.adw_modules.worktree_ops import validate_worktree

WORKFLOW = "adw_document_iso"


def record_kpis(state: ADWState, shipped: bool = False) -> None:
    wt = state.working_dir()
    plan_size = 0
    if state.data.plan_file:
        plan = resolve_inside(wt, state.data.plan_file)
        plan_size = len(plan.read_text().splitlines()) if plan.exists() else 0
    upsert(row_from_state(state, diff_stat(wt), plan_size, shipped=shipped))


def reflect(state: ADWState) -> int:
    """Write durable lessons when the run needed repairs or hit review blockers."""
    events = telemetry.read_events(state.adw_id)
    repairs = [e for e in events if e["event_type"] == "repair" and "attempt 1:" not in e["message"]]
    failed_gates = [g.model_dump() for g in (state.data.gate_report.gates if state.data.gate_report else [])
                    if g.status == "failed"]
    reviews = sorted(state.dir.glob("review_*.json"))
    if not repairs and not failed_gates and len(reviews) <= 1:
        return 0
    summary = {"adw_id": state.adw_id, "domain": state.data.domain, "issue_class": state.data.issue_class,
               "phases": state.data.phases, "repair_events": [e["message"] for e in repairs][:30],
               "failed_gates": failed_gates, "review_rounds": len(reviews), "cost_usd": state.data.usage.cost_usd}
    path = write_input_file(state.adw_id, "run_summary.json", json.dumps(summary, indent=2))
    resp = execute_template(AgentRequest(adw_id=state.adw_id, agent_name="reflector", slash_command="/reflect",
                                         args=[state.adw_id, path]))
    if not resp.success:
        return 0
    try:
        lessons = parse_json(resp.output, list[Lesson])
    except ValueError:
        return 0
    for lesson in lessons[:3]:
        write_lesson(lesson.model_copy(update={"source_adw": state.adw_id}))
        telemetry.emit(state.adw_id, "lesson", message=lesson.title)
    return len(lessons[:3])


def run(adw_id: str) -> bool:
    state = require_state(adw_id)
    state.append_adw(WORKFLOW)
    state.save()
    ok, err = validate_worktree(state)
    if not ok:
        raise ops.WorkflowError(err)
    wt = state.working_dir()
    with ops.phase(state, "document"):
        if diff_stat(wt)["files"] == 0:
            ops.notify(state, "no changes to document")
        else:
            slug = (state.data.branch_name or state.adw_id).split(f"adw-{state.adw_id}-")[-1]
            doc_rel = f"docs/features/{slug}-{state.adw_id}.md"
            shots = str(state.dir / "reviewer_0" / "review_img")
            resp = execute_template(AgentRequest(adw_id=adw_id, agent_name="documenter", slash_command="/document",
                                                 args=[adw_id, state.data.plan_file or "", doc_rel, shots], working_dir=wt))
            if not resp.success or not resolve_inside(wt, doc_rel).exists():
                raise ops.WorkflowError(f"documenter did not write {doc_rel}")
            ops.commit(state, "documenter", "add feature documentation")
            ops.publish(state, f"{(state.data.issue_class or '/chore').lstrip('/')}: {state.data.issue_title or ''}"[:120],
                        ops.pr_body(state))
            ops.notify(state, f"docs written: `{doc_rel}`")
        state.reload()
        record_kpis(state)
        reflect(state)
    return True


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--adw-id", required=True)
    a = p.parse_args()
    main_wrapper(lambda: run(a.adw_id), lambda: a.adw_id)


if __name__ == "__main__":
    main()
