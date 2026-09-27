#!/usr/bin/env -S uv run
"""Plan phase (isolated): issue -> classify -> branch -> worktree + ports -> spec plan -> commit -> PR.

Usage:
  uv run adws/adw_plan_iso.py --issue 42 [--adw-id ab12cd34] [--model-set heavy]
  uv run adws/adw_plan_iso.py --issue-file specs/examples/issue.md
"""

from __future__ import annotations

import argparse

from adws.adw_modules import workflow_ops as ops
from adws.adw_modules.budget import default_budget_usd
from adws.adw_modules.cli import main_wrapper
from adws.adw_modules.data_types import ModelSet
from adws.adw_modules.security import validate_adw_id
from adws.adw_modules.state import ADWState
from adws.adw_modules.utils import make_adw_id
from adws.adw_modules.worktree_ops import allocate_ports, create_worktree, setup_environment

WORKFLOW = "adw_plan_iso"


def run(issue: str | None, issue_file: str | None, adw_id: str | None = None,
        model_set: ModelSet = "base", issue_class: str | None = None) -> str:
    """Returns the adw_id. Raises on failure."""
    adw_id = validate_adw_id(adw_id) if adw_id else make_adw_id()
    state = ADWState.load_or_create(adw_id, model_set=model_set, budget_usd=default_budget_usd(), domain="swe")
    state.append_adw(WORKFLOW)
    state.save()

    with ops.phase(state, "plan"):
        payload = ops.load_issue(issue, issue_file)
        issue_path = ops.write_issue_input(adw_id, payload)
        state.update(issue_number=payload.number, issue_title=payload.title)
        state.save()

        cls = issue_class or state.data.issue_class or ops.classify_issue(state, issue_path)
        if cls == "/patch":
            cls = "/bug"  # a patch request on a fresh run is planned as a narrow bug fix
        branch = state.data.branch_name or ops.make_branch_name(state, cls, issue_path, payload.number)
        backend, frontend = (state.data.backend_port, state.data.frontend_port)
        if not backend or not frontend:
            backend, frontend = allocate_ports(adw_id)
        wt = create_worktree(adw_id, branch)
        setup_environment(wt, backend, frontend, adw_id)
        state.update(issue_class=cls, branch_name=branch, worktree_path=str(wt),
                     backend_port=backend, frontend_port=frontend)
        state.save()
        ops.notify(state, f"planning started (class {cls}, branch `{branch}`)")

        plan_rel = ops.build_plan(state, cls, issue_path, ops.plan_path_for(branch))
        state.update(plan_file=plan_rel)
        state.save()
        ops.commit(state, "sdlc_planner", f"add plan for {payload.title[:40]}")
        url = ops.publish(state, f"{cls.lstrip('/')}: #{payload.number} {payload.title}"[:120], ops.pr_body(state))
        if url:
            state.update(pr_url=url)
            state.save()
        ops.notify(state, f"plan ready: `{plan_rel}`")
    return adw_id


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--issue", help="GitHub issue number")
    src.add_argument("--issue-file", help="local markdown issue (first '# ' line is the title)")
    p.add_argument("--adw-id")
    p.add_argument("--model-set", choices=["base", "heavy"], default="base")
    a = p.parse_args()

    def entry() -> bool:
        print(run(a.issue, a.issue_file, a.adw_id, a.model_set))
        return True

    main_wrapper(entry, lambda: a.adw_id)


if __name__ == "__main__":
    main()
