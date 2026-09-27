#!/usr/bin/env -S uv run
"""Build phase (isolated): implement the plan inside the run's worktree, commit, push.

Usage: uv run adws/adw_build_iso.py --adw-id ab12cd34
"""

from __future__ import annotations

import argparse

from adws.adw_modules import workflow_ops as ops
from adws.adw_modules.cli import main_wrapper, require_state
from adws.adw_modules.worktree_ops import validate_worktree

WORKFLOW = "adw_build_iso"


def run(adw_id: str) -> bool:
    state = require_state(adw_id)
    state.append_adw(WORKFLOW)
    state.save()
    ok, err = validate_worktree(state)
    if not ok:
        raise ops.WorkflowError(err)
    if not state.data.plan_file:
        raise ops.WorkflowError("no plan_file in state; run the plan phase first")
    with ops.phase(state, "build"):
        summary = ops.implement_plan(state, state.data.plan_file)
        ops.commit(state, "sdlc_implementor", "implement plan")
        ops.publish(state, f"{(state.data.issue_class or '/chore').lstrip('/')}: {state.data.issue_title or ''}"[:120],
                    ops.pr_body(state))
        ops.notify(state, "build complete:\n" + summary[:1500])
    return True


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--adw-id", required=True)
    a = p.parse_args()
    main_wrapper(lambda: run(a.adw_id), lambda: a.adw_id)


if __name__ == "__main__":
    main()
