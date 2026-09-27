#!/usr/bin/env -S uv run
"""Red-team phase (isolated): adversarial agent + deterministic scanners + secret scan.

Fails on any critical/high finding, including "spec cheating" (weakened/skipped tests).

Usage: uv run adws/adw_redteam_iso.py --adw-id ab12cd34 [--no-agent]
"""

from __future__ import annotations

import argparse

from adws.adw_modules import workflow_ops as ops
from adws.adw_modules.cli import main_wrapper, require_state
from adws.adw_modules.gates import run_secret_scan
from adws.adw_modules.redteam import run_redteam
from adws.adw_modules.worktree_ops import validate_worktree

WORKFLOW = "adw_redteam_iso"


def run(adw_id: str, use_agent: bool = True) -> bool:
    state = require_state(adw_id)
    state.append_adw(WORKFLOW)
    state.save()
    ok, err = validate_worktree(state)
    if not ok:
        raise ops.WorkflowError(err)
    with ops.phase(state, "redteam"):
        gate, result = run_redteam(adw_id, state.working_dir(), state.data.plan_file or "", use_agent=use_agent)
        (state.dir / "redteam.json").write_text(result.model_dump_json(indent=2))
        secrets = run_secret_scan(state.working_dir())
        state.reload()
        state.gate_report().upsert(gate)
        state.gate_report().upsert(secrets)
        passed = gate.status == "passed" and secrets.status == "passed"
        if not passed:
            state.set_phase("redteam", "failed")
        state.save()
        ops.notify(state, f"red team {gate.status} ({gate.detail[:300]}); secret scan {secrets.status}")
    return passed


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--adw-id", required=True)
    p.add_argument("--no-agent", action="store_true", help="deterministic scanners only")
    a = p.parse_args()
    main_wrapper(lambda: run(a.adw_id, not a.no_agent), lambda: a.adw_id)


if __name__ == "__main__":
    main()
