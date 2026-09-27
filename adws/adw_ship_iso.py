#!/usr/bin/env -S uv run
"""Ship phase: server-side squash merge of the run's PR, only when every lock is open.

Locks (all required):
  1. TAC_ZTE_ENABLED=1
  2. domain ship policy allows auto-merge (swe only; devops/iam are pr_only, soc report_only)
  3. every required gate in the persisted GateReport passed (E2E not skipped)
  4. run budget not exhausted
  5. a GitHub PR exists and its CI checks are green
The main working copy is never checked out or modified (tac-7 merged locally on main).

Usage: uv run adws/adw_ship_iso.py --adw-id ab12cd34 [--dry-run]
"""

from __future__ import annotations

import argparse

from adws.adw_modules import github, telemetry
from adws.adw_modules import workflow_ops as ops
from adws.adw_modules.budget import Budget
from adws.adw_modules.cli import main_wrapper, require_state
from adws.adw_modules.domains import get_domain
from adws.adw_modules.git_ops import has_remote
from adws.adw_modules.state import ADWState
from adws.adw_modules.utils import env_flag

WORKFLOW = "adw_ship_iso"


def ship_blockers(state: ADWState, check_remote: bool = True) -> list[str]:
    d = state.data
    domain = get_domain(d.domain)
    reasons: list[str] = []
    if not env_flag("TAC_ZTE_ENABLED"):
        reasons.append("TAC_ZTE_ENABLED is not set")
    if not domain.zte_allowed:
        reasons.append(f"domain '{d.domain}' ship policy is {domain.ship_policy}")
    report = d.gate_report
    if report is None:
        reasons.append("no gate report persisted")
    else:
        missing = report.missing(list(domain.required_gates))
        # a gate legitimately skipped because it does not apply (e.g. no client app) is not required
        missing = [m for m in missing if not ((g := report.get(m)) and g.status == "skipped" and not g.required_for_zte)]
        if missing:
            reasons.append(f"gates not passed: {missing}")
    if d.e2e_skipped:
        reasons.append("E2E was skipped")
    if Budget(d.budget_usd, d.usage).exhausted:
        reasons.append("budget exhausted")
    if check_remote:
        if not d.branch_name or not has_remote(state.working_dir()):
            reasons.append("no GitHub remote/branch to merge")
        elif not github.find_pr(d.branch_name):
            reasons.append("no pull request found")
        elif not github.pr_checks_green(d.branch_name):
            reasons.append("PR checks are not green")
    return reasons


def run(adw_id: str, dry_run: bool = False) -> bool:
    state = require_state(adw_id)
    state.append_adw(WORKFLOW)
    state.save()
    with ops.phase(state, "ship"):
        blockers = ship_blockers(state, check_remote=not dry_run)
        if blockers:
            telemetry.emit(adw_id, "gate", phase="ship", message="ship blocked", blockers=blockers)
            ops.notify(state, "ship blocked:\n- " + "\n- ".join(blockers))
            state.reload()
            state.set_phase("ship", "failed")
            state.save()
            print("ship blocked:\n- " + "\n- ".join(blockers))
            return False
        if dry_run:
            print("all ship locks open (dry run; nothing merged)")
            return True
        github.merge_pr(state.data.branch_name or "")
        from adws.adw_document_iso import record_kpis

        state.reload()
        record_kpis(state, shipped=True)
        ops.notify(state, "shipped: PR squash-merged by Zero-Touch Engineering")
    return True


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--adw-id", required=True)
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()
    main_wrapper(lambda: run(a.adw_id, a.dry_run), lambda: a.adw_id)


if __name__ == "__main__":
    main()
