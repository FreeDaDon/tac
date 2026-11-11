#!/usr/bin/env -S uv run
"""Full isolated SDLC: plan -> build -> test -> review -> document -> redteam. Stops at the first
failed phase (tac-7 carried on after failed tests). Never merges; see adw_sdlc_zte_iso.py.

Every gate verdict is bound to the commit it judged. When review patches change code after the
tests ran, test and review re-run until no verdict is stale. Red team runs last, on the final diff.

Usage:
  uv run adws/adw_sdlc_iso.py --issue 42 [--model-set heavy] [--skip-e2e]
  uv run adws/adw_sdlc_iso.py --issue-file specs/examples/issue.md
  uv run adws/adw_sdlc_iso.py --adw-id ab12cd34 --resume      # continue after the last passed phase
"""

from __future__ import annotations

import argparse
from collections.abc import Callable

from adws import adw_build_iso, adw_document_iso, adw_plan_iso, adw_redteam_iso, adw_review_iso, adw_test_iso
from adws.adw_modules import telemetry
from adws.adw_modules.cli import main_wrapper
from adws.adw_modules.gates import TEST_GATES, stale_gates
from adws.adw_modules.state import ADWState

PHASES = ("plan", "build", "test", "review", "document", "redteam")
MAX_REVERIFY_ROUNDS = 2


def reverify(adw_id: str, skip_e2e: bool) -> bool:
    """Re-run test and review until every verdict judges the current commit."""
    for _ in range(MAX_REVERIFY_ROUNDS):
        state = ADWState.load(adw_id)
        if state is None:
            return False
        wt = state.working_dir()
        report = state.gate_report()
        if stale_gates(report, wt, TEST_GATES):
            telemetry.emit(adw_id, "pipeline", message="code changed after tests; re-running test phase")
            if not adw_test_iso.run(adw_id, skip_e2e=skip_e2e):
                return False
            continue
        if stale_gates(report, wt, ["spec_review"]):
            telemetry.emit(adw_id, "pipeline", message="code changed after review; re-running review phase")
            if not adw_review_iso.run(adw_id):
                return False
            continue
        return True
    state = ADWState.load(adw_id)
    return state is not None and not stale_gates(state.gate_report(), state.working_dir(), [*TEST_GATES, "spec_review"])


def run_pipeline(args: argparse.Namespace) -> tuple[bool, str]:
    adw_id: str = args.adw_id or ""
    done: set[str] = set()
    if args.resume and adw_id:
        state = ADWState.load(adw_id)
        done = {p for p, s in (state.data.phases.items() if state else []) if s == "passed"}

    steps: dict[str, Callable[[], bool]] = {
        "build": lambda: adw_build_iso.run(adw_id),
        "test": lambda: adw_test_iso.run(adw_id, skip_e2e=args.skip_e2e),
        "review": lambda: adw_review_iso.run(adw_id) and reverify(adw_id, args.skip_e2e),
        "redteam": lambda: adw_redteam_iso.run(adw_id),
        "document": lambda: adw_document_iso.run(adw_id),
    }
    if "plan" not in done:
        adw_id = adw_plan_iso.run(args.issue, args.issue_file, args.adw_id, args.model_set)
        args.adw_id = adw_id
    for name in PHASES[1:]:
        if name in done:
            continue
        if not steps[name]():
            telemetry.emit(adw_id, "pipeline", message=f"stopped: {name} failed", phase=name)
            print(f"pipeline stopped: {name} failed (adw_id {adw_id}; resume with --adw-id {adw_id} --resume)")
            return False, adw_id
    telemetry.emit(adw_id, "pipeline", message="sdlc complete")
    print(f"sdlc complete: adw_id {adw_id}")
    return True, adw_id


def build_parser(doc: str | None) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=doc, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--issue")
    p.add_argument("--issue-file")
    p.add_argument("--adw-id")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--model-set", choices=["base", "heavy"], default="base")
    p.add_argument("--skip-e2e", action="store_true", help="recorded in state; blocks Zero-Touch shipping")
    return p


def main() -> None:
    p = build_parser(__doc__)
    a = p.parse_args()
    if not (a.issue or a.issue_file or (a.adw_id and a.resume)):
        p.error("provide --issue, --issue-file, or --adw-id with --resume")
    main_wrapper(lambda: run_pipeline(a)[0], lambda: a.adw_id)


if __name__ == "__main__":
    main()
