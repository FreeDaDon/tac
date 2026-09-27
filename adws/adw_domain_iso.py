#!/usr/bin/env -S uv run
"""Domain pack workflow: deterministic analysis -> agent interpretation -> report (md/json/SARIF).

  devops: Terraform plan risk, drift, rollback plan       (ship policy: pr_only, never applies)
  soc:    auth/syslog, JSON events, Zeek, Sigma, vuln scans (report_only)
  iam:    policy lint, RBAC/ABAC, dormant accounts, revocation plan (pr_only, never revokes)
  swe:    secret scan of a directory

With --propose (pr_only packs), the report is committed to an isolated worktree branch and a PR
is opened for human approval.

Usage:
  uv run adws/adw_domain_iso.py --pack soc --input core/fixtures/soc/auth.log
  uv run adws/adw_domain_iso.py --pack iam --input core/fixtures/iam --propose
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from adws.adw_modules import telemetry
from adws.adw_modules import workflow_ops as ops
from adws.adw_modules.agent import execute_template, write_input_file
from adws.adw_modules.budget import default_budget_usd
from adws.adw_modules.cli import main_wrapper
from adws.adw_modules.data_types import AgentRequest, GateResult
from adws.adw_modules.domains import get_domain
from adws.adw_modules.security import validate_adw_id
from adws.adw_modules.state import ADWState
from adws.adw_modules.utils import agent_dir, make_adw_id, parse_json
from adws.adw_modules.worktree_ops import create_worktree

WORKFLOW = "adw_domain_iso"


def render_assessment(assessment: ops.DomainAssessment) -> str:
    from core.security.sanitize import escape_markdown

    lines = [f"## Agent assessment — risk: **{assessment.risk_rating}**", "", escape_markdown(assessment.summary), ""]
    if assessment.prioritized_actions:
        lines += ["| Priority | Action | Human approval | Findings |", "|---|---|---|---|"]
        for a in sorted(assessment.prioritized_actions, key=lambda x: x.priority):
            lines.append(f"| {a.priority} | {escape_markdown(a.title)} | {'required' if a.requires_human_approval else 'no'}"
                         f" | {escape_markdown(', '.join(a.finding_refs))} |")
    if assessment.false_positives:
        lines += ["", "### Likely false positives"]
        lines += [f"- `{escape_markdown(fp.finding_ref)}`: {escape_markdown(fp.reason)}" for fp in assessment.false_positives]
    return "\n".join(lines) + "\n"


def run(pack: str, input_path: str, adw_id: str | None = None, tool: str | None = None,
        use_agent: bool = True, propose: bool = False, fail_on: str | None = None) -> bool:
    from core.export.markdown import render_reports
    from core.export.sarif import to_sarif
    from core.registry import run_pack

    domain = get_domain(pack)
    adw_id = validate_adw_id(adw_id) if adw_id else make_adw_id()
    state = ADWState.load_or_create(adw_id, domain=pack, budget_usd=default_budget_usd())
    state.append_adw(WORKFLOW)
    state.save()
    out_dir = agent_dir() / "reports" / adw_id
    out_dir.mkdir(parents=True, exist_ok=True)

    with ops.phase(state, "analyze"):
        reports = run_pack(pack, Path(input_path), tool=tool)
        if not reports:
            raise ops.WorkflowError(f"no recognizable {pack} inputs at {input_path}")
        findings_json = json.dumps([r.model_dump() for r in reports], indent=2)
        (out_dir / "findings.json").write_text(findings_json)
        (out_dir / "findings.sarif").write_text(json.dumps(to_sarif(reports), indent=2))
        total = sum(len(r.findings) for r in reports)
        telemetry.emit(adw_id, "analysis", phase="analyze", message=f"{total} findings from {len(reports)} tools",
                       tools=[r.tool for r in reports])

    assessment_md = ""
    if use_agent and domain.analyze_command:
        with ops.phase(state, "interpret"):
            path = write_input_file(adw_id, "findings.json", findings_json)
            resp = execute_template(AgentRequest(adw_id=adw_id, agent_name=f"{pack}_analyst",
                                                 slash_command=domain.analyze_command, args=[adw_id, path]))
            if not resp.success:
                raise ops.WorkflowError(f"{domain.analyze_command} failed: {resp.output[:300]}")
            try:
                assessment = parse_json(resp.output, ops.DomainAssessment)
            except ValueError as exc:
                raise ops.WorkflowError(f"unparseable assessment: {exc}") from exc
            (out_dir / "assessment.json").write_text(assessment.model_dump_json(indent=2))
            assessment_md = render_assessment(assessment)

    report_md = render_reports(reports) + ("\n" + assessment_md if assessment_md else "")
    (out_dir / "report.md").write_text(report_md)
    print(f"report: {out_dir / 'report.md'}")

    if propose:
        if domain.ship_policy == "report_only":
            print(f"--propose ignored: {pack} ship policy is report_only")
        else:
            with ops.phase(state, "propose"):
                branch = f"chore-{pack}-review-adw-{adw_id}"
                wt = create_worktree(adw_id, branch)
                state.update(branch_name=branch, worktree_path=str(wt), issue_class="/chore")
                state.save()
                dest = wt / "reports" / pack / f"{adw_id}.md"
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(report_md)
                (dest.with_suffix(".sarif")).write_text((out_dir / "findings.sarif").read_text())
                from adws.adw_modules.git_ops import commit_all

                commit_all(f"{pack}_analyst: chore: {pack} review report\n\nADW-ID: {adw_id}", wt)
                url = ops.publish(state, f"{pack} review {adw_id} (requires human approval)",
                                  report_md[:60000] + "\n\n> Nothing in this PR has been applied. Approve and act manually.")
                print(f"proposal: {url or f'committed on local branch {branch}'}")

    worst = [f for r in reports for f in r.blocking(fail_on)] if fail_on else []
    state.reload()
    state.gate_report().upsert(GateResult(name=f"{pack}_analysis", status="failed" if worst else "passed",
                                          detail=f"{len(worst)} findings at/above {fail_on}" if fail_on else "report only",
                                          required_for_zte=False))
    state.save()
    return not worst


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--pack", required=True, choices=["swe", "devops", "soc", "iam"])
    p.add_argument("--input", required=True)
    p.add_argument("--tool")
    p.add_argument("--adw-id")
    p.add_argument("--no-agent", action="store_true", help="deterministic analysis only")
    p.add_argument("--propose", action="store_true", help="open a PR with the report (pr_only packs)")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low"])
    a = p.parse_args()
    main_wrapper(lambda: run(a.pack, a.input, a.adw_id, a.tool, not a.no_agent, a.propose, a.fail_on),
                 lambda: a.adw_id)


if __name__ == "__main__":
    main()
