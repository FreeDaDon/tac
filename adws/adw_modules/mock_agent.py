"""Default MockRunner handlers: deterministic stand-ins that produce each command's real output
contract (and file side effects), so every workflow can run end-to-end offline at zero cost."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from .agent import MockRunner
from .data_types import AgentRequest
from .security import resolve_inside


def _wd(req: AgentRequest) -> Path:
    from .utils import project_root

    return Path(req.working_dir) if req.working_dir else project_root()


def _write(req: AgentRequest, rel: str, content: str) -> str:
    path = resolve_inside(_wd(req), rel)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return rel


def _plan(req: AgentRequest, _: str) -> str:
    kind = req.slash_command.lstrip("/").title()
    return _write(req, req.args[3], (
        f"# {kind}: mock plan\n\n## Metadata\nissue_number: `{req.args[0]}`\nadw_id: `{req.args[1]}`\n\n"
        "## Step by Step Tasks\n- Add a change note under docs/changes/\n\n"
        "## Validation Commands\n- `uv run pytest -q`\n"
    ))


def _implement(req: AgentRequest, _: str) -> str:
    _write(req, f"docs/changes/{req.adw_id}.md", f"# Change {req.adw_id}\n\nImplemented plan `{req.args[0]}` (mock).\n")
    return "- added docs/changes note (mock implementation)"


def _review(req: AgentRequest, _: str) -> str:
    return json.dumps({"success": True, "review_summary": "mock review: implementation matches spec",
                       "review_issues": [], "screenshots": []})


def _e2e(req: AgentRequest, _: str) -> str:
    name = Path(req.args[2]).stem if len(req.args) > 2 else "e2e"
    return json.dumps({"test_name": name, "status": "passed", "test_path": req.args[2] if len(req.args) > 2 else "",
                       "screenshots": [], "error": None})


def _domain(req: AgentRequest, _: str) -> str:
    reports = json.loads(Path(req.args[1]).read_text())
    findings = [f for r in reports for f in r.get("findings", [])]
    order = ["critical", "high", "medium", "low", "info"]
    worst = min((order.index(f["severity"]) for f in findings), default=3)
    rating = order[min(worst, 3)]
    actions = [
        {"title": f"Address {f['rule_id']}: {f['title']}"[:120], "priority": "P1" if f["severity"] in ("critical", "high") else "P3",
         "rationale": "deterministic finding (mock interpretation)", "finding_refs": [f["rule_id"]],
         "requires_human_approval": True, "proposed_change": f.get("recommendation", "")}
        for f in findings[:10]
    ]
    return json.dumps({"risk_rating": rating, "summary": f"mock: {len(findings)} findings reviewed",
                       "prioritized_actions": actions, "false_positives": []})


def _copy_to_output(req: AgentRequest, _: str) -> str:
    src = Path(req.args[1])
    dst = resolve_inside(_wd(req), req.args[3])
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    return req.args[3]


HANDLERS = {
    "/classify_issue": lambda r, p: "/feature",
    "/generate_branch_name": lambda r, p: "mock-change",
    "/feature": _plan,
    "/bug": _plan,
    "/chore": _plan,
    "/implement": _implement,
    "/resolve_failed_test": lambda r, p: "mock: no change",
    "/resolve_failed_e2e_test": lambda r, p: "mock: no change",
    "/test_e2e": _e2e,
    "/review": _review,
    "/patch": lambda r, p: _write(r, r.args[3], "# Patch: mock\n\n## Implementation Steps\n- none\n"),
    "/document": lambda r, p: _write(r, r.args[2], f"# Feature docs ({r.adw_id})\n\nMock documentation.\n"),
    "/commit": lambda r, p: "apply planned change",
    "/redteam": lambda r, p: json.dumps({"summary": "mock: no findings", "findings": []}),
    "/reflect": lambda r, p: "[]",
    "/devops_iac_plan": _domain,
    "/devops_drift_review": _domain,
    "/soc_triage": _domain,
    "/iam_access_review": _domain,
    "/mcp_connector_review": _domain,
    "/gcp_sre_triage": _domain,
    "/soc_tune_rule": _copy_to_output,
    "/iam_policy_fix": _copy_to_output,
}

for _cmd, _handler in HANDLERS.items():
    MockRunner.handlers.setdefault(_cmd, _handler)
