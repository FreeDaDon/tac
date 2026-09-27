"""Revocation plan from audit findings. Data only: `command_preview` is illustrative text; nothing is executed,
and every plan stays `pending_human_approval`."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from core.common import AnalysisReport, Finding
from core.iam.audit import audit_inventory, config_from, load_inventory

TOOL = "iam_revoke"
RevokeAction = Literal["disable", "remove_key", "detach_policy", "remove_group"]
AWS_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/"


class RevocationStep(BaseModel):
    account: str
    action: RevokeAction
    target: str = ""
    reason: str
    reversible: bool
    command_preview: str
    source_rule: str


class RevocationPlan(BaseModel):
    status: Literal["pending_human_approval"] = "pending_human_approval"
    executes: Literal[False] = False
    steps: list[RevocationStep]


def _q(value: str) -> str:
    return shlex.quote(value)


def _policy_arn(policy: str) -> str:
    return policy if policy.startswith("arn:") else AWS_MANAGED_POLICY_ARN + policy


def steps_for(finding: Finding) -> list[RevocationStep]:
    ev, rule = finding.evidence, finding.rule_id
    user = str(ev.get("user") or finding.resource)
    if rule in {"AUD-DORMANT", "AUD-NEVER-USED"}:
        if ev.get("type") == "service":
            preview = f"aws iam list-access-keys --user-name {_q(user)}  # then set each key Inactive"
        else:
            preview = f"aws iam delete-login-profile --user-name {_q(user)}  # re-enable with create-login-profile"
        return [RevocationStep(account=user, action="disable", reason=finding.title, reversible=True,
                               command_preview=preview, source_rule=rule)]
    if rule == "AUD-STALE-KEY":
        key = str(ev.get("key_id", ""))
        return [RevocationStep(
            account=user, action="remove_key", target=key, reason=finding.title, reversible=False,
            command_preview=f"aws iam update-access-key --user-name {_q(user)} --access-key-id {_q(key)} "
            f"--status Inactive  # wait, then: aws iam delete-access-key --user-name {_q(user)} "
            f"--access-key-id {_q(key)}", source_rule=rule)]
    if rule == "AUD-NO-MFA-ADMIN":
        via = ev.get("admin_via") or {}
        steps = [RevocationStep(account=user, action="detach_policy", target=_policy_arn(p), reason=finding.title,
                                reversible=True, source_rule=rule,
                                command_preview=f"aws iam detach-user-policy --user-name {_q(user)} "
                                f"--policy-arn {_q(_policy_arn(p))}")
                 for p in via.get("policies") or []]
        steps += [RevocationStep(account=user, action="remove_group", target=g, reason=finding.title,
                                 reversible=True, source_rule=rule,
                                 command_preview=f"aws iam remove-user-from-group --user-name {_q(user)} "
                                 f"--group-name {_q(g)}")
                  for g in via.get("groups") or []]
        return steps
    return []


def build_revocation_plan(findings: list[Finding]) -> RevocationPlan:
    """Deterministic, de-duplicated steps ordered by account then action."""
    unique: dict[tuple[str, str, str], RevocationStep] = {}
    for finding in findings:
        for step in steps_for(finding):
            unique.setdefault((step.account, step.action, step.target), step)
    return RevocationPlan(steps=[unique[k] for k in sorted(unique)])


def analyze_file(path: Path, **opts: Any) -> AnalysisReport:
    """Audit an inventory and attach the proposed (never executed) revocation plan to metrics."""
    inventory = load_inventory(path)
    findings, metrics = audit_inventory(inventory, config_from(inventory, opts))
    plan = build_revocation_plan(findings)
    return AnalysisReport(
        pack="iam", tool=TOOL, input=str(path), findings=findings,
        metrics={**metrics, "steps": len(plan.steps), "irreversible_steps": sum(not s.reversible for s in plan.steps),
                 "revocation_plan": plan.model_dump()},
        summary=f"{len(plan.steps)} proposed step(s), status {plan.status}; nothing executed",
    )
