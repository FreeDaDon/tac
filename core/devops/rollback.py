"""Rollback plan for a Terraform plan. Pure data for humans: nothing here runs a command."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from core.common import AnalysisReport, Finding
from core.devops.drift import diff_attributes
from core.devops.tfplan import classify_actions, is_critical_type, load_plan, managed_changes

TOOL = "rollback"
RollbackAction = Literal["destroy_created", "revert_update", "restore_deleted", "restore_replaced"]


class RollbackStep(BaseModel):
    order: int
    address: str
    resource_type: str
    original_action: str
    rollback_action: RollbackAction
    description: str
    reversible: bool                  # False when the rollback cannot recover data (stateful delete/replace)
    data_loss_risk: bool
    attributes: list[dict[str, Any]] = Field(default_factory=list)
    command_preview: str


class RollbackPlan(BaseModel):
    status: Literal["dry_run"] = "dry_run"
    preconditions: list[str]
    steps: list[RollbackStep]


PRECONDITIONS = [
    "terraform state pull > pre-apply.tfstate  # keep a copy of state before applying",
    "Snapshot every stateful resource listed below with data_loss_risk=true (RDS/EBS snapshot, S3 versioning).",
    "Tag the commit that is being applied so the previous configuration can be restored with `git revert`.",
]


def _step(order: int, rc: dict[str, Any], kind: str) -> RollbackStep | None:
    address, rtype = rc.get("address", ""), rc.get("type", "")
    change = rc.get("change", {})
    target = shlex.quote(f"-target={address}")
    stateful = is_critical_type(rtype)
    if kind == "create":
        return RollbackStep(order=order, address=address, resource_type=rtype, original_action=kind,
                            rollback_action="destroy_created", description=f"Destroy newly created {address}",
                            reversible=True, data_loss_risk=False,
                            command_preview=f"terraform destroy {target}  # after reviewing its dependents")
    if kind == "update":
        attrs = diff_attributes(change.get("before") or {}, change.get("after") or {})
        return RollbackStep(order=order, address=address, resource_type=rtype, original_action=kind,
                            rollback_action="revert_update", attributes=attrs,
                            description=f"Restore {len(attrs)} attribute(s) of {address} to their previous values",
                            reversible=True, data_loss_risk=False,
                            command_preview=f"git revert <apply-commit> && terraform plan {target} && terraform apply")
    if kind in {"delete", "replace"}:
        action: RollbackAction = "restore_deleted" if kind == "delete" else "restore_replaced"
        what = "data restored from snapshot/backup" if stateful else "re-created from the previous configuration"
        return RollbackStep(order=order, address=address, resource_type=rtype, original_action=kind,
                            rollback_action=action, description=f"{address} must be {what}",
                            reversible=not stateful, data_loss_risk=stateful,
                            command_preview=(f"git revert <apply-commit> && terraform apply {target}"
                                             + ("  # then restore data from the pre-apply snapshot" if stateful else "")))
    return None


def build_rollback_plan(plan: dict[str, Any]) -> RollbackPlan:
    """Steps undo changes in reverse plan order (Terraform lists dependents after their dependencies)."""
    steps: list[RollbackStep] = []
    for rc in reversed(managed_changes(plan)):
        step = _step(len(steps) + 1, rc, classify_actions(rc.get("change", {}).get("actions", [])))
        if step:
            steps.append(step)
    return RollbackPlan(preconditions=PRECONDITIONS, steps=steps)


def analyze_file(path: Path, **opts: Any) -> AnalysisReport:
    rollback = build_rollback_plan(load_plan(path))
    findings = [
        Finding(rule_id="TF-ROLLBACK-IRREVERSIBLE", title=f"Rollback of {s.address} cannot recover data",
                severity="high", category="rollback", resource=s.address, location=s.address,
                evidence={"original_action": s.original_action, "resource_type": s.resource_type},
                recommendation="Take and verify a snapshot/backup before apply, or split this change out.")
        for s in rollback.steps if not s.reversible
    ]
    return AnalysisReport(
        pack="devops", tool=TOOL, input=str(path), findings=findings,
        metrics={"steps": len(rollback.steps), "irreversible_steps": len(findings),
                 "rollback_plan": rollback.model_dump()},
        summary=f"{len(rollback.steps)} rollback step(s), {len(findings)} irreversible (dry run, nothing executed)",
    )
