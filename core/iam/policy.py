"""AWS IAM policy linter (identity and trust policies). Rule ids IAM001..IAM010."""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any

from core.common import AnalysisReport, Finding, FindingSeverity

TOOL = "iam_policy"
CURRENT_VERSION = "2012-10-17"
READ_VERB_PREFIXES = ("get", "list", "describe", "head", "search", "lookup", "batchget", "view", "query", "scan",
                      "select", "check", "validate", "simulate", "generate")
FULL_WILDCARDS = frozenset({"*", "*:*"})
SENSITIVE_ACTIONS = (
    "iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:AttachUserPolicy",
    "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:CreatePolicyVersion",
    "iam:UpdateAssumeRolePolicy", "iam:DeleteUser", "kms:ScheduleKeyDeletion", "kms:DisableKey",
    "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "organizations:LeaveOrganization", "s3:DeleteBucket",
)
ASSUME_ROLE_ACTIONS = ("sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML")


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def action_matches(pattern: str, action: str) -> bool:
    """IAM action patterns are case-insensitive globs."""
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def grants(actions: list[str], target: str) -> bool:
    return any(action_matches(a, target) for a in actions)


def is_write_action(action: str) -> bool:
    if action in FULL_WILDCARDS:
        return True
    verb = action.split(":", 1)[-1].lower()
    return verb == "*" or not verb.startswith(READ_VERB_PREFIXES)


def extract_document(data: Any) -> dict[str, Any]:
    """Accept a bare policy document or `aws iam get-policy-version` / get-role output wrappers."""
    if isinstance(data, dict):
        if "Statement" in data:
            return data
        for key in ("PolicyVersion", "Role"):
            inner = data.get(key)
            if isinstance(inner, dict):
                doc = inner.get("Document") or inner.get("AssumeRolePolicyDocument")
                if isinstance(doc, str):
                    doc = json.loads(doc)
                if isinstance(doc, dict):
                    return doc
    raise ValueError("not an IAM policy document (no Statement)")


def _principal_is_public(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any("*" in as_list(v) for v in principal.values())
    return False


def _has_mfa_condition(condition: Any) -> bool:
    text = json.dumps(condition or {})
    return "MultiFactorAuthPresent" in text or "MultiFactorAuthAge" in text


def _finding(rule_id: str, severity: FindingSeverity, title: str, resource: str, location: str,
             stmt: dict[str, Any], recommendation: str, **extra: Any) -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=severity, category="privilege", resource=resource,
                   location=location, evidence={"statement": stmt, **extra}, recommendation=recommendation)


def lint_statement(stmt: dict[str, Any], index: int, source: str = "") -> list[Finding]:
    sid = stmt.get("Sid", "")
    resource = f"{source}#{sid}" if sid else f"{source}#Statement[{index}]"
    loc = f"{source}#Statement[{index}]"
    effect = stmt.get("Effect")
    if effect not in ("Allow", "Deny") or not any(k in stmt for k in ("Action", "NotAction")):
        return [_finding("IAM010", "medium", "Malformed statement (missing Effect or Action)", resource, loc, stmt,
                         "Every statement needs Effect Allow|Deny and Action or NotAction.")]
    if effect == "Deny":
        return []

    actions = [str(a) for a in as_list(stmt.get("Action"))]
    resources = [str(r) for r in as_list(stmt.get("Resource"))]
    condition = stmt.get("Condition")
    star_resource = "*" in resources
    full_admin_action = any(a in FULL_WILDCARDS for a in actions)
    findings: list[Finding] = []

    if full_admin_action and star_resource:
        findings.append(_finding("IAM001", "critical", "Allow *:* on * (full administrator access)", resource, loc,
                                 stmt, "Replace with the specific actions and resources the principal needs."))
    elif full_admin_action:
        findings.append(_finding("IAM002", "high", "Allow all actions (*) on scoped resources", resource, loc, stmt,
                                 "Enumerate the required actions instead of `*`."))
    service_wildcards = sorted(a for a in actions if a.endswith(":*") and a not in FULL_WILDCARDS)
    if service_wildcards:
        findings.append(_finding("IAM002", "high", f"Service-wide wildcard actions: {', '.join(service_wildcards)}",
                                 resource, loc, stmt, "Grant only the specific API actions required.",
                                 actions=service_wildcards))
    if star_resource:
        writes = sorted(a for a in actions if a not in FULL_WILDCARDS and not a.endswith(":*") and is_write_action(a))
        if writes:
            findings.append(_finding("IAM003", "high", "Write actions on Resource \"*\"", resource, loc, stmt,
                                     "Scope write actions to specific ARNs.", actions=writes))
    if "NotAction" in stmt:
        findings.append(_finding("IAM004", "high", "Allow with NotAction grants everything not listed", resource,
                                 loc, stmt, "Use an explicit Action allow-list."))
    if "NotResource" in stmt:
        findings.append(_finding("IAM005", "high", "Allow with NotResource applies to every other resource",
                                 resource, loc, stmt, "Use an explicit Resource list."))
    unscoped = star_resource or "NotResource" in stmt
    if unscoped and not full_admin_action and grants(actions, "iam:PassRole"):
        findings.append(_finding("IAM006", "high", "iam:PassRole on any role", resource, loc, stmt,
                                 "Restrict Resource to specific role ARNs and add iam:PassedToService."))
    if _principal_is_public(stmt.get("Principal")) and any(grants(actions, a) for a in ASSUME_ROLE_ACTIONS):
        findings.append(_finding(
            "IAM007", "medium" if condition else "critical", "Trust policy allows any principal to assume role",
            resource, loc, stmt, "Name specific principals; require sts:ExternalId / aws:PrincipalOrgID conditions.",
            has_condition=bool(condition)))
    sensitive = [a for a in SENSITIVE_ACTIONS if grants(actions, a)]
    if sensitive and not (full_admin_action and star_resource) and "Principal" not in stmt \
            and not _has_mfa_condition(condition):
        findings.append(_finding("IAM008", "medium", "Sensitive actions allowed without an MFA condition", resource,
                                 loc, stmt, "Add Condition {\"Bool\": {\"aws:MultiFactorAuthPresent\": \"true\"}}.",
                                 sensitive_actions=sensitive))
    return findings


def lint_policy(doc: dict[str, Any], source: str = "") -> list[Finding]:
    findings: list[Finding] = []
    if doc.get("Version") != CURRENT_VERSION:
        findings.append(Finding(rule_id="IAM009", title=f"Policy Version is not {CURRENT_VERSION}", severity="low",
                                category="privilege", resource=source, location=source,
                                evidence={"version": doc.get("Version")},
                                recommendation=f"Set \"Version\": \"{CURRENT_VERSION}\" (policy variables need it)."))
    for index, stmt in enumerate(as_list(doc.get("Statement"))):
        if isinstance(stmt, dict):
            findings.extend(lint_statement(stmt, index, source))
    return findings


def analyze_file(path: Path, **opts: Any) -> AnalysisReport:
    doc = extract_document(json.loads(Path(path).read_text(encoding="utf-8")))
    findings = lint_policy(doc, str(path))
    statements = len(as_list(doc.get("Statement")))
    return AnalysisReport(
        pack="iam", tool=TOOL, input=str(path), findings=findings,
        metrics={"statements": statements, "findings": len(findings)},
        summary=f"{len(findings)} issue(s) across {statements} statement(s)",
    )
