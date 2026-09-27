"""Privilege audit of an identity inventory, evaluated as of a fixed date."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from core.common import AnalysisReport, Finding, FindingSeverity

TOOL = "iam_audit"
DEFAULT_ADMIN_POLICIES = ("AdministratorAccess", "IAMFullAccess")
DEFAULT_ADMIN_GROUPS = ("admins", "Administrators", "administrators")


@dataclass(frozen=True)
class AuditConfig:
    as_of: date
    dormant_days: int = 90
    never_used_grace_days: int = 30
    key_max_age_days: int = 90
    key_unused_days: int = 90
    max_admins: int = 3
    admin_policies: tuple[str, ...] = DEFAULT_ADMIN_POLICIES
    admin_groups: tuple[str, ...] = DEFAULT_ADMIN_GROUPS


def parse_date(value: Any) -> date | None:
    if not value:
        return None
    text = str(value)
    if len(text) == 10:
        return date.fromisoformat(text)
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).astimezone(UTC).date()


def admin_via(user: dict[str, Any], cfg: AuditConfig) -> dict[str, list[str]]:
    """Which attached policies / groups make this user an admin."""
    policies = [p for p in user.get("attached_policies") or [] if str(p).rsplit("/", 1)[-1] in cfg.admin_policies]
    groups = [g for g in user.get("groups") or [] if g in cfg.admin_groups]
    return {"policies": policies, "groups": groups}


def is_admin(user: dict[str, Any], cfg: AuditConfig) -> bool:
    via = admin_via(user, cfg)
    return bool(via["policies"] or via["groups"])


def last_activity(user: dict[str, Any]) -> date | None:
    dates = [parse_date(user.get("last_login"))] + [parse_date(k.get("last_used")) for k in user.get("access_keys") or []]
    known = [d for d in dates if d]
    return max(known) if known else None


def _f(rule_id: str, severity: FindingSeverity, title: str, user: dict[str, Any], recommendation: str,
       cfg: AuditConfig, **evidence: Any) -> Finding:
    name = user.get("name", "")
    return Finding(rule_id=rule_id, title=title, severity=severity, category="privilege", resource=name,
                   location=name, recommendation=recommendation,
                   evidence={"user": name, "type": user.get("type", "human"), "admin": is_admin(user, cfg),
                             "admin_via": admin_via(user, cfg), **evidence})


def audit_user(user: dict[str, Any], cfg: AuditConfig) -> list[Finding]:
    findings: list[Finding] = []
    name, kind, admin = user.get("name", ""), user.get("type", "human"), is_admin(user, cfg)
    activity, created = last_activity(user), parse_date(user.get("created"))

    if activity is None:
        age = (cfg.as_of - created).days if created else None
        if age is None or age > cfg.never_used_grace_days:
            findings.append(_f("AUD-NEVER-USED", "high" if admin else "medium",
                               f"{name} has never been used ({age if age is not None else '?'} days old)", user,
                               "Disable the account; delete it after the owner confirms.", cfg, age_days=age))
    else:
        idle = (cfg.as_of - activity).days
        if idle > cfg.dormant_days:
            findings.append(_f("AUD-DORMANT", "high" if admin else "medium", f"{name} dormant for {idle} days", user,
                               "Disable the account; delete it after the owner confirms.", cfg, idle_days=idle,
                               last_activity=activity.isoformat()))

    for key in user.get("access_keys") or []:
        if key.get("status", "Active") != "Active":
            continue
        key_created, key_used = parse_date(key.get("created")), parse_date(key.get("last_used"))
        reasons = []
        if key_created and (cfg.as_of - key_created).days > cfg.key_max_age_days:
            reasons.append(f"created {(cfg.as_of - key_created).days} days ago")
        if key_used is None and key_created and (cfg.as_of - key_created).days > cfg.never_used_grace_days:
            reasons.append("never used")
        elif key_used and (cfg.as_of - key_used).days > cfg.key_unused_days:
            reasons.append(f"unused for {(cfg.as_of - key_used).days} days")
        if reasons:
            findings.append(_f("AUD-STALE-KEY", "medium", f"Stale access key for {name}: {', '.join(reasons)}", user,
                               "Deactivate, confirm nothing breaks, then delete; move workloads to roles.", cfg,
                               key_id=key.get("id", ""), reasons=reasons))

    if kind == "human" and admin and not user.get("mfa_enabled"):
        findings.append(_f("AUD-NO-MFA-ADMIN", "high", f"Admin {name} has no MFA", user,
                           "Enforce MFA before any other action; remove admin until it is enabled.", cfg))
    return findings


def audit_inventory(inventory: dict[str, Any], cfg: AuditConfig) -> tuple[list[Finding], dict[str, Any]]:
    users = inventory.get("users") or []
    findings = [f for u in users for f in audit_user(u, cfg)]
    admins = sorted(u.get("name", "") for u in users if is_admin(u, cfg))
    if len(admins) > cfg.max_admins:
        findings.append(Finding(
            rule_id="AUD-ADMIN-SPRAWL", title=f"{len(admins)} admin identities (limit {cfg.max_admins})",
            severity="medium", category="privilege", resource="inventory", location="inventory",
            evidence={"admins": admins, "limit": cfg.max_admins},
            recommendation="Reduce standing admin access; use role assumption with MFA and just-in-time grants."))
    metrics = {"as_of": cfg.as_of.isoformat(), "users": len(users),
               "humans": sum(1 for u in users if u.get("type", "human") == "human"),
               "service_accounts": sum(1 for u in users if u.get("type") == "service"),
               "admins": len(admins), "access_keys": sum(len(u.get("access_keys") or []) for u in users)}
    return findings, metrics


def config_from(inventory: dict[str, Any], opts: dict[str, Any]) -> AuditConfig:
    """`as_of` precedence: option, then the inventory's own `as_of`, then today (UTC)."""
    as_of = parse_date(opts.get("as_of")) or parse_date(inventory.get("as_of")) or datetime.now(UTC).date()
    d = AuditConfig(as_of=as_of)
    return AuditConfig(
        as_of=as_of,
        dormant_days=int(opts.get("dormant_days", d.dormant_days)),
        never_used_grace_days=int(opts.get("never_used_grace_days", d.never_used_grace_days)),
        key_max_age_days=int(opts.get("key_max_age_days", d.key_max_age_days)),
        key_unused_days=int(opts.get("key_unused_days", d.key_unused_days)),
        max_admins=int(opts.get("max_admins", d.max_admins)),
    )


def load_inventory(path: Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("users"), list):
        raise ValueError(f"{path}: not an identity inventory (no `users` list)")
    return data


def analyze_file(path: Path, **opts: Any) -> AnalysisReport:
    inventory = load_inventory(path)
    findings, metrics = audit_inventory(inventory, config_from(inventory, opts))
    return AnalysisReport(pack="iam", tool=TOOL, input=str(path), findings=findings, metrics=metrics,
                          summary=f"{len(findings)} issue(s) across {metrics['users']} identities as of {metrics['as_of']}")
