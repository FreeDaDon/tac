"""RBAC/ABAC model checks: separation of duties, admin-equivalent users, ABAC violations, unused roles."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.common import AnalysisReport, Finding, FindingSeverity, as_list
from core.loaders import load_structured

TOOL = "rbac"
DEFAULT_ADMIN_PERMISSIONS = ("*", "*:*", "admin", "admin:*", "iam:*")


@dataclass
class Resolution:
    role_permissions: dict[str, set[str]]
    cycles: list[list[str]] = field(default_factory=list)
    unknown_roles: set[str] = field(default_factory=set)


def _parents(roles: dict[str, Any], role: str) -> list[str]:
    return [str(p) for p in as_list((roles.get(role) or {}).get("inherits"))]


def _user_roles(user: Any) -> list[str]:
    return [str(r) for r in as_list((user or {}).get("roles"))]


def ancestors(roles: dict[str, Any], role: str) -> set[str]:
    """`role` plus every role it inherits from, transitively (cycle-safe)."""
    seen: set[str] = set()
    stack = [role]
    while stack:
        current = stack.pop()
        if current in seen or current not in roles:
            continue
        seen.add(current)
        stack.extend(_parents(roles, current))
    return seen


def _strongly_connected(roles: dict[str, Any]) -> list[set[str]]:
    """Tarjan's SCC, iterative (no recursion limit), linear in roles + inherits edges."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[set[str]] = []
    for root in sorted(roles):
        if root in index:
            continue
        work = [(root, iter(_parents(roles, root)))]
        index[root] = low[root] = len(index)
        stack.append(root)
        on_stack.add(root)
        while work:
            node, parents = work[-1]
            parent = next((p for p in parents if p in roles), None)
            if parent is None:
                work.pop()
                if work:
                    low[work[-1][0]] = min(low[work[-1][0]], low[node])
                if low[node] == index[node]:
                    component: set[str] = set()
                    while True:
                        member = stack.pop()
                        on_stack.discard(member)
                        component.add(member)
                        if member == node:
                            break
                    components.append(component)
            elif parent not in index:
                index[parent] = low[parent] = len(index)
                stack.append(parent)
                on_stack.add(parent)
                work.append((parent, iter(_parents(roles, parent))))
            elif parent in on_stack:
                low[node] = min(low[node], index[parent])
    return components


def _cycle_path(roles: dict[str, Any], members: set[str]) -> list[str]:
    """A shortest inheritance path from the alphabetically first member back to itself, inside one SCC."""
    start = min(members)
    previous: dict[str, str] = {}
    frontier = [start]
    while frontier:
        nxt = []
        for node in frontier:
            for parent in sorted(set(_parents(roles, node)) & members):
                if parent == start:
                    path = [node]
                    while path[-1] != start:
                        path.append(previous[path[-1]])
                    return [start, *reversed(path[:-1]), start]
                if parent not in previous:
                    previous[parent] = node
                    nxt.append(parent)
        frontier = nxt
    return [start, start]


def find_cycles(roles: dict[str, Any]) -> list[list[str]]:
    """One cycle per strongly connected group of roles, as [a, b, ..., a] from its alphabetically first member."""
    cyclic = [c for c in _strongly_connected(roles)
              if len(c) > 1 or next(iter(c)) in _parents(roles, next(iter(c)))]
    return sorted(_cycle_path(roles, c) for c in cyclic)


def resolve_roles(roles: dict[str, Any]) -> Resolution:
    """Effective permissions per role = own permissions of the role and all its ancestors."""
    perms = {
        name: {str(p) for anc in ancestors(roles, name) for p in as_list((roles.get(anc) or {}).get("permissions"))}
        for name in roles
    }
    unknown = {p for name in roles for p in _parents(roles, name) if p not in roles}
    return Resolution(role_permissions=perms, cycles=find_cycles(roles), unknown_roles=unknown)


def has_permission(granted: set[str], permission: str) -> bool:
    """Granted permissions may be globs (`payments:*`)."""
    return any(fnmatch.fnmatchcase(permission, g) for g in granted)


def user_permissions(user: dict[str, Any], resolution: Resolution) -> set[str]:
    perms: set[str] = set()
    for role in _user_roles(user):
        perms |= resolution.role_permissions.get(role, set())
    return perms


def _finding(rule_id: str, severity: FindingSeverity, title: str, resource: str, recommendation: str, **evidence: Any) -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=severity, category="access-model",
                   resource=resource, location=resource, evidence=evidence, recommendation=recommendation)


def check_model(model: dict[str, Any], source: str = "") -> tuple[list[Finding], dict[str, Any]]:
    roles: dict[str, Any] = model.get("roles") or {}
    users: dict[str, Any] = model.get("users") or {}
    admin_perms = tuple(model.get("admin_permissions") or DEFAULT_ADMIN_PERMISSIONS)
    res = resolve_roles(roles)
    findings: list[Finding] = []

    for cycle in res.cycles:
        findings.append(_finding("RBAC-CYCLE", "high", f"Role inheritance cycle: {' -> '.join(cycle)}",
                                 f"role:{cycle[0]}", "Break the cycle; inheritance must be a DAG.", cycle=cycle))
    referenced = {r for u in users.values() for r in _user_roles(u)}
    for role in sorted(res.unknown_roles | (referenced - set(roles))):
        findings.append(_finding("RBAC-UNKNOWN-ROLE", "medium", f"Reference to undefined role `{role}`", f"role:{role}",
                                 "Define the role or remove the reference."))

    effective = {name: user_permissions(u or {}, res) for name, u in users.items()}
    for name in sorted(users):
        perms = effective[name]
        for pair in model.get("sod_rules") or []:
            a, b = pair[0], pair[1]
            if has_permission(perms, a) and has_permission(perms, b):
                findings.append(_finding(
                    "RBAC-SOD", "high", f"{name} holds conflicting duties `{a}` + `{b}`", f"user:{name}",
                    "Split the duties across different users or add a compensating approval control.",
                    user=name, conflict=[a, b], roles=_user_roles(users[name])))
        admin = sorted(p for p in perms if p in admin_perms)
        if admin:
            findings.append(_finding("RBAC-ADMIN", "medium", f"{name} has admin-equivalent permissions", f"user:{name}",
                                     "Confirm the business need; prefer just-in-time elevation.",
                                     user=name, permissions=admin))
        attrs = (users[name] or {}).get("attributes") or {}
        for policy in model.get("abac_policies") or []:
            permission, require = policy.get("permission", ""), policy.get("require") or {}
            if not has_permission(perms, permission):
                continue
            failed = {k: {"required": v, "actual": attrs.get(k)} for k, v in require.items()
                      if attrs.get(k) not in (v if isinstance(v, list) else [v])}
            if failed:
                findings.append(_finding(
                    "RBAC-ABAC", "high", f"{name} can `{permission}` without required attributes", f"user:{name}",
                    "Remove the role or fix the user's attributes; enforce the ABAC condition at the PDP.",
                    user=name, permission=permission, failed=failed))

    used = _reachable_roles(referenced, roles)
    for role in sorted(set(roles) - used):
        findings.append(_finding("RBAC-UNUSED-ROLE", "low", f"Role `{role}` is not assigned to anyone", f"role:{role}",
                                 "Delete the role or document why it is kept.", role=role))

    metrics = {"roles": len(roles), "users": len(users), "sod_rules": len(model.get("sod_rules") or []),
               "admin_users": sorted(n for n, p in effective.items() if any(x in admin_perms for x in p)),
               "cycles": len(res.cycles)}
    return findings, metrics


def _reachable_roles(assigned: set[str], roles: dict[str, Any]) -> set[str]:
    return {r for role in assigned for r in ancestors(roles, role)}


def analyze_file(path: Path, **opts: Any) -> AnalysisReport:
    model = load_structured(Path(path))
    if not isinstance(model, dict) or "roles" not in model:
        raise ValueError(f"{path}: not an RBAC model (no `roles`)")
    findings, metrics = check_model(model, str(path))
    return AnalysisReport(pack="iam", tool=TOOL, input=str(path), findings=findings, metrics=metrics,
                          summary=f"{len(findings)} issue(s) across {metrics['users']} user(s) and "
                          f"{metrics['roles']} role(s)")
