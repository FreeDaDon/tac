"""RBAC / OAuth-scope validation for an MCP server: least privilege, audience restriction, allowlist conformance."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from core.common import Finding, FindingSeverity

BROAD_SCOPE = re.compile(r"(?:^|[:/._-])(?:\*|admin|administrator|all|full[_-]?access|owner|root|superuser|cloud-platform)$"
                         r"|\.all$|^\*$", re.IGNORECASE)
WRITE_SCOPE = re.compile(r"(?<!read)(?:write|edit|delete|admin|manage|modify|readwrite|full|send|create)", re.IGNORECASE)
BROAD_AUDIENCE = frozenset({"*", "everyone", "all", "all-users", "allusers", "authenticated users", "domain users",
                            "all employees", "public", "anyone"})
DEPRECATED_FLOWS = frozenset({"implicit", "password", "ropc"})
STATIC_AUTH_TYPES = frozenset({"api_key", "apikey", "bearer", "basic", "token", "static"})


@dataclass
class RbacPolicy:
    allowed_scopes: frozenset[str] = frozenset()  # empty = no allowlist supplied
    require_audience: bool = True


@dataclass
class ToolAccess:
    name: str
    required_scopes: tuple[str, ...] = ()
    read_only: bool = False
    mutating: bool = False


@dataclass
class Rbac:
    """The access model a server asks for, normalized from any of the accepted manifest shapes."""
    server: str
    auth_type: str = ""
    flow: str = ""
    pkce: bool | None = None
    scopes: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()
    tools: list[ToolAccess] = field(default_factory=list)
    remote: bool = False


def _f(rule_id: str, severity: FindingSeverity, title: str, server: str, recommendation: str, **evidence: Any) -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=severity, category="rbac", resource=server, location=server,
                   evidence=evidence, recommendation=recommendation)


def validate(rbac: Rbac, policy: RbacPolicy) -> list[Finding]:
    out: list[Finding] = []
    s = rbac.server
    for scope in rbac.scopes:
        if BROAD_SCOPE.search(scope):
            out.append(_f("MCP-SCOPE-BROAD", "high", f"Over-broad OAuth scope {scope!r}", s,
                          "Request the narrowest scope per capability; split write/admin behind a separate approved server.",
                          scope=scope))
    if policy.allowed_scopes:
        outside = sorted(set(rbac.scopes) - policy.allowed_scopes)
        if outside:
            out.append(_f("MCP-SCOPE-NOT-ALLOWED", "high", "Requested scopes are outside the approved scope allowlist", s,
                          "Remove the scopes or file an exception with the IAM owner.", scopes=outside,
                          allowed=sorted(policy.allowed_scopes)))
    declared = [t for t in rbac.tools if t.required_scopes]
    if declared and rbac.scopes:
        needed = {sc for t in declared for sc in t.required_scopes}
        unused = sorted(set(rbac.scopes) - needed)
        if unused:
            out.append(_f("MCP-SCOPE-UNUSED", "medium", "Scopes requested but no tool declares a need for them", s,
                          "Drop unused scopes (least privilege).", scopes=unused))
        missing = sorted({(t.name, sc) for t in declared for sc in t.required_scopes if sc not in rbac.scopes})
        if missing:
            out.append(_f("MCP-SCOPE-MISSING", "low", "Tools require scopes that are not requested", s,
                          "Fix the manifest; the tool would fail authorization at runtime.",
                          missing=[{"tool": n, "scope": sc} for n, sc in missing]))
    write_scopes = sorted(sc for sc in rbac.scopes if WRITE_SCOPE.search(sc) and not BROAD_SCOPE.search(sc))
    if rbac.tools and write_scopes and all(t.read_only or not t.mutating for t in rbac.tools):
        out.append(_f("MCP-SCOPE-WRITE-ON-READONLY", "medium", "Write-capable scopes requested but every tool is read-only", s,
                      "Request read-only scopes.", scopes=write_scopes))
    if rbac.remote and rbac.auth_type in ("", "none"):
        out.append(_f("MCP-AUTH-NONE", "high", "Remote MCP server declares no authentication", s,
                      "Require OAuth 2.1 with the enterprise IdP; never expose an unauthenticated tool endpoint.",
                      auth_type=rbac.auth_type or "missing"))
    if rbac.auth_type in STATIC_AUTH_TYPES:
        out.append(_f("MCP-AUTH-STATIC", "medium", f"Static credential auth ({rbac.auth_type}) instead of IdP-issued tokens", s,
                      "Prefer OAuth via the enterprise IdP with short-lived, per-user tokens; if a service identity is "
                      "unavoidable, store its secret in the vault and rotate it.", auth_type=rbac.auth_type))
    if rbac.flow.lower() in DEPRECATED_FLOWS:
        out.append(_f("MCP-AUTH-FLOW", "high", f"Deprecated OAuth flow {rbac.flow!r}", s,
                      "Use authorization code with PKCE (or client credentials for service identities).", flow=rbac.flow))
    elif rbac.auth_type in ("oauth", "oauth2") and rbac.pkce is False:
        out.append(_f("MCP-AUTH-PKCE", "medium", "OAuth without PKCE", s, "Enable PKCE.", pkce=False))
    broad = sorted(g for g in rbac.groups if g.strip().lower() in BROAD_AUDIENCE)
    if broad:
        out.append(_f("MCP-AUDIENCE-BROAD", "high", "Audience is not restricted to approved groups", s,
                      "Limit distribution to named IdP groups approved for this use case.", groups=broad))
    elif not rbac.groups and policy.require_audience and (rbac.remote or rbac.tools):
        out.append(_f("MCP-AUDIENCE-MISSING", "medium", "No approved access group / audience declared", s,
                      "Declare governance.approved_groups; enterprise connectors ship only to approved audiences."))
    return out
