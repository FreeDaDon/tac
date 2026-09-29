"""GCP Terraform state/plan and IAM auditor. Input: `terraform show -json` of a state file or a saved plan.

Reads only the JSON export (never runs terraform or gcloud). Secret values (service-account private keys) are
never copied into findings. Rule ids: GCP-IAM-*, GCP-SA-*, GCP-NET-*, GCP-DATA-*, GCP-GKE-*, GCP-STATE-*.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from core.common import AnalysisReport, Finding, FindingSeverity
from core.loaders import load_structured

TOOL = "gcp_tf"
SEVERITY_WEIGHTS = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})
PRIMITIVE_ROLES = frozenset({"roles/owner", "roles/editor"})
ESCALATION_ROLES = frozenset({
    "roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser", "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountKeyAdmin", "roles/iam.securityAdmin", "roles/iam.workloadIdentityPoolAdmin",
    "roles/resourcemanager.projectIamAdmin", "roles/resourcemanager.organizationAdmin",
    "roles/resourcemanager.folderIamAdmin", "roles/iam.organizationRoleAdmin", "roles/iam.roleAdmin",
    "roles/cloudfunctions.admin", "roles/compute.admin", "roles/container.admin",
})
ADMIN_ROLE = re.compile(r"^roles/[\w.]+\.admin$")
SENSITIVE_DATA_TYPES = ("storage_bucket", "bigquery", "secret_manager", "kms", "pubsub", "sql", "spanner", "artifact_registry")
INVOKER_TYPES = ("cloud_run", "cloudfunctions", "cloudfunctions2")
IAM_KIND = re.compile(r"^google_(?P<scope>project|organization|folder|billing_account|service_account|[\w]+?)_iam_"
                      r"(?P<kind>member|binding|policy|audit_config)$")
SENSITIVE_PORTS = {22: "ssh", 3389: "rdp", 3306: "mysql", 5432: "postgres", 1433: "mssql", 6379: "redis",
                   27017: "mongodb", 9200: "elasticsearch", 9092: "kafka", 2181: "zookeeper", 5601: "kibana"}
DEFAULT_SA = re.compile(r"-compute@developer\.gserviceaccount\.com$|@appspot\.gserviceaccount\.com$")
HIGH_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
PUBLIC_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


def looks_like_terraform_json(data: Any) -> bool:
    return isinstance(data, dict) and ("resource_changes" in data or "planned_values" in data
                                       or isinstance(data.get("values"), dict))


def _modules(module: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield module
    for child in module.get("child_modules") or []:
        yield from _modules(child)


def resources(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Managed `google*` resources from a state (`values`) or plan (`planned_values`); falls back to resource_changes."""
    root = (data.get("values") or data.get("planned_values") or {}).get("root_module")
    found: list[dict[str, Any]] = []
    if isinstance(root, dict):
        for mod in _modules(root):
            found.extend(r for r in mod.get("resources") or [] if str(r.get("type", "")).startswith("google")
                         and r.get("mode", "managed") == "managed")
    elif "resource_changes" in data:
        for rc in data["resource_changes"]:
            after = (rc.get("change") or {}).get("after")
            if str(rc.get("type", "")).startswith("google") and isinstance(after, dict) and "delete" not in (
                    rc.get("change", {}).get("actions") or []):
                found.append({"address": rc.get("address"), "type": rc["type"], "name": rc.get("name"), "values": after})
    return found


def _first(value: Any) -> dict[str, Any]:
    """Terraform blocks are one-element lists in JSON."""
    if isinstance(value, list):
        return value[0] if value and isinstance(value[0], dict) else {}
    return value if isinstance(value, dict) else {}


def _f(res: dict[str, Any], rule_id: str, severity: FindingSeverity, title: str, category: str, rec: str,
       **evidence: Any) -> Finding:
    addr = str(res.get("address", ""))
    return Finding(rule_id=rule_id, title=title, severity=severity, category=category, resource=addr, location=addr,
                   evidence={"type": res.get("type"), **evidence}, recommendation=rec)


def iam_grants(res: dict[str, Any]) -> list[tuple[str, str]]:
    """(role, member) pairs granted by one IAM resource (member, binding, or policy_data)."""
    v = res.get("values") or {}
    rtype = str(res.get("type", ""))
    if rtype.endswith("_iam_member"):
        return [(str(v.get("role", "")), str(v.get("member", "")))]
    if rtype.endswith("_iam_binding"):
        return [(str(v.get("role", "")), str(m)) for m in v.get("members") or []]
    if rtype.endswith("_iam_policy"):
        try:
            doc = json.loads(v.get("policy_data") or "{}")
        except (TypeError, ValueError):
            return []
        return [(str(b.get("role", "")), str(m)) for b in doc.get("bindings") or [] for m in b.get("members") or []]
    return []


def _iam_scope(rtype: str) -> str:
    m = IAM_KIND.match(rtype)
    return m.group("scope") if m else ""


def check_iam(res: dict[str, Any]) -> list[Finding]:
    rtype = str(res.get("type", ""))
    if not IAM_KIND.match(rtype):
        return []
    out: list[Finding] = []
    scope = _iam_scope(rtype)
    org_level = scope in ("project", "organization", "folder")
    for role, member in iam_grants(res):
        if member in PUBLIC_MEMBERS:
            data = any(t in rtype for t in SENSITIVE_DATA_TYPES)
            invoker = any(t in rtype for t in INVOKER_TYPES)
            sev: FindingSeverity = "critical" if data or org_level or role in PRIMITIVE_ROLES else "high"
            out.append(_f(res, "GCP-IAM-PUBLIC", sev, f"{role} granted to {member} (public internet)", "iam",
                          "Remove the public member; front public workloads with an authenticated gateway. "
                          + ("Intentional public invoker? Record the exception." if invoker else ""),
                          role=role, member=member))
            continue
        if role in PRIMITIVE_ROLES:
            sev = "critical" if member.startswith("serviceAccount:") or scope == "organization" else "high"
            out.append(_f(res, "GCP-IAM-PRIMITIVE", sev, f"Primitive role {role} granted", "iam",
                          "Replace with predefined or custom roles scoped to the required permissions.",
                          role=role, member=member))
        elif role in ESCALATION_ROLES and org_level:
            out.append(_f(res, "GCP-IAM-ESCALATION", "high", f"{role} at {scope} level allows privilege escalation", "iam",
                          "Grant on the specific service account or resource instead, to a group, with an IAM condition.",
                          role=role, member=member))
        elif ADMIN_ROLE.match(role) and org_level:
            out.append(_f(res, "GCP-IAM-ADMIN-ROLE", "medium", f"Admin role {role} granted at {scope} level", "iam",
                          "Prefer a narrower role or resource-level grant.", role=role, member=member))
        if member.startswith("user:") and (role in PRIMITIVE_ROLES or role in ESCALATION_ROLES or ADMIN_ROLE.match(role)):
            out.append(_f(res, "GCP-IAM-USER-DIRECT", "medium", "Privileged role bound to an individual user", "iam",
                          "Bind privileged roles to IdP-managed groups so access follows joiner/mover/leaver.",
                          role=role, member=member))
    if rtype.endswith("_iam_policy"):
        out.append(_f(res, "GCP-IAM-AUTHORITATIVE", "high" if org_level else "medium",
                      "Authoritative IAM policy replaces all existing bindings (lockout risk)", "iam",
                      "Use additive _iam_member resources; review the plan diff for removed bindings."))
    elif rtype.endswith("_iam_binding"):
        out.append(_f(res, "GCP-IAM-AUTHORITATIVE", "low", "Authoritative binding removes members granted elsewhere", "iam",
                      "Use _iam_member unless this role is fully owned by this configuration."))
    return out


def check_service_account(res: dict[str, Any]) -> list[Finding]:
    rtype, v = str(res.get("type", "")), res.get("values") or {}
    out: list[Finding] = []
    if rtype == "google_service_account_key":
        out.append(_f(res, "GCP-SA-KEY", "high", "User-managed service-account key exists", "service-identity",
                      "Use workload identity / impersonation instead of long-lived keys; if unavoidable, rotate and vault it.",
                      service_account=str(v.get("service_account_id", "")), key_type=str(v.get("key_algorithm", "")),
                      private_key_in_state=bool(v.get("private_key"))))
        if v.get("private_key"):
            out.append(_f(res, "GCP-STATE-SECRET", "high", "Service-account private key is stored in Terraform state",
                          "secrets", "Restrict state access, enable CMEK on the state bucket, and remove the key resource.",
                          service_account=str(v.get("service_account_id", ""))))
    if rtype in ("google_compute_instance", "google_compute_instance_template", "google_compute_instance_from_template"):
        sa = _first(v.get("service_account"))
        email, scopes = str(sa.get("email", "")), [str(s) for s in sa.get("scopes") or []]
        if DEFAULT_SA.search(email) or (sa and not email):
            broad = HIGH_SCOPE in scopes
            out.append(_f(res, "GCP-SA-DEFAULT", "high" if broad else "medium",
                          "Workload runs as the default service account" + (" with cloud-platform scope" if broad else ""),
                          "service-identity", "Create a dedicated least-privilege service account per workload.",
                          service_account=email or "default", scopes=scopes))
        elif HIGH_SCOPE in scopes:
            out.append(_f(res, "GCP-SA-SCOPE", "medium", "cloud-platform access scope on a dedicated service account",
                          "service-identity", "Rely on IAM roles for authorization; keep the access scope narrow.",
                          service_account=email, scopes=scopes))
        if any(_first(ni.get("access_config") if isinstance(ni, dict) else None) for ni in v.get("network_interface") or []):
            out.append(_f(res, "GCP-NET-PUBLIC-IP", "medium", "VM has an external IP address", "network",
                          "Use Cloud NAT and IAP for access unless a public IP is required."))
    return out


def _port_ranges(allow: list[dict[str, Any]]) -> tuple[bool, set[int]]:
    """(all ports open?, sensitive ports covered) for a firewall rule's allow blocks."""
    open_all = False
    sensitive: set[int] = set()
    for block in allow:
        proto = str(block.get("protocol", "")).lower()
        ports = [str(p) for p in block.get("ports") or []]
        if proto == "all" or (proto in ("tcp", "udp") and not ports):
            open_all = True
        for p in ports:
            lo, _, hi = p.partition("-")
            try:
                start, end = int(lo), int(hi or lo)
            except ValueError:
                continue
            sensitive.update(port for port in SENSITIVE_PORTS if start <= port <= end)
    return open_all, sensitive


def check_network(res: dict[str, Any]) -> list[Finding]:
    if res.get("type") != "google_compute_firewall":
        return []
    v = res.get("values") or {}
    if v.get("disabled") or str(v.get("direction", "INGRESS")).upper() != "INGRESS":
        return []
    sources = {str(s) for s in v.get("source_ranges") or []}
    public = sources & PUBLIC_CIDRS
    if not public:
        return []
    open_all, sensitive = _port_ranges(v.get("allow") or [])
    if open_all:
        return [_f(res, "GCP-NET-FW-OPEN", "critical", "Firewall allows all ports from the internet", "network",
                   "Restrict source_ranges and ports; use IAP TCP forwarding for admin access.", source_ranges=sorted(public))]
    if sensitive:
        names = {p: SENSITIVE_PORTS[p] for p in sorted(sensitive)}
        admin = bool(sensitive & {22, 3389})
        return [_f(res, "GCP-NET-FW-OPEN", "critical" if not admin else "high",
                   f"Firewall exposes {', '.join(names.values())} to the internet", "network",
                   "Restrict source_ranges; use IAP or a bastion for administrative ports.",
                   source_ranges=sorted(public), ports={str(k): v for k, v in names.items()})]
    return [_f(res, "GCP-NET-FW-PUBLIC", "low", "Firewall allows the internet on non-sensitive ports", "network",
               "Confirm the workload is meant to be public.", source_ranges=sorted(public))]


def check_data(res: dict[str, Any]) -> list[Finding]:
    rtype, v = str(res.get("type", "")), res.get("values") or {}
    out: list[Finding] = []
    if rtype == "google_storage_bucket":
        if str(v.get("public_access_prevention", "inherited")).lower() != "enforced":
            out.append(_f(res, "GCP-DATA-BUCKET-PAP", "medium", "Bucket does not enforce public access prevention", "data",
                          "Set public_access_prevention = \"enforced\"."))
        if v.get("uniform_bucket_level_access") is False:
            out.append(_f(res, "GCP-DATA-BUCKET-ACL", "medium", "Uniform bucket-level access is disabled", "data",
                          "Enable uniform_bucket_level_access so IAM is the only access path."))
    if rtype == "google_sql_database_instance":
        settings = _first(v.get("settings"))
        ipc = _first(settings.get("ip_configuration"))
        nets = {str(n.get("value", "")) for n in ipc.get("authorized_networks") or [] if isinstance(n, dict)}
        if nets & PUBLIC_CIDRS:
            out.append(_f(res, "GCP-DATA-SQL-PUBLIC", "critical", "Cloud SQL accepts connections from the internet", "data",
                          "Use private IP and the Cloud SQL Auth Proxy; remove 0.0.0.0/0 from authorized networks.",
                          authorized_networks=sorted(nets & PUBLIC_CIDRS)))
        elif ipc.get("ipv4_enabled") is True:
            out.append(_f(res, "GCP-DATA-SQL-PUBLIC-IP", "medium", "Cloud SQL has a public IPv4 address", "data",
                          "Prefer private IP only."))
        if not _first(settings.get("backup_configuration")).get("enabled"):
            out.append(_f(res, "GCP-DATA-SQL-BACKUP", "medium", "Cloud SQL automated backups are disabled", "data",
                          "Enable backups and point-in-time recovery."))
        if v.get("deletion_protection") is False:
            out.append(_f(res, "GCP-DATA-DELETION-PROTECTION", "low", "Cloud SQL deletion protection is off", "data",
                          "Set deletion_protection = true for production."))
    return out


def check_gke(res: dict[str, Any]) -> list[Finding]:
    if res.get("type") != "google_container_cluster":
        return []
    v = res.get("values") or {}
    out: list[Finding] = []
    if v.get("enable_legacy_abac") is True:
        out.append(_f(res, "GCP-GKE-ABAC", "high", "Legacy ABAC enabled on GKE cluster", "gke", "Disable legacy ABAC; use RBAC."))
    if not _first(v.get("private_cluster_config")).get("enable_private_nodes"):
        out.append(_f(res, "GCP-GKE-PUBLIC-NODES", "medium", "GKE nodes are not private", "gke",
                      "Enable private nodes and restrict the control-plane endpoint."))
    cidrs = {str(c.get("cidr_block", "")) for c in _first(v.get("master_authorized_networks_config")).get("cidr_blocks") or []
             if isinstance(c, dict)}
    if cidrs & PUBLIC_CIDRS:
        out.append(_f(res, "GCP-GKE-MASTER-OPEN", "high", "GKE control plane is reachable from the internet", "gke",
                      "Restrict master_authorized_networks to corporate ranges.", cidr_blocks=sorted(cidrs & PUBLIC_CIDRS)))
    if not _first(v.get("workload_identity_config")).get("workload_pool"):
        out.append(_f(res, "GCP-GKE-NO-WI", "low", "Workload Identity is not enabled", "gke",
                      "Enable Workload Identity instead of node service-account credentials."))
    return out


CHECKS = (check_iam, check_service_account, check_network, check_data, check_gke)


def identity_matrix(res_list: list[dict[str, Any]]) -> dict[str, list[str]]:
    """member -> sorted roles, from every IAM resource (the service-identity view)."""
    matrix: dict[str, set[str]] = defaultdict(set)
    for res in res_list:
        if IAM_KIND.match(str(res.get("type", ""))):
            for role, member in iam_grants(res):
                matrix[member].add(role)
    return {m: sorted(r) for m, r in sorted(matrix.items())}


def check_identities(matrix: dict[str, list[str]]) -> list[Finding]:
    out: list[Finding] = []
    for member, roles in matrix.items():
        if not member.startswith("serviceAccount:"):
            continue
        risky = [r for r in roles if r in PRIMITIVE_ROLES or r in ESCALATION_ROLES or ADMIN_ROLE.match(r)]
        if len(risky) > 1 or len(roles) >= 6:
            out.append(Finding(
                rule_id="GCP-SA-OVERPRIVILEGED", title="Service identity holds many or several privileged roles",
                severity="high" if risky else "medium", category="service-identity", resource=member, location=member,
                evidence={"roles": roles, "privileged": risky},
                recommendation="Split into per-workload service accounts, each with the minimum roles."))
    return out


def analyze_file(path: Path, **opts: Any) -> AnalysisReport:
    data = load_structured(Path(path))
    if not looks_like_terraform_json(data):
        raise ValueError("not `terraform show -json` output (no values/planned_values/resource_changes)")
    res_list = resources(data)
    findings = [f for res in res_list for check in CHECKS for f in check(res)]
    matrix = identity_matrix(res_list)
    findings.extend(check_identities(matrix))
    service_accounts = sorted({str((r.get("values") or {}).get("email") or r.get("address"))
                               for r in res_list if r.get("type") == "google_service_account"})
    by_type: dict[str, int] = defaultdict(int)
    for r in res_list:
        by_type[str(r.get("type"))] += 1
    score = min(100, sum(SEVERITY_WEIGHTS[f.severity] for f in findings))
    return AnalysisReport(
        pack="gcp_sre", tool=TOOL, input=str(path), findings=findings,
        metrics={"source": "state" if "values" in data else "plan", "google_resources": len(res_list),
                 "resources_by_type": dict(sorted(by_type.items())), "service_accounts": service_accounts,
                 "identity_matrix": matrix, "risk_score": score},
        summary=f"{len(findings)} finding(s) across {len(res_list)} GCP resource(s); risk score {score}/100")
