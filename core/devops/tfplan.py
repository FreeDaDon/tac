"""Risk review of `terraform show -json plan.out` output."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from core.common import SEVERITY_ORDER, AnalysisReport, Finding, FindingSeverity
from core.iam.policy import lint_policy

TOOL = "tfplan"

# Stateful or security-critical resource types: destroying/replacing them is critical and they should carry
# `lifecycle { prevent_destroy = true }`.
CRITICAL_TYPE_PATTERNS = tuple(re.compile(p) for p in (
    r"^aws_(db_instance|rds_cluster|rds_cluster_instance|dynamodb_table|redshift_cluster|docdb_cluster|neptune_cluster"
    r"|elasticache_\w+|efs_file_system|ebs_volume)$",
    r"^aws_s3_bucket$", r"^aws_kms_\w+$", r"^aws_iam_\w+$", r"^aws_secretsmanager_secret$",
    r"^google_(sql_database_instance|sql_database|storage_bucket|bigquery_dataset|kms_\w+|spanner_\w+)$",
    r"^google_\w*iam\w*$", r"^azurerm_(\w*sql\w*|storage_account|key_vault\w*|cosmosdb_\w+|role_\w+)$",
))
SENSITIVE_PORTS = {22: "ssh", 23: "telnet", 21: "ftp", 3389: "rdp", 3306: "mysql", 5432: "postgres",
                   1433: "mssql", 1521: "oracle", 27017: "mongodb", 6379: "redis", 9200: "elasticsearch",
                   5601: "kibana", 11211: "memcached", 2375: "docker", 445: "smb", 5900: "vnc"}
ADMIN_PORTS = frozenset({22, 3389})
PUBLIC_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
PUBLIC_ACLS: dict[str, FindingSeverity] = {"public-read": "high", "public-read-write": "critical", "authenticated-read": "high"}
IAM_POLICY_TYPES = frozenset({"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"})
# (type, attribute, value meaning "unencrypted")
UNENCRYPTED_CHECKS: tuple[tuple[str, str], ...] = (
    ("aws_db_instance", "storage_encrypted"), ("aws_rds_cluster", "storage_encrypted"),
    ("aws_ebs_volume", "encrypted"), ("aws_efs_file_system", "encrypted"), ("aws_redshift_cluster", "encrypted"),
    ("aws_elasticache_replication_group", "at_rest_encryption_enabled"), ("aws_docdb_cluster", "storage_encrypted"),
)
SEVERITY_WEIGHTS = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}


def is_critical_type(resource_type: str) -> bool:
    return any(p.match(resource_type) for p in CRITICAL_TYPE_PATTERNS)


def classify_actions(actions: list[str]) -> str:
    """Map Terraform's action list to one of create|update|delete|replace|read|no-op."""
    s = set(actions)
    if {"delete", "create"} <= s:
        return "replace"
    if len(actions) == 1 and actions[0] in {"create", "update", "delete", "read", "no-op"}:
        return actions[0]
    return "no-op"


def _finding(rc: dict[str, Any], rule_id: str, severity: FindingSeverity, title: str, category: str,
             recommendation: str, **evidence: Any) -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=severity, category=category,
                   resource=rc.get("address", ""), location=rc.get("address", ""),
                   evidence={"type": rc.get("type"), "actions": rc.get("change", {}).get("actions"), **evidence},
                   recommendation=recommendation)


def check_destructive(rc: dict[str, Any]) -> list[Finding]:
    kind = classify_actions(rc.get("change", {}).get("actions", []))
    rtype = rc.get("type", "")
    critical = is_critical_type(rtype)
    if kind == "delete":
        return [_finding(rc, "TF-DESTROY", "critical" if critical else "high", f"Destroys {rtype}", "destructive",
                         "Confirm intent; snapshot/backup first; protect with lifecycle.prevent_destroy.",
                         stateful_or_security_critical=critical)]
    if kind == "replace":
        return [_finding(rc, "TF-REPLACE", "critical" if critical else "high", f"Replaces {rtype} (delete+create)",
                         "destructive", "Find the ForceNew attribute; use create_before_destroy or avoid the change.",
                         stateful_or_security_critical=critical, reason=rc.get("action_reason"),
                         replace_paths=rc.get("change", {}).get("replace_paths"))]
    if kind == "update" and critical:
        return [_finding(rc, "TF-SENSITIVE-UPDATE", "medium", f"In-place update of protected type {rtype}",
                         "change", "Review the attribute diff; ensure prevent_destroy is set on this resource.")]
    return []


def _port_range(rule: dict[str, Any]) -> tuple[int, int]:
    protocol = str(rule.get("protocol", rule.get("ip_protocol", "tcp")))
    if protocol in {"-1", "all"}:
        return 0, 65535
    lo, hi = rule.get("from_port"), rule.get("to_port")
    return int(lo if lo is not None else 0), int(hi if hi is not None else 65535)


def _public_ingress_rules(rtype: str, after: dict[str, Any]) -> list[dict[str, Any]]:
    if rtype == "aws_security_group":
        rules = [r for r in after.get("ingress") or [] if isinstance(r, dict)]
    elif rtype == "aws_security_group_rule" and after.get("type") == "ingress":
        rules = [after]
    elif rtype == "aws_vpc_security_group_ingress_rule":
        rules = [{**after, "cidr_blocks": [after.get("cidr_ipv4")], "ipv6_cidr_blocks": [after.get("cidr_ipv6")]}]
    else:
        return []
    return [r for r in rules
            if PUBLIC_CIDRS & set((r.get("cidr_blocks") or []) + (r.get("ipv6_cidr_blocks") or []))]


def check_open_ingress(rc: dict[str, Any], after: dict[str, Any]) -> list[Finding]:
    findings = []
    for rule in _public_ingress_rules(rc.get("type", ""), after):
        lo, hi = _port_range(rule)
        exposed = sorted(p for p in SENSITIVE_PORTS if lo <= p <= hi)
        if not exposed:
            continue
        all_ports = lo == 0 and hi >= 65535
        severity: FindingSeverity = "critical" if all_ports or ADMIN_PORTS & set(exposed) else "high"
        findings.append(_finding(
            rc, "TF-SG-OPEN", severity, f"Ingress from the internet to {', '.join(SENSITIVE_PORTS[p] for p in exposed)}",
            "network", "Restrict the CIDR to known ranges or use SSM/bastion/VPN.",
            from_port=lo, to_port=hi, ports=exposed))
    return findings


def _policy_doc(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip().startswith("{"):
        try:
            doc = json.loads(value)
        except json.JSONDecodeError:
            return None
        return doc if isinstance(doc, dict) else None
    return None


def check_public_s3(rc: dict[str, Any], after: dict[str, Any]) -> list[Finding]:
    rtype = rc.get("type", "")
    if rtype in {"aws_s3_bucket", "aws_s3_bucket_acl"} and after.get("acl") in PUBLIC_ACLS:
        acl = after["acl"]
        return [_finding(rc, "TF-S3-PUBLIC", PUBLIC_ACLS[acl], f"Bucket ACL `{acl}` makes objects public",
                         "exposure", "Use private ACLs, bucket ownership controls and a public access block.", acl=acl)]
    if rtype == "aws_s3_bucket_policy":
        doc = _policy_doc(after.get("policy")) or {}
        public = [s for s in doc.get("Statement", []) if isinstance(s, dict) and s.get("Effect") == "Allow"
                  and s.get("Principal") in ("*", {"AWS": "*"}) and not s.get("Condition")]
        if public:
            return [_finding(rc, "TF-S3-PUBLIC", "critical", "Bucket policy allows anonymous access", "exposure",
                             "Remove Principal \"*\" or add restrictive conditions (aws:SourceVpce, aws:PrincipalOrgID).",
                             statements=public)]
    if rtype == "aws_s3_bucket_public_access_block":
        disabled = sorted(k for k in ("block_public_acls", "block_public_policy", "ignore_public_acls",
                                      "restrict_public_buckets") if after.get(k) is False)
        if disabled:
            return [_finding(rc, "TF-S3-PUBLIC", "medium", "S3 public access block partially disabled", "exposure",
                             "Enable all four public access block settings.", disabled=disabled)]
    return []


def check_encryption(rc: dict[str, Any], after: dict[str, Any]) -> list[Finding]:
    rtype = rc.get("type", "")
    for check_type, attr in UNENCRYPTED_CHECKS:
        if rtype == check_type and after.get(attr) is False:
            return [_finding(rc, "TF-UNENCRYPTED", "high", f"{rtype} storage is not encrypted at rest", "encryption",
                             f"Set {attr} = true (with a customer-managed KMS key where required).", attribute=attr)]
    return []


def check_iam_policy(rc: dict[str, Any], after: dict[str, Any]) -> list[Finding]:
    if rc.get("type") not in IAM_POLICY_TYPES:
        return []
    doc = _policy_doc(after.get("policy"))
    if doc is None:
        return []
    return [
        _finding(rc, "TF-IAM-POLICY", f.severity, f"Inline IAM policy: {f.title}", "privilege", f.recommendation,
                 iam_rule=f.rule_id, statement=f.evidence.get("statement"))
        for f in lint_policy(doc, rc.get("address", ""))
        if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER["high"]
    ]


def analyze_resource_change(rc: dict[str, Any]) -> list[Finding]:
    findings = check_destructive(rc)
    after = rc.get("change", {}).get("after")
    if isinstance(after, dict):
        for check in (check_open_ingress, check_public_s3, check_encryption, check_iam_policy):
            findings.extend(check(rc, after))
    return findings


def risk_score(findings: list[Finding]) -> int:
    return min(100, sum(SEVERITY_WEIGHTS[f.severity] for f in findings))


def managed_changes(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [rc for rc in plan.get("resource_changes", []) if rc.get("mode", "managed") == "managed"]


def analyze_plan(plan: dict[str, Any], source: str = "") -> AnalysisReport:
    changes = managed_changes(plan)
    findings = [f for rc in changes for f in analyze_resource_change(rc)]
    counts = Counter(classify_actions(rc.get("change", {}).get("actions", [])) for rc in changes)
    by_action = {k: counts.get(k, 0) for k in ("create", "update", "delete", "replace", "read", "no-op")}
    score = risk_score(findings)
    return AnalysisReport(
        pack="devops", tool=TOOL, input=source, findings=findings,
        metrics={"actions": by_action, "resources": len(changes), "risk_score": score,
                 "terraform_version": plan.get("terraform_version")},
        summary=f"{by_action['create']} create, {by_action['update']} update, {by_action['delete']} delete, "
        f"{by_action['replace']} replace; risk score {score}/100",
    )


def load_plan(path: Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("plan JSON must be an object")
    return data


def analyze_file(path: Path, **opts: Any) -> AnalysisReport:
    return analyze_plan(load_plan(path), str(path))
