"""Drift detection: a plan's `resource_drift` section, or a diff of two Terraform state JSON files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.common import AnalysisReport, Finding, FindingSeverity

TOOL = "drift"
SECURITY_ATTR_KEYWORDS = ("ingress", "egress", "policy", "acl", "encrypt", "public", "cidr", "kms", "iam", "role",
                          "security_group", "password", "ssl", "tls", "logging", "versioning")
SECRET_ATTR_KEYWORDS = ("password", "secret", "token", "private_key")
IGNORED_ATTRS = frozenset({"tags_all"})


def _mask(path: str, value: Any) -> Any:
    return "<redacted>" if any(k in path.lower() for k in SECRET_ATTR_KEYWORDS) and value is not None else value


def diff_attributes(before: Any, after: Any, prefix: str = "") -> list[dict[str, Any]]:
    """Recursive attribute diff -> [{path, before, after}] (secret-looking values masked)."""
    if isinstance(before, dict) and isinstance(after, dict):
        diffs: list[dict[str, Any]] = []
        for key in sorted(set(before) | set(after)):
            if not prefix and key in IGNORED_ATTRS:
                continue
            path = f"{prefix}.{key}" if prefix else str(key)
            diffs.extend(diff_attributes(before.get(key), after.get(key), path))
        return diffs
    if isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        return [d for i, (b, a) in enumerate(zip(before, after, strict=True))
                for d in diff_attributes(b, a, f"{prefix}[{i}]")]
    if before == after:
        return []
    return [{"path": prefix, "before": _mask(prefix, before), "after": _mask(prefix, after)}]


def _drift_severity(attrs: list[dict[str, Any]]) -> FindingSeverity:
    paths = [a["path"].lower() for a in attrs]
    if any(k in p for p in paths for k in SECURITY_ATTR_KEYWORDS):
        return "high"
    if all(p.startswith("tags") for p in paths):
        return "low"
    return "medium"


def _changed(address: str, rtype: str, attrs: list[dict[str, Any]]) -> Finding:
    return Finding(
        rule_id="TF-DRIFT", title=f"{address} drifted ({len(attrs)} attribute(s))", severity=_drift_severity(attrs),
        category="drift", resource=address, location=address,
        evidence={"type": rtype, "attributes": attrs},
        recommendation="Decide per attribute: codify the out-of-band change in Terraform, or re-apply to revert it. "
        "Find who changed it (CloudTrail) before reverting security settings.",
    )


def _missing(address: str, rtype: str, rule_id: str, title: str, severity: FindingSeverity) -> Finding:
    return Finding(rule_id=rule_id, title=title, severity=severity, category="drift", resource=address,
                   location=address, evidence={"type": rtype},
                   recommendation="Investigate the out-of-band change; re-import or re-create through Terraform.")


def drift_from_plan(plan: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for rc in plan.get("resource_drift", []):
        address, rtype = rc.get("address", ""), rc.get("type", "")
        change = rc.get("change", {})
        if change.get("actions") == ["delete"] or change.get("after") is None:
            findings.append(_missing(address, rtype, "TF-DRIFT-DELETED", f"{address} was deleted outside Terraform",
                                     "high"))
            continue
        attrs = diff_attributes(change.get("before") or {}, change.get("after") or {})
        if attrs:
            findings.append(_changed(address, rtype, attrs))
    return findings


def _module_resources(module: dict[str, Any]) -> list[dict[str, Any]]:
    resources = list(module.get("resources", []))
    for child in module.get("child_modules", []):
        resources.extend(_module_resources(child))
    return resources


def state_resources(state: dict[str, Any]) -> dict[str, tuple[str, dict[str, Any]]]:
    """address -> (type, attributes) for `terraform show -json` state or a raw v4 .tfstate file."""
    out: dict[str, tuple[str, dict[str, Any]]] = {}
    if "values" in state:
        for r in _module_resources(state.get("values", {}).get("root_module", {})):
            if r.get("mode", "managed") == "managed":
                out[r["address"]] = (r.get("type", ""), r.get("values") or {})
        return out
    for r in state.get("resources", []):
        if r.get("mode", "managed") != "managed":
            continue
        base = f"{r['module']}.{r['type']}.{r['name']}" if r.get("module") else f"{r['type']}.{r['name']}"
        for inst in r.get("instances", []):
            key = inst.get("index_key")
            suffix = "" if key is None else (f"[{key}]" if isinstance(key, int) else f'["{key}"]')
            out[base + suffix] = (r.get("type", ""), inst.get("attributes") or {})
    return out


def compare_states(baseline: dict[str, Any], current: dict[str, Any]) -> list[Finding]:
    before, after = state_resources(baseline), state_resources(current)
    findings: list[Finding] = []
    for address in sorted(set(before) | set(after)):
        if address not in after:
            findings.append(_missing(address, before[address][0], "TF-DRIFT-DELETED",
                                     f"{address} missing from current state", "high"))
        elif address not in before:
            findings.append(_missing(address, after[address][0], "TF-DRIFT-ADDED",
                                     f"{address} appeared in current state", "medium"))
        else:
            attrs = diff_attributes(before[address][1], after[address][1])
            if attrs:
                findings.append(_changed(address, after[address][0], attrs))
    return findings


def _load(path: Path | str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return data


def analyze_file(path: Path, compare_to: Path | str | None = None, **opts: Any) -> AnalysisReport:
    """Plan JSON -> resource_drift review; with `compare_to`, `path` is the baseline state and `compare_to` current."""
    if compare_to:
        findings = compare_states(_load(path), _load(compare_to))
        source = f"{path} -> {compare_to}"
    else:
        findings = drift_from_plan(_load(path))
        source = str(path)
    return AnalysisReport(
        pack="devops", tool=TOOL, input=source, findings=findings,
        metrics={"drifted_resources": len(findings),
                 "drifted_attributes": sum(len(f.evidence.get("attributes", [])) for f in findings)},
        summary=f"{len(findings)} resource(s) drifted" if findings else "No drift detected",
    )
