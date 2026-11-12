"""Drift detection: a plan's `resource_drift` section, or a diff of two Terraform state JSON files."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from core.common import AnalysisReport, Finding, FindingSeverity
from core.security.secret_scan import redact_secrets

TOOL = "drift"
REDACTED = "<redacted>"
# Keywords match at the start of an underscore/dash-separated word of an attribute name, so `acl` does not match
# `oracle` and `encrypt` still matches `storage_encrypted`.
_SECURITY_ATTR = re.compile(r"(?:^|[_\-])(?:ingress|egress|policy|acl|encrypt|public|cidr|kms|iam|role|security_group"
                            r"|password|ssl|tls|logging|versioning)")
_SECRET_ATTR = re.compile(r"(?:^|[_\-])(?:(?:pass|pwd)(?:$|[_\-])|password|passwd|passphrase|secret|token|private_?key"
                          r"|access_?key|api_?key|connection_?string|user_?data|credential)")
_ENV_NAME_KEYS = ("name", "key")
IGNORED_ATTRS = frozenset({"tags_all"})


def _segments(path: str) -> list[str]:
    """Attribute names along a path, camelCase split to snake_case: `env[0].dbPassword` -> ["env", "db_password"]."""
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", path).lower()
    return [s for s in re.split(r"[.\[\]]+", snake) if s and not s.isdigit()]


def _is_secret_path(path: str) -> bool:
    return any(_SECRET_ATTR.search(s) for s in _segments(path))


def _child(mask: Any, key: str | int) -> Any:
    if isinstance(mask, dict):
        return mask.get(key, False)
    if isinstance(mask, list) and isinstance(key, int) and key < len(mask):
        return mask[key]
    return False


def _merge_masks(a: Any, b: Any) -> Any:
    """Union of two Terraform sensitivity masks (`true`, or dicts/lists mirroring the value)."""
    if a is True or b is True:
        return True
    if isinstance(a, dict) and isinstance(b, dict):
        return {k: _merge_masks(a.get(k, False), b.get(k, False)) for k in set(a) | set(b)}
    if isinstance(a, list) and isinstance(b, list):
        return [_merge_masks(_child(a, i), _child(b, i)) for i in range(max(len(a), len(b)))]
    return a or b or False


def change_mask(change: dict[str, Any]) -> Any:
    return _merge_masks(change.get("before_sensitive", False), change.get("after_sensitive", False))


def _attribute_paths_mask(paths: Any) -> Any:
    """State v4 `sensitive_attributes` ([[{"type": "get_attr", "value": "password"}], ...]) -> nested mask."""
    mask: dict[Any, Any] = {}
    for steps in paths if isinstance(paths, list) else []:
        keys = [_step_key(s) for s in steps] if isinstance(steps, list) else []
        node = mask
        for key in keys[:-1]:
            if node.get(key) is True:
                break
            node = node.setdefault(key, {})
        else:
            if keys:
                node[keys[-1]] = True
    return mask


def _step_key(step: Any) -> Any:
    """{"type": "get_attr", "value": "password"} -> "password"; {"type": "index", "value": {"value": 0}} -> 0."""
    value = step.get("value") if isinstance(step, dict) else step
    return value.get("value") if isinstance(value, dict) else value


def _scrub(value: Any, path: str = "", mask: Any = False) -> Any:
    """Evidence-safe copy: sensitive-marked or secret-named attributes masked, secrets inside strings redacted, and
    env-style `{name: DB_PASSWORD, value: ...}` entries masked by their name."""
    if value is None:
        return None
    if mask is True or _is_secret_path(path):
        return REDACTED
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, list):
        return [_scrub(v, f"{path}[{i}]", _child(mask, i)) for i, v in enumerate(value)]
    if isinstance(value, dict):
        named = next((str(value[k]) for k in _ENV_NAME_KEYS if isinstance(value.get(k), str)), "")
        secret_entry = bool(named) and _is_secret_path(named)
        return {k: REDACTED if secret_entry and k not in _ENV_NAME_KEYS and v is not None
                else _scrub(v, f"{path}.{k}" if path else str(k), _child(mask, k)) for k, v in value.items()}
    return value


def diff_attributes(before: Any, after: Any, prefix: str = "", sensitive: Any = False) -> list[dict[str, Any]]:
    """Recursive attribute diff -> [{path, before, after}] with values scrubbed for evidence. `sensitive` is the
    Terraform sensitivity mask for this level (plan `before_sensitive`/`after_sensitive`, state `sensitive_values`)."""
    if isinstance(before, dict) and isinstance(after, dict) and sensitive is not True:
        diffs: list[dict[str, Any]] = []
        for key in sorted(set(before) | set(after)):
            if not prefix and key in IGNORED_ATTRS:
                continue
            path = f"{prefix}.{key}" if prefix else str(key)
            diffs.extend(diff_attributes(before.get(key), after.get(key), path, _child(sensitive, key)))
        return diffs
    if isinstance(before, list) and isinstance(after, list) and len(before) == len(after) and sensitive is not True:
        return [d for i, (b, a) in enumerate(zip(before, after, strict=True))
                for d in diff_attributes(b, a, f"{prefix}[{i}]", _child(sensitive, i))]
    if before == after:
        return []
    return [{"path": prefix, "before": _scrub(before, prefix, sensitive), "after": _scrub(after, prefix, sensitive)}]


def _drift_severity(attrs: list[dict[str, Any]]) -> FindingSeverity:
    paths = [a["path"] for a in attrs]
    if any(_SECURITY_ATTR.search(s) for p in paths for s in _segments(p)):
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
        attrs = diff_attributes(change.get("before") or {}, change.get("after") or {}, sensitive=change_mask(change))
        if attrs:
            findings.append(_changed(address, rtype, attrs))
    return findings


def _module_resources(module: dict[str, Any]) -> list[dict[str, Any]]:
    resources = list(module.get("resources", []))
    for child in module.get("child_modules", []):
        resources.extend(_module_resources(child))
    return resources


def state_resources(state: dict[str, Any]) -> dict[str, tuple[str, dict[str, Any], Any]]:
    """address -> (type, attributes, sensitivity mask) for `terraform show -json` state or a raw v4 .tfstate file."""
    out: dict[str, tuple[str, dict[str, Any], Any]] = {}
    if "values" in state:
        for r in _module_resources(state.get("values", {}).get("root_module", {})):
            if r.get("mode", "managed") == "managed":
                out[r["address"]] = (r.get("type", ""), r.get("values") or {}, r.get("sensitive_values", False))
        return out
    for r in state.get("resources", []):
        if r.get("mode", "managed") != "managed":
            continue
        base = f"{r['module']}.{r['type']}.{r['name']}" if r.get("module") else f"{r['type']}.{r['name']}"
        for inst in r.get("instances", []):
            key = inst.get("index_key")
            suffix = "" if key is None else (f"[{key}]" if isinstance(key, int) else f'["{key}"]')
            out[base + suffix] = (r.get("type", ""), inst.get("attributes") or {},
                                  _attribute_paths_mask(inst.get("sensitive_attributes")))
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
            attrs = diff_attributes(before[address][1], after[address][1],
                                    sensitive=_merge_masks(before[address][2], after[address][2]))
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
