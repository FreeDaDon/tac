import time
from typing import Any

from core.iam.rbac import analyze_file, check_model, find_cycles, has_permission, resolve_roles


def test_fixture_model(fixtures):
    report = analyze_file(fixtures / "iam" / "rbac_model.yaml")
    got = sorted((f.rule_id, f.resource) for f in report.findings)
    assert got == [
        ("RBAC-ABAC", "user:carol"), ("RBAC-ABAC", "user:dan"), ("RBAC-ADMIN", "user:dan"),
        ("RBAC-SOD", "user:alice"), ("RBAC-SOD", "user:dan"), ("RBAC-UNUSED-ROLE", "role:legacy_ops"),
    ]
    alice = next(f for f in report.findings if f.resource == "user:alice")
    assert alice.evidence["conflict"] == ["payments:create", "payments:approve"]
    assert report.metrics["admin_users"] == ["dan"]
    carol = next(f for f in report.findings if f.rule_id == "RBAC-ABAC" and f.resource == "user:carol")
    assert carol.evidence["failed"] == {"department": {"required": "finance", "actual": "sales"}}


def test_inheritance_resolution():
    roles = {"a": {"permissions": ["x"]}, "b": {"permissions": ["y"], "inherits": ["a"]},
             "c": {"inherits": ["b", "ghost"]}}
    res = resolve_roles(roles)
    assert res.role_permissions["c"] == {"x", "y"}
    assert res.unknown_roles == {"ghost"}
    assert res.cycles == []


def test_cycle_detection_is_safe():
    roles = {"a": {"permissions": ["p:a"], "inherits": ["b"]}, "b": {"permissions": ["p:b"], "inherits": ["c"]},
             "c": {"permissions": ["p:c"], "inherits": ["a"]}, "d": {"inherits": ["a"]}}
    assert find_cycles(roles) == [["a", "b", "c", "a"]]
    res = resolve_roles(roles)
    assert res.role_permissions["a"] == res.role_permissions["d"] == {"p:a", "p:b", "p:c"}
    model = {"roles": roles, "users": {"u": {"roles": ["d"]}}, "sod_rules": [["p:a", "p:c"]]}
    findings, metrics = check_model(model)
    assert {f.rule_id for f in findings} == {"RBAC-CYCLE", "RBAC-SOD"}
    assert metrics["cycles"] == 1


def test_wildcard_permissions_and_clean_model():
    assert has_permission({"payments:*"}, "payments:approve")
    assert not has_permission({"payments:read"}, "payments:approve")
    clean: dict[str, Any] = {"roles": {"r": {"permissions": ["a:read"]}}, "users": {"u": {"roles": ["r"]}},
             "sod_rules": [["a:read", "a:write"]], "abac_policies": [{"permission": "a:read", "require": {"t": ["x", "y"]}}]}
    findings, _ = check_model(clean)
    assert [f.rule_id for f in findings] == ["RBAC-ABAC"]
    clean["users"]["u"]["attributes"] = {"t": "y"}
    assert check_model(clean)[0] == []


def test_unknown_user_role():
    findings, _ = check_model({"roles": {}, "users": {"u": {"roles": ["nope"]}}})
    assert [(f.rule_id, f.resource) for f in findings] == [("RBAC-UNKNOWN-ROLE", "role:nope")]


def test_scalar_strings_are_one_role_not_characters():
    roles: dict[str, Any] = {"viewer": {"permissions": "docs:read"},
                             "editor": {"permissions": ["docs:write"], "inherits": "viewer"}}
    findings, _ = check_model({"roles": roles, "users": {"u": {"roles": "editor"}}})
    assert findings == []
    assert resolve_roles(roles).role_permissions["editor"] == {"docs:read", "docs:write"}


def test_cycle_detection_is_linear_on_wide_layered_graphs():
    layers, width = 40, 3
    roles: dict[str, Any] = {f"r{i}_{j}": {"inherits": [f"r{i + 1}_{k}" for k in range(width)] if i + 1 < layers else []}
                             for i in range(layers) for j in range(width)}
    roles["r39_0"]["inherits"] = ["r0_0"]
    started = time.perf_counter()
    [cycle] = find_cycles(roles)
    assert time.perf_counter() - started < 2
    assert cycle[0] == cycle[-1] == "r0_0" and len(cycle) == layers + 1
    assert find_cycles({"self": {"inherits": "self"}, "deep": {}}) == [["self", "self"]]
    chain = {f"c{i}": {"inherits": [f"c{i + 1}"]} for i in range(5000)}
    assert find_cycles(chain) == []
