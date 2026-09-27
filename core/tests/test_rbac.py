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
