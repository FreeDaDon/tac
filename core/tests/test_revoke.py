from datetime import date

from core.iam.audit import AuditConfig, audit_inventory
from core.iam.revoke import analyze_file, build_revocation_plan


def test_plan_from_fixture(fixtures):
    report = analyze_file(fixtures / "iam" / "inventory.json")
    plan = report.metrics["revocation_plan"]
    assert plan["status"] == "pending_human_approval" and plan["executes"] is False
    steps = [(s["account"], s["action"], s["target"], s["reversible"]) for s in plan["steps"]]
    assert steps == [
        ("bob", "remove_group", "admins", True),
        ("carol", "disable", "", True),
        ("dave", "disable", "", True),
        ("svc-ci", "remove_key", "AKIA" + "EXAMPLESVCCI0001", False),
        ("svc-legacy", "disable", "", True),
        ("svc-legacy", "remove_key", "AKIA" + "EXAMPLELEGACY001", False),
    ]
    assert report.metrics["irreversible_steps"] == 2
    bob = plan["steps"][0]
    assert bob["command_preview"] == "aws iam remove-user-from-group --user-name bob --group-name admins"
    assert "list-access-keys" in plan["steps"][4]["command_preview"]  # service accounts: keys, not console


def test_detach_policy_and_quoting():
    cfg = AuditConfig(as_of=date(2025, 6, 30))
    inventory = {"users": [{"name": "x y", "type": "human", "created": "2025-01-01", "last_login": "2025-06-29",
                            "mfa_enabled": False, "attached_policies": ["AdministratorAccess"]}]}
    findings, _ = audit_inventory(inventory, cfg)
    [step] = build_revocation_plan(findings).steps
    assert step.action == "detach_policy" and step.target == "arn:aws:iam::aws:policy/AdministratorAccess"
    assert "--user-name 'x y'" in step.command_preview


def test_plan_is_deduplicated_and_empty_for_no_findings():
    assert build_revocation_plan([]).steps == []
    assert build_revocation_plan([]).status == "pending_human_approval"
