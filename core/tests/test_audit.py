from datetime import date

from core.iam.audit import AuditConfig, analyze_file, audit_user, parse_date


def test_fixture_inventory(fixtures):
    report = analyze_file(fixtures / "iam" / "inventory.json")
    got = sorted((f.rule_id, f.resource, f.severity) for f in report.findings)
    assert got == [
        ("AUD-ADMIN-SPRAWL", "inventory", "medium"),
        ("AUD-DORMANT", "carol", "medium"),
        ("AUD-DORMANT", "svc-legacy", "high"),
        ("AUD-NEVER-USED", "dave", "medium"),
        ("AUD-NO-MFA-ADMIN", "bob", "high"),
        ("AUD-STALE-KEY", "svc-ci", "medium"),
        ("AUD-STALE-KEY", "svc-legacy", "medium"),
    ]
    assert report.metrics["as_of"] == "2025-06-30"
    assert report.metrics["admins"] == 5 and report.metrics["users"] == 9
    sprawl = next(f for f in report.findings if f.rule_id == "AUD-ADMIN-SPRAWL")
    assert sprawl.evidence["admins"] == ["alice", "bob", "frank", "gina", "svc-legacy"]
    legacy_key = next(f for f in report.findings if f.rule_id == "AUD-STALE-KEY" and f.resource == "svc-legacy")
    assert legacy_key.evidence["key_id"] == "AKIA" + "EXAMPLELEGACY001"  # inactive key 002 ignored
    assert legacy_key.evidence["reasons"] == ["created 532 days ago", "unused for 302 days"]


def test_as_of_and_thresholds_are_options(fixtures):
    later = analyze_file(fixtures / "iam" / "inventory.json", as_of="2025-12-31", max_admins=10)
    assert later.metrics["as_of"] == "2025-12-31"
    assert "AUD-ADMIN-SPRAWL" not in {f.rule_id for f in later.findings}
    assert ("AUD-NEVER-USED", "eve") in {(f.rule_id, f.resource) for f in later.findings}
    lenient = analyze_file(fixtures / "iam" / "inventory.json", dormant_days=400, key_max_age_days=1000,
                           key_unused_days=1000)
    assert not {f.rule_id for f in lenient.findings} & {"AUD-DORMANT", "AUD-STALE-KEY"}


def test_clean_user():
    cfg = AuditConfig(as_of=date(2025, 6, 30))
    user = {"name": "ok", "type": "human", "created": "2024-01-01", "last_login": "2025-06-29", "mfa_enabled": True,
            "attached_policies": ["AdministratorAccess"],
            "access_keys": [{"id": "k", "created": "2025-06-01", "last_used": "2025-06-29"}]}
    assert audit_user(user, cfg) == []


def test_parse_date():
    assert parse_date("2025-06-30") == date(2025, 6, 30)
    assert parse_date("2025-06-30T23:30:00-02:00") == date(2025, 7, 1)
    assert parse_date(None) is None
