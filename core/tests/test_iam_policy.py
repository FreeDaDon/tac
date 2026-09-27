import json

import pytest

from core.common import SEVERITY_ORDER
from core.iam.policy import analyze_file, extract_document, is_write_action, lint_policy


def doc(*statements, version="2012-10-17"):
    return {"Version": version, "Statement": list(statements)}


def ids(policy):
    return sorted(f.rule_id for f in lint_policy(policy))


def test_admin_policy_is_critical(fixtures):
    report = analyze_file(fixtures / "iam" / "policies" / "admin.json")
    assert [(f.rule_id, f.severity) for f in report.findings] == [("IAM001", "critical")]
    assert report.findings[0].resource.endswith("#BreakGlass")


def test_least_privilege_policy_is_clean(fixtures):
    report = analyze_file(fixtures / "iam" / "policies" / "least_privilege.json")
    assert report.findings == []
    assert not report.blocking("high")


def test_overly_broad_policy(fixtures):
    report = analyze_file(fixtures / "iam" / "policies" / "overly_broad.json")
    got = sorted((f.rule_id, f.resource.rsplit("#", 1)[1]) for f in report.findings)
    assert got == [("IAM002", "S3Everything"), ("IAM003", "LaunchAnything"), ("IAM004", "AllButIam"),
                   ("IAM006", "LaunchAnything"), ("IAM008", "RotateOwnKeys"), ("IAM008", "S3Everything")]
    iam003 = next(f for f in report.findings if f.rule_id == "IAM003")
    assert iam003.evidence["actions"] == ["ec2:RunInstances", "iam:PassRole"]
    assert report.max_severity == "high"


def test_trust_policy(fixtures):
    report = analyze_file(fixtures / "iam" / "policies" / "trust_any_principal.json")
    assert [(f.rule_id, f.severity) for f in report.findings] == [("IAM007", "critical")]
    conditioned = doc({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
                       "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-123"}}})
    assert [(f.rule_id, f.severity) for f in lint_policy(conditioned)] == [("IAM007", "medium")]
    named = doc({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:root"}, "Action": "sts:AssumeRole"})
    assert lint_policy(named) == []


def test_individual_rules():
    assert ids(doc({"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b"})) == ["IAM002", "IAM008"]
    assert ids(doc({"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::b"})) == ["IAM005"]
    assert ids(doc({"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::1:role/app"})) == []
    assert ids(doc({"Effect": "Allow", "Action": "iam:CreateUser", "Resource": "arn:aws:iam::1:user/*",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}})) == []
    assert ids(doc({"Effect": "Deny", "Action": "*", "Resource": "*"})) == []
    assert ids(doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}, version="2008-10-17")) == ["IAM009"]
    assert ids(doc({"Action": "s3:GetObject", "Resource": "*"})) == ["IAM010"]
    assert ids(doc({"Effect": "Allow", "Action": "S3:Put*", "Resource": "*"})) == ["IAM003"]


@pytest.mark.parametrize(("action", "write"), [
    ("s3:GetObject", False), ("ec2:DescribeInstances", False), ("s3:List*", False),
    ("s3:PutObject", True), ("iam:PassRole", True), ("*", True), ("s3:*", True),
])
def test_is_write_action(action, write):
    assert is_write_action(action) is write


def test_extract_wrappers():
    inner = doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"})
    assert extract_document({"PolicyVersion": {"Document": json.dumps(inner)}}) == inner
    assert extract_document({"Role": {"AssumeRolePolicyDocument": inner}}) == inner
    with pytest.raises(ValueError):
        extract_document({"users": []})


def test_no_high_findings_threshold(fixtures):
    report = analyze_file(fixtures / "iam" / "policies" / "least_privilege.json")
    assert all(SEVERITY_ORDER[f.severity] < SEVERITY_ORDER["high"] for f in report.findings)
