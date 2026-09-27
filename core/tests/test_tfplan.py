from core.devops.tfplan import analyze_file, analyze_plan, classify_actions, is_critical_type, risk_score


def rc(address, rtype, actions, before=None, after=None):
    return {"address": address, "mode": "managed", "type": rtype, "name": address.split(".")[-1],
            "change": {"actions": actions, "before": before, "after": after}}


def test_classify_actions():
    assert classify_actions(["delete", "create"]) == "replace"
    assert classify_actions(["create", "delete"]) == "replace"
    assert classify_actions(["update"]) == "update"
    assert classify_actions(["no-op"]) == "no-op"


def test_critical_types():
    for t in ("aws_db_instance", "aws_s3_bucket", "aws_kms_key", "aws_iam_role", "google_storage_bucket"):
        assert is_critical_type(t), t
    for t in ("aws_instance", "aws_cloudwatch_log_group", "aws_s3_bucket_acl"):
        assert not is_critical_type(t), t


def test_fixture_plan(fixtures):
    report = analyze_file(fixtures / "devops" / "plan.tfplan.json")
    assert report.pack == "devops" and report.tool == "tfplan"
    assert report.metrics["actions"] == {"create": 4, "update": 2, "delete": 2, "replace": 1, "read": 0, "no-op": 0}
    assert report.metrics["resources"] == 9
    got = sorted((f.rule_id, f.resource, f.severity) for f in report.findings)
    assert got == sorted([
        ("TF-REPLACE", "aws_db_instance.main", "critical"),
        ("TF-UNENCRYPTED", "aws_db_instance.main", "high"),
        ("TF-SG-OPEN", "aws_security_group.bastion", "critical"),
        ("TF-S3-PUBLIC", "aws_s3_bucket_acl.assets", "high"),
        ("TF-IAM-POLICY", "aws_iam_role_policy.ci", "critical"),
        ("TF-DESTROY", "aws_cloudwatch_log_group.old_app", "high"),
        ("TF-DESTROY", "aws_kms_key.data", "critical"),
    ])
    assert report.metrics["risk_score"] == 100
    sg = next(f for f in report.findings if f.rule_id == "TF-SG-OPEN")
    assert sg.evidence["ports"] == [22]


def test_safe_plan_has_no_findings():
    plan = {"resource_changes": [
        rc("aws_instance.web", "aws_instance", ["update"], {"instance_type": "t3.small"}, {"instance_type": "t3.medium"}),
        rc("aws_security_group.db", "aws_security_group", ["create"], None,
           {"ingress": [{"from_port": 5432, "to_port": 5432, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/8"]}]}),
        rc("aws_security_group.web", "aws_security_group", ["create"], None,
           {"ingress": [{"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]}),
        rc("aws_ebs_volume.data", "aws_ebs_volume", ["create"], None, {"encrypted": True}),
    ]}
    report = analyze_plan(plan)
    assert report.findings == []
    assert report.metrics["risk_score"] == 0


def test_security_rules():
    plan = {"resource_changes": [
        rc("aws_security_group_rule.all", "aws_security_group_rule", ["create"], None,
           {"type": "ingress", "protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}),
        rc("aws_vpc_security_group_ingress_rule.redis", "aws_vpc_security_group_ingress_rule", ["create"], None,
           {"cidr_ipv4": "0.0.0.0/0", "from_port": 6379, "to_port": 6379, "ip_protocol": "tcp"}),
        rc("aws_s3_bucket_policy.p", "aws_s3_bucket_policy", ["create"], None,
           {"policy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}'}),
        rc("aws_s3_bucket_public_access_block.b", "aws_s3_bucket_public_access_block", ["update"], {},
           {"block_public_acls": False, "block_public_policy": True, "ignore_public_acls": True,
            "restrict_public_buckets": True}),
        rc("aws_ebs_volume.v", "aws_ebs_volume", ["create"], None, {"encrypted": False}),
        rc("aws_iam_policy.p", "aws_iam_policy", ["create"], None,
           {"policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}'}),
        rc("aws_s3_bucket.b", "aws_s3_bucket", ["update"], {"acl": "private"}, {"acl": "private"}),
    ]}
    by_addr = {(f.resource, f.rule_id): f.severity for f in analyze_plan(plan).findings}
    assert by_addr == {
        ("aws_security_group_rule.all", "TF-SG-OPEN"): "critical",
        ("aws_vpc_security_group_ingress_rule.redis", "TF-SG-OPEN"): "high",
        ("aws_s3_bucket_policy.p", "TF-S3-PUBLIC"): "critical",
        ("aws_s3_bucket_public_access_block.b", "TF-S3-PUBLIC"): "medium",
        ("aws_ebs_volume.v", "TF-UNENCRYPTED"): "high",
        ("aws_iam_policy.p", "TF-IAM-POLICY"): "high",
        ("aws_s3_bucket.b", "TF-SENSITIVE-UPDATE"): "medium",
    }


def test_risk_score_caps():
    plan = {"resource_changes": [rc(f"aws_kms_key.k{i}", "aws_kms_key", ["delete"], {}, None) for i in range(5)]}
    report = analyze_plan(plan)
    assert risk_score(report.findings) == 100
    assert analyze_plan({"resource_changes": [rc("aws_sqs_queue.q", "aws_sqs_queue", ["delete"], {}, None)]}
                        ).metrics["risk_score"] == 20
