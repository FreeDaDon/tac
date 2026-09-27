from core.devops.rollback import analyze_file, build_rollback_plan


def test_fixture_rollback_plan(fixtures):
    report = analyze_file(fixtures / "devops" / "plan.tfplan.json")
    plan = report.metrics["rollback_plan"]
    assert plan["status"] == "dry_run"
    steps = plan["steps"]
    assert [s["order"] for s in steps] == list(range(1, 10))
    # reverse plan order
    assert steps[0]["address"] == "aws_kms_key.data" and steps[-1]["address"] == "aws_s3_bucket.logs"
    by_addr = {s["address"]: s for s in steps}
    assert by_addr["aws_s3_bucket.logs"]["rollback_action"] == "destroy_created"
    assert by_addr["aws_instance.web"]["rollback_action"] == "revert_update"
    assert by_addr["aws_instance.web"]["attributes"] == [{"path": "instance_type", "before": "t3.small", "after": "t3.medium"}]
    assert by_addr["aws_db_instance.main"]["rollback_action"] == "restore_replaced"
    assert by_addr["aws_db_instance.main"]["reversible"] is False
    assert by_addr["aws_cloudwatch_log_group.old_app"]["reversible"] is True
    assert sorted(f.resource for f in report.findings) == ["aws_db_instance.main", "aws_kms_key.data"]
    assert report.metrics["irreversible_steps"] == 2
    assert "data.aws_caller_identity.current" not in by_addr


def test_empty_plan():
    plan = build_rollback_plan({"resource_changes": []})
    assert plan.steps == [] and plan.preconditions
