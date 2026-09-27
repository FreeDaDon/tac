from core.devops.drift import analyze_file, compare_states, diff_attributes, drift_from_plan, state_resources


def test_diff_attributes_nested_and_masked():
    before = {"a": 1, "nested": {"b": [1, 2], "password": "old"}, "tags_all": {"x": 1}}
    after = {"a": 1, "nested": {"b": [1, 3], "password": "new"}, "tags_all": {"x": 2}}
    assert diff_attributes(before, after) == [
        {"path": "nested.b[1]", "before": 2, "after": 3},
        {"path": "nested.password", "before": "<redacted>", "after": "<redacted>"},
    ]
    assert diff_attributes({"a": [1]}, {"a": [1, 2]}) == [{"path": "a", "before": [1], "after": [1, 2]}]
    assert diff_attributes({"a": 1}, {"a": 1}) == []


def test_plan_drift_fixture(fixtures):
    report = analyze_file(fixtures / "devops" / "plan.tfplan.json")
    by_res = {f.resource: f for f in report.findings}
    assert set(by_res) == {"aws_security_group.app", "aws_instance.web"}
    sg = by_res["aws_security_group.app"]
    assert sg.severity == "high"
    assert {a["path"] for a in sg.evidence["attributes"]} == {"ingress[0].cidr_blocks[0]", "tags.changed_by"}
    assert by_res["aws_instance.web"].severity == "low"  # tags only
    assert report.metrics == {"drifted_resources": 2, "drifted_attributes": 3}


def test_plan_without_drift():
    assert drift_from_plan({"resource_changes": []}) == []
    deleted = drift_from_plan({"resource_drift": [
        {"address": "aws_sqs_queue.q", "type": "aws_sqs_queue", "change": {"actions": ["delete"], "before": {}, "after": None}}
    ]})
    assert [(f.rule_id, f.severity) for f in deleted] == [("TF-DRIFT-DELETED", "high")]


def test_compare_states_fixture(fixtures):
    state = fixtures / "devops" / "state"
    report = analyze_file(state / "baseline.json", compare_to=state / "current.json")
    got = sorted((f.rule_id, f.resource, f.severity) for f in report.findings)
    assert got == [
        ("TF-DRIFT", "aws_s3_bucket.logs", "high"),
        ("TF-DRIFT", "module.db.aws_db_instance.this", "high"),
        ("TF-DRIFT-ADDED", "aws_lambda_function.hotfix", "medium"),
        ("TF-DRIFT-DELETED", "aws_sns_topic.alerts", "high"),
    ]
    db = next(f for f in report.findings if f.resource == "module.db.aws_db_instance.this")
    assert "rotated-value" not in db.model_dump_json()


def test_raw_tfstate_format():
    raw = {"version": 4, "resources": [
        {"mode": "managed", "type": "aws_instance", "name": "web", "instances": [
            {"index_key": 0, "attributes": {"ami": "a"}}, {"index_key": "b", "attributes": {"ami": "b"}}]},
        {"mode": "data", "type": "aws_ami", "name": "x", "instances": [{"attributes": {}}]},
        {"module": "module.m", "mode": "managed", "type": "aws_sqs_queue", "name": "q", "instances": [{"attributes": {}}]},
    ]}
    assert sorted(state_resources(raw)) == ['aws_instance.web["b"]', "aws_instance.web[0]", "module.m.aws_sqs_queue.q"]
    assert compare_states(raw, raw) == []
