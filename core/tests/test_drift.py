import json

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


HUNTER = "hunter2" + "Zx8kQ2mV"


def _dump(value) -> str:
    return json.dumps(value)


def test_secrets_never_reach_drift_evidence():
    before = {"env": [{"name": "DB_PASS", "value": HUNTER}], "access_key": "AKIA" + "OLDOLDOLDOLD1234",
              "api_key": "k1-" + HUNTER, "connection_string": f"postgres://app:{HUNTER}@db/x", "user_data": "a",
              "command": "run"}
    after = {"env": [{"name": "DB_PASS", "value": HUNTER + "x"}, {"name": "MODE", "value": "fast"}],
             "access_key": "AKIA" + "NEWNEWNEWNEW1234", "api_key": "k2-" + HUNTER,
             "connection_string": f"postgres://app:{HUNTER}x@db/x", "user_data": f"PASSWORD={HUNTER}",
             "command": f"start --token={HUNTER}"}
    attrs = diff_attributes(before, after)
    assert {a["path"] for a in attrs} == {"env", "access_key", "api_key", "connection_string", "user_data", "command"}
    assert HUNTER not in _dump(attrs) and "OLDOLDOLDOLD" not in _dump(attrs)
    env = next(a for a in attrs if a["path"] == "env")
    assert env["after"] == [{"name": "DB_PASS", "value": "<redacted>"}, {"name": "MODE", "value": "fast"}]


def test_terraform_sensitivity_markers_are_honored(tmp_path):
    plan = {"resource_drift": [{"address": "x.y", "type": "x", "change": {
        "actions": ["update"], "before": {"settings": {"value": "plain-one"}}, "after": {"settings": {"value": "plain-two"}},
        "before_sensitive": {}, "after_sensitive": {"settings": {"value": True}}}}]}
    [finding] = drift_from_plan(plan)
    assert finding.evidence["attributes"] == [{"path": "settings.value", "before": "<redacted>", "after": "<redacted>"}]

    def raw(value):
        return {"version": 4, "resources": [{"mode": "managed", "type": "x", "name": "y", "instances": [
            {"attributes": {"opaque": value}, "sensitive_attributes": [[{"type": "get_attr", "value": "opaque"}]]}]}]}

    def shown(value):
        return {"values": {"root_module": {"resources": [{"address": "x.y", "type": "x", "values": {"opaque": value},
                                                          "sensitive_values": {"opaque": True}}]}}}

    for build in (raw, shown):
        [finding] = compare_states(build("plain-one"), build("plain-two"))
        assert "plain-" not in finding.model_dump_json()


def test_security_keywords_match_whole_words():
    assert drift_from_plan({"resource_drift": [{"address": "db", "type": "t", "change": {
        "actions": ["update"], "before": {"engine_oracle_version": "19"}, "after": {"engine_oracle_version": "21"}}}]}
    )[0].severity == "medium"
    assert drift_from_plan({"resource_drift": [{"address": "db", "type": "t", "change": {
        "actions": ["update"], "before": {"storage_encrypted": True}, "after": {"storage_encrypted": False}}}]}
    )[0].severity == "high"
