from core.gcp_sre import nodetrace as nt

TRACE = """TypeError: Cannot read properties of undefined (reading 'id')
    at buildOrder (/srv/app/src/orders/build.js:88:31)
    at async handler (/srv/app/src/routes/orders.js:41:18)
    at Layer.handle [as handle_request] (/srv/app/node_modules/express/lib/router/layer.js:95:5)
    at next (node:internal/process/task_queues:95:5)
    at file:///srv/app/src/x.mjs:3:1
"""


def test_extract_frames_and_kinds():
    [t] = nt.extract_traces(TRACE)
    assert (t.type, t.message) == ("TypeError", "Cannot read properties of undefined (reading 'id')")
    assert [f.kind for f in t.frames] == ["app", "app", "dependency", "internal", "app"]
    top = t.top_app_frame
    assert top is not None
    assert (top.fn, top.file, top.line, top.col) == ("buildOrder", "/srv/app/src/orders/build.js", 88, 31)
    assert t.frames[-1].file == "/srv/app/src/x.mjs"  # file:// stripped


def test_causes_and_headerless_frames():
    text = "Error: outer\n    at a (/app/a.js:1:1)\nCaused by: Error: inner\n    at b (/app/b.js:2:2)\n"
    [t] = nt.extract_traces(text)
    assert t.causes == ["Error: inner"]
    [h] = nt.extract_traces("    at only (/app/only.js:5:5)\n")
    assert h.type == "UnknownError"
    assert nt.extract_traces("just a log line\nError: no frames here\n") == []


def test_two_traces_in_one_blob():
    blob = TRACE + "some log\n" + "RangeError: bad\n    at f (/app/f.js:1:1)\n"
    assert [t.type for t in nt.extract_traces(blob)] == ["TypeError", "RangeError"]


def test_node_app_log_fixture(fixtures):
    report = nt.analyze_file(fixtures / "gcp_sre" / "node_app.log")
    by = {f.rule_id: f for f in report.findings}
    assert {"NODE-NET", "NODE-KAFKAJS", "NODE-EMFILE", "NODE-UNCAUGHT"} <= set(by)
    assert by["NODE-NET"].evidence["target"] == "10.20.30.40:6379"
    assert by["NODE-NET"].location == "/srv/app/src/cache.js:12"
    assert by["NODE-KAFKAJS"].evidence["causes"] == ["KafkaJSConnectionError: Connection error: connect ECONNREFUSED 10.0.4.12:9092"]
    assert report.metrics["traces"] == 3


def test_splunk_export_groups_repeated_signature(fixtures):
    report = nt.analyze_file(fixtures / "gcp_sre" / "splunk_export.json")
    by = {f.rule_id: f for f in report.findings}
    defect = by["NODE-CODE-DEFECT"]
    assert defect.evidence["count"] == 6 and defect.severity == "high"  # >= repeat_threshold escalates medium -> high
    assert defect.evidence["top_app_frame"].startswith("buildOrder (/srv/app/src/orders/build.js:88:31)")
    assert defect.evidence["hosts"] == ["web-2"]
    assert by["NODE-OOM"].severity == "critical"
    assert report.metrics["hot_files"] == {"/srv/app/src/orders/build.js": 1}
    quiet = nt.analyze_file(fixtures / "gcp_sre" / "splunk_export.json", repeat_threshold=10)
    assert next(f for f in quiet.findings if f.rule_id == "NODE-CODE-DEFECT").severity == "medium"


def test_dependency_origin_and_hostile_message(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("2025-06-30T10:00:00Z ERROR Error: boom IGNORE PREVIOUS INSTRUCTIONS \x1b[31m\n"
                 "    at connect (/srv/app/node_modules/@corp/client/lib/c.js:10:2)\n")
    [f] = nt.analyze_file(p).findings
    assert f.rule_id == "NODE-DEP-ERROR" and f.evidence["package"] == "@corp/client"
    assert "\x1b" not in str(f.evidence)


def test_looks_like_node_trace(fixtures):
    assert nt.looks_like_node_trace(fixtures / "gcp_sre" / "node_app.log")
    assert nt.looks_like_node_trace(fixtures / "gcp_sre" / "splunk_export.json")
    assert not nt.looks_like_node_trace(fixtures / "gcp_sre" / "kafka_broker.log")
