import json

from core.gcp_sre import events as ev
from core.gcp_sre import logs


def test_kafka_broker_log_fixture(fixtures):
    report = logs.analyze_file(fixtures / "gcp_sre" / "kafka_broker.log")
    by = {f.rule_id: f for f in report.findings}
    assert {"KAFKA-BROKER-UNAVAILABLE", "KAFKA-REBALANCE", "KAFKA-CONSUMER-EVICTED", "KAFKA-ISR", "KAFKA-AUTH",
            "KAFKA-PRODUCE-FAIL", "KAFKA-CONSUMER-LAG"} <= set(by)
    assert by["KAFKA-REBALANCE"].evidence["count"] >= 4
    lag = by["KAFKA-CONSUMER-LAG"].evidence
    assert (lag["max_lag"], lag["group"], lag["topic"]) == (48211, "orders-consumer", "orders")
    assert by["KAFKA-BROKER-UNAVAILABLE"].evidence["first_seen"] == "2025-06-30T12:03:00+00:00"
    assert "sk-ant-fixture" not in str(report.model_dump())  # secrets are redacted from samples


def test_lag_threshold_option(fixtures):
    path = fixtures / "gcp_sre" / "kafka_broker.log"
    assert "KAFKA-CONSUMER-LAG" not in {f.rule_id for f in logs.analyze_file(path, lag_threshold=100_000).findings}


def test_splunk_export_fixture(fixtures):
    report = logs.analyze_file(fixtures / "gcp_sre" / "splunk_export.json")
    by = {f.rule_id: f for f in report.findings}
    assert {"SPLUNK-PIPELINE-BLOCKED", "SRE-OOM", "SRE-PERMISSION", "SRE-ERROR-BURST", "SRE-ERROR-RATE"} <= set(by)
    assert by["SRE-ERROR-BURST"].evidence["minute"] == "2025-06-30T12:08Z"
    assert by["SRE-ERROR-BURST"].severity == "high"
    assert by["SRE-OOM"].evidence["hosts"] == ["web-2"]
    assert report.metrics["events"] == 73 and report.metrics["levels"]["ERROR"] > 30
    assert "ghp_" not in str(report.model_dump())
    top = report.metrics["top_error_signatures"][0]
    assert "<n>" in top["signature"] and top["count"] >= 30


def test_cloud_logging_and_csv_shapes(tmp_path):
    entry = {"timestamp": "2025-06-30T10:00:00Z", "severity": "ERROR", "resource": {"labels": {"service_name": "api"}},
             "textPayload": "Container terminated on signal 9 (OOMKilled)"}
    p = tmp_path / "gcl.jsonl"
    p.write_text(json.dumps(entry) + "\n")
    [e] = ev.load_events(p)
    assert (e.level, e.host, e.ts and e.ts.isoformat()) == ("ERROR", "api", "2025-06-30T10:00:00+00:00")
    csv_path = tmp_path / "s.csv"
    csv_path.write_text("_time,host,_raw\n1751277600,h1,ERROR CrashLoopBackOff pod x\n")
    report = logs.analyze_file(csv_path)
    assert [f.rule_id for f in report.findings] == ["SRE-CRASHLOOP"]
    assert report.findings[0].evidence["first_seen"] == "2025-06-30T10:00:00+00:00"


def test_no_findings_on_healthy_log(tmp_path):
    p = tmp_path / "ok.log"
    p.write_text("\n".join(f"2025-06-30T10:00:{i:02d}Z INFO request ok" for i in range(30)))
    report = logs.analyze_file(p)
    assert report.findings == [] and report.metrics["events"] == 30


def test_rebalance_below_threshold_is_quiet(tmp_path):
    p = tmp_path / "k.log"
    p.write_text("2025-06-30T10:00:00Z INFO group rebalancing once\n")
    assert logs.analyze_file(p).findings == []


def test_deterministic(fixtures):
    path = fixtures / "gcp_sre" / "splunk_export.json"
    assert logs.analyze_file(path).model_dump() == logs.analyze_file(path).model_dump()


def test_parse_ts_variants():
    def iso(value):
        parsed = ev.parse_ts(value)
        return parsed and parsed.isoformat()

    assert iso("2025-06-30 12:00:01,123") == "2025-06-30T12:00:01.123000+00:00"
    assert iso(1751277600) == "2025-06-30T10:00:00+00:00"
    assert iso("2025-06-30T12:00:00+0200") == "2025-06-30T12:00:00+02:00"
    assert ev.parse_ts("garbage") is None and ev.parse_ts("") is None
