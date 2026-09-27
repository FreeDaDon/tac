from datetime import UTC, datetime, timedelta

from core.soc.logs import (
    AuthEvent,
    analyze_file,
    detect_bruteforce,
    detect_impossible_travel,
    haversine_km,
    parse_auth_line,
    parse_json_event,
)

T0 = datetime(2024, 3, 10, 12, 0, tzinfo=UTC)


def fail(ip, user, minutes):
    return AuthEvent(T0 + timedelta(minutes=minutes), "auth", "failure", user, ip)


def test_parse_auth_lines():
    e = parse_auth_line("Mar  5 01:02:03 h sshd[1]: Failed password for invalid user bob from 1.2.3.4 port 22 ssh2")
    assert e and e.outcome == "failure" and e.user == "bob" and e.invalid_user and e.source_ip == "1.2.3.4"
    assert e.timestamp == datetime(2024, 3, 5, 1, 2, 3, tzinfo=UTC)
    a = parse_auth_line("2024-03-10T10:00:00Z h sshd[9]: Accepted publickey for ann from 10.0.0.1 port 5 ssh2")
    assert a and a.outcome == "success" and a.method == "publickey"
    s = parse_auth_line("Mar 10 16:45:12 h sudo:      bob : TTY=pts/2 ; PWD=/ ; USER=root ; COMMAND=/bin/bash -i")
    assert s and s.kind == "sudo" and s.target_user == "root" and s.command == "/bin/bash -i"
    assert parse_auth_line("Mar 10 16:45:12 h CRON[1]: session opened") is None
    assert parse_auth_line("garbage") is None


def test_parse_json_event_geo_variants():
    nested = parse_json_event({"@timestamp": "2024-01-01T00:00:00Z", "event": {"action": "user_login", "outcome": "success"},
                               "user": {"name": "a"}, "source": {"geo": {"location": {"lat": 1, "lon": 2}}}})
    flat = parse_json_event({"@timestamp": "2024-01-01T00:00:00Z", "event.action": "logon", "event.outcome": "failure",
                             "user.name": "a", "geo": {"lat": 3, "lon": 4}})
    assert nested and (nested.lat, nested.lon, nested.outcome) == (1.0, 2.0, "success")
    assert flat and (flat.lat, flat.lon, flat.outcome) == (3.0, 4.0, "failure")
    assert parse_json_event({"@timestamp": "2024-01-01T00:00:00Z", "event": {"action": "file_read"},
                             "user": {"name": "a"}}) is None


def test_auth_log_fixture(fixtures):
    report = analyze_file(fixtures / "soc" / "auth.log")
    assert report.tool == "auth_log"
    got = [(f.rule_id, f.resource, f.severity) for f in report.findings]
    assert got == [
        ("SOC-BRUTEFORCE-SUCCESS", "203.0.113.50", "critical"),
        ("SOC-PASSWORD-SPRAY", "192.0.2.99", "high"),
        ("SOC-UNUSUAL-SUDO", "bob", "high"),
    ]
    brute = report.findings[0]
    assert brute.evidence["failures_in_window"] == 8 and brute.evidence["success_user"] == "root"
    assert brute.location.endswith("auth.log:16")
    assert report.metrics["auth_failures"] == 17 and report.metrics["sudo_events"] == 4


def test_benign_log_has_no_detections(fixtures):
    report = analyze_file(fixtures / "soc" / "auth_benign.log")
    assert report.findings == []
    assert report.metrics["events"] > 0


def test_bruteforce_without_success_is_high():
    events = [fail("5.5.5.5", "root", m) for m in range(6)]
    [f] = detect_bruteforce(events)
    assert (f.rule_id, f.severity) == ("SOC-BRUTEFORCE", "high")


def test_bruteforce_respects_window_and_threshold():
    assert detect_bruteforce([fail("5.5.5.5", "root", m * 5) for m in range(6)]) == []  # spread over 25 min
    assert detect_bruteforce([fail("5.5.5.5", "root", m) for m in range(4)]) == []      # below threshold


def test_haversine():
    assert round(haversine_km(40.7128, -74.006, 51.5074, -0.1278)) == 5570
    assert haversine_km(1, 1, 1, 1) == 0


def test_impossible_travel_fixture(fixtures):
    report = analyze_file(fixtures / "soc" / "events.jsonl")
    assert report.tool == "json_events"
    [f] = report.findings
    assert (f.rule_id, f.resource) == ("SOC-IMPOSSIBLE-TRAVEL", "alice")
    assert f.evidence["from"]["country"] == "US" and f.evidence["to"]["country"] == "GB"
    assert f.evidence["speed_kmh"] > 7000


def test_travel_needs_geo_and_speed():
    ok = [AuthEvent(T0, "auth", "success", "d", lat=48.85, lon=2.35),
          AuthEvent(T0 + timedelta(hours=5), "auth", "success", "d", lat=52.52, lon=13.40)]
    assert detect_impossible_travel(ok) == []
    same_time = [AuthEvent(T0, "auth", "success", "d", lat=48.85, lon=2.35),
                 AuthEvent(T0, "auth", "success", "d", lat=35.68, lon=139.69)]
    [f] = detect_impossible_travel(same_time)
    assert f.evidence["speed_kmh"] is None
