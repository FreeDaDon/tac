from core.soc.zeek import (
    Conn,
    analyze_file,
    detect_beaconing,
    detect_large_outbound,
    detect_port_scan,
    parse_conn_log,
)


def conn(ts, src="10.0.0.1", dst="8.8.8.8", dport=443, ob=100):
    return Conn(ts, src, 40000, dst, dport, "tcp", 0.1, ob, 100, "SF")


def test_parse_header_and_unset_fields(fixtures):
    conns = parse_conn_log((fixtures / "soc" / "conn.log").read_text().splitlines())
    assert len(conns) == 64
    assert conns == sorted(conns, key=lambda c: c.ts)
    scan = [c for c in conns if c.src == "10.0.0.66"]
    assert scan[0].orig_bytes == 0 and scan[0].conn_state == "REJ"


def test_fixture_detections(fixtures):
    report = analyze_file(fixtures / "soc" / "conn.log")
    got = {(f.rule_id, f.resource) for f in report.findings}
    assert got == {
        ("SOC-PORTSCAN", "10.0.0.66"),
        ("SOC-BEACON", "10.0.0.23->185.100.87.202:443"),
        ("SOC-LARGE-OUTBOUND", "10.0.0.40->198.51.100.200"),
    }
    scan = next(f for f in report.findings if f.rule_id == "SOC-PORTSCAN")
    assert scan.evidence["targets"] == 30 and scan.evidence["scan_type"] == "vertical"
    beacon = next(f for f in report.findings if f.rule_id == "SOC-BEACON")
    assert beacon.evidence["connections"] == 15 and beacon.evidence["cv"] < 0.01
    assert round(beacon.evidence["mean_interval_s"]) == 60
    big = next(f for f in report.findings if f.rule_id == "SOC-LARGE-OUTBOUND")
    assert big.evidence["bytes_out"] == 250_000_000 and big.severity == "medium"


def test_irregular_traffic_is_not_beaconing():
    times, t = [], 0.0
    for gap in [3, 45, 7, 120, 15, 300, 2, 60, 33, 9, 200]:
        t += gap
        times.append(t)
    assert detect_beaconing([conn(x) for x in [0.0, *times]]) == []


def test_beacon_needs_min_connections():
    assert detect_beaconing([conn(i * 60.0) for i in range(9)]) == []
    assert len(detect_beaconing([conn(i * 60.0) for i in range(10)])) == 1


def test_scan_threshold_and_outbound_internal_only():
    few = [conn(i * 0.1, dst="10.0.0.9", dport=p) for i, p in enumerate(range(10))]
    assert detect_port_scan(few) == []
    internal = [conn(0, dst="10.0.0.9", ob=10**9)]
    assert detect_large_outbound(internal) == []
    assert detect_large_outbound([conn(0, ob=2 * 10**9)])[0].severity == "high"
