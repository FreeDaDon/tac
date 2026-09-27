import json

from core.soc.vuln_triage import Vuln, analyze_file, parse_kev, prioritize


def v(**kw):
    base = {"vuln_id": "CVE-2000-0001", "package": "p", "installed": "1", "fixed_version": "", "severity": "low",
            "cvss": None, "epss": None, "target": "t", "title": "", "source": "test"}
    return Vuln(**(base | kw))


def test_trivy_fixture_order_and_priorities(fixtures):
    report = analyze_file(fixtures / "soc" / "trivy.json")
    got = [(f.evidence["vuln_id"], f.evidence["priority"]) for f in report.findings]
    assert got == [("CVE-2021-44228", "P1"), ("CVE-2022-42889", "P2"), ("CVE-2024-2961", "P3"),
                   ("CVE-2023-2976", "P3"), ("CVE-2020-8908", "P4")]
    assert report.findings[0].severity == "critical" and report.findings[0].evidence["kev"] is True
    assert report.metrics["by_priority"] == {"P1": 1, "P2": 1, "P3": 2, "P4": 1}
    assert report.metrics["kev_matches"] == 1 and report.metrics["fixable"] == 3


def test_grype_fixture(fixtures):
    report = analyze_file(fixtures / "soc" / "grype.json")
    got = [(f.evidence["vuln_id"], f.evidence["priority"]) for f in report.findings]
    assert got == [("CVE-2023-44487", "P1"), ("CVE-2021-3121", "P2"), ("CVE-2023-39325", "P3"),
                   ("GHSA-vvpx-j8f3-3w6h", "P3"), ("CVE-2022-28948", "P4")]
    ghsa = next(f for f in report.findings if f.evidence["vuln_id"].startswith("GHSA"))
    assert ghsa.evidence["aliases"] == ["CVE-2022-41723"] and ghsa.evidence["epss"] == 0.2


def test_kev_alias_match_and_explicit_kev(tmp_path, fixtures):
    kev = tmp_path / "k.json"
    kev.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2022-41723"}]}))
    report = analyze_file(fixtures / "soc" / "grype.json", kev=kev)
    ghsa = next(f for f in report.findings if f.evidence["vuln_id"].startswith("GHSA"))
    assert ghsa.evidence["priority"] == "P1"
    # without the fixture kev.json's entry, Log4Shell is only P2 (CVSS 10, no EPSS)
    trivy = analyze_file(fixtures / "soc" / "trivy.json", kev=kev)
    assert trivy.findings[0].evidence["priority"] == "P2"


def test_prioritize_rules():
    none = frozenset[str]()
    assert prioritize(v(cvss=9.8, epss=0.6), none)[0] == "P1"
    assert prioritize(v(cvss=9.8), none)[0] == "P2"
    assert prioritize(v(cvss=7.5, epss=0.2), none)[0] == "P2"
    assert prioritize(v(cvss=7.5), none)[0] == "P3"
    assert prioritize(v(cvss=5.0, fixed_version="2"), none)[0] == "P3"
    assert prioritize(v(cvss=5.0), none)[0] == "P4"
    assert prioritize(v(severity="critical"), none)[0] == "P2"  # no CVSS: severity default 9.5
    assert prioritize(v(cvss=2.0), frozenset({"CVE-2000-0001"}))[0] == "P1"


def test_parse_kev_formats():
    assert parse_kev(["cve-1"]) == frozenset({"CVE-1"})
    assert parse_kev({"cveIDs": ["CVE-2"], "vulnerabilities": [{"cveID": "CVE-3"}]}) == frozenset({"CVE-2", "CVE-3"})
