import json

from core.common import AnalysisReport, Finding
from core.export.jsonout import to_dict, to_json
from core.export.markdown import render_report, render_reports
from core.export.sarif import parse_location, to_sarif, to_sarif_json

HOSTILE = "evil | `rm -rf /` <script>alert(1)</script>\n# injected heading \u202e"


def sample_reports():
    findings = [
        Finding(rule_id="R-CRIT", title=HOSTILE, severity="critical", category="c", resource="src/a.py",
                location="src/a.py:12", evidence={"x": HOSTILE}, recommendation="fix"),
        Finding(rule_id="R-MED", title="medium thing", severity="medium", category="c", resource="aws_s3_bucket.b",
                location="aws_s3_bucket.b"),
        Finding(rule_id="R-CRIT", title="again", severity="critical", category="c", location="src/b.py:3"),
        Finding(rule_id="R-INFO", title="fyi", severity="info", category="c", location="policy.json#Statement[0]"),
    ]
    return [AnalysisReport(pack="swe", tool="t1", input="repo", findings=findings, summary="s"),
            AnalysisReport(pack="iam", tool="t2", input="x.json")]


def test_markdown_structure_and_escaping():
    md = render_reports(sample_reports())
    assert md.startswith("# Analysis Report\n")
    assert "| critical | 2 |" in md and "| medium | 1 |" in md
    assert "### Critical (2)" in md and "### Medium (1)" in md
    assert "No findings." in md
    title_line = next(line for line in md.splitlines() if line.startswith("- **R-CRIT**: evil"))
    assert "&lt;script&gt;" in title_line and "<script>" not in title_line
    assert "\u202e" not in md
    assert "\n# injected" not in md
    assert "evil \\| \\`rm" in md


def test_render_single_report_orders_by_severity():
    md = render_report(sample_reports()[0])
    assert md.index("Critical (2)") < md.index("Medium (1)") < md.index("Info (1)")


def test_json_roundtrip():
    data = json.loads(to_json(sample_reports()))
    assert data["total_findings"] == 4
    assert data["reports"][0]["max_severity"] == "critical"
    assert to_dict([])["reports"] == []


def test_sarif_structure():
    sarif = to_sarif(sample_reports())
    assert sarif["version"] == "2.1.0" and sarif["$schema"].endswith("sarif-2.1.0.json")
    assert len(sarif["runs"]) == 2
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["R-CRIT", "R-MED", "R-INFO"]
    assert [r["defaultConfiguration"]["level"] for r in rules] == ["error", "warning", "note"]
    levels = [r["level"] for r in run["results"]]
    assert levels == ["error", "warning", "error", "note"]
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        assert result["message"]["text"]
    loc = run["results"][0]["locations"][0]["physicalLocation"]
    assert loc == {"artifactLocation": {"uri": "src/a.py"}, "region": {"startLine": 12}}
    assert "locations" not in run["results"][1] and "locations" not in run["results"][3]
    assert sarif["runs"][1]["results"] == [] and sarif["runs"][1]["tool"]["driver"]["rules"] == []
    json.loads(to_sarif_json(sample_reports()))


def test_parse_location():
    assert parse_location("a/b.py:7") == ("a/b.py", 7)
    assert parse_location("a/b.py:0") is None
    assert parse_location("203.0.113.50") is None
    assert parse_location("policy.json#Statement[0]") is None
    assert parse_location("") is None
