import json
import shutil
from pathlib import Path

import pytest

from core.registry import PACK_TOOLS, UnknownInputError, detect_tool, main, run_pack


@pytest.mark.parametrize(("pack", "rel", "tool"), [
    ("devops", "devops/plan.tfplan.json", "tfplan"),
    ("soc", "soc/auth.log", "auth_log"),
    ("soc", "soc/conn.log", "zeek"),
    ("soc", "soc/events.jsonl", "json_events"),
    ("soc", "soc/rules/ssh_bruteforce.yml", "sigma"),
    ("soc", "soc/trivy.json", "vuln_triage"),
    ("soc", "soc/grype.json", "vuln_triage"),
    ("iam", "iam/policies/admin.json", "iam_policy"),
    ("iam", "iam/inventory.json", "iam_audit"),
    ("iam", "iam/rbac_model.yaml", "rbac"),
    ("swe", "swe/sample_repo", "secret_scan"),
    ("swe", "swe/queries.sql", "sql_lint"),
])
def test_detect_tool(fixtures, pack, rel, tool):
    assert detect_tool(pack, fixtures / rel) == tool


def test_detect_unknown(fixtures):
    with pytest.raises(UnknownInputError):
        detect_tool("soc", fixtures / "soc" / "kev.json")
    with pytest.raises(UnknownInputError):
        detect_tool("iam", fixtures / "iam")
    with pytest.raises(ValueError):
        detect_tool("nope", fixtures)


def test_pack_tools_shape():
    assert set(PACK_TOOLS) == {"swe", "devops", "soc", "iam"}
    assert all(callable(fn) for tools in PACK_TOOLS.values() for fn in tools.values())


def test_run_pack_directory(fixtures):
    reports = run_pack("iam", fixtures / "iam")
    assert sorted((r.tool, Path(r.input).name) for r in reports) == [
        ("iam_audit", "inventory.json"), ("iam_policy", "admin.json"), ("iam_policy", "least_privilege.json"),
        ("iam_policy", "overly_broad.json"), ("iam_policy", "trust_any_principal.json"), ("rbac", "rbac_model.yaml")]
    soc = {(r.tool, Path(r.input).name) for r in run_pack("soc", fixtures / "soc")}
    assert ("zeek", "conn.log") in soc and ("sigma", "ssh_bruteforce.yml") in soc
    assert not any(name == "kev.json" for _, name in soc)


def test_run_pack_tool_filter_on_directory(fixtures):
    reports = run_pack("devops", fixtures / "devops", tool="rollback")
    assert [(r.tool, Path(r.input).name) for r in reports] == [("rollback", "plan.tfplan.json")]


def test_run_pack_directory_reports_bad_files(tmp_path):
    (tmp_path / "broken.tfplan.json").write_text("{not json")
    [report] = run_pack("devops", tmp_path)
    assert report.findings[0].rule_id == "INPUT-ERROR"


def test_run_pack_swe_whole_repo_is_clean_with_allowlist():
    repo = Path(__file__).resolve().parents[2]
    [report] = run_pack("swe", repo, tool="secret_scan")
    assert report.findings == [], [f.location for f in report.findings]
    assert report.metrics["suppressed"] >= 2


def test_run_pack_errors(fixtures):
    with pytest.raises(ValueError):
        run_pack("iam", fixtures / "iam", tool="zeek")
    with pytest.raises(FileNotFoundError):
        run_pack("iam", fixtures / "missing.json")


def test_cli_formats_and_exit_codes(fixtures, tmp_path, capsys):
    policy = str(fixtures / "iam" / "policies" / "admin.json")
    assert main(["iam", policy]) == 0
    assert capsys.readouterr().out.startswith("# Analysis Report")
    assert main(["iam", policy, "--fail-on", "high"]) == 2
    capsys.readouterr()
    good = str(fixtures / "iam" / "policies" / "least_privilege.json")
    assert main(["iam", good, "--fail-on", "high", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["total_findings"] == 0
    out = tmp_path / "r.sarif"
    assert main(["soc", str(fixtures / "soc" / "auth.log"), "--format", "sarif", "--out", str(out)]) == 0
    assert json.loads(out.read_text())["version"] == "2.1.0"
    assert main(["iam", str(fixtures / "iam" / "inventory.json"), "--tool", "iam_revoke",
                 "--opt", "as_of=2025-12-31", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["reports"][0]["metrics"]["as_of"] == "2025-12-31"
    assert main(["iam", str(fixtures / "iam" / "missing.json")]) == 1


def test_cli_opt_passthrough_for_sigma_and_drift(fixtures, tmp_path, capsys):
    rule = tmp_path / "rule.yml"
    shutil.copy(fixtures / "soc" / "rules" / "ssh_bruteforce.yml", rule)
    events = fixtures / "soc" / "labeled_events.jsonl"
    assert main(["soc", str(rule), "--opt", f"events={events}", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["reports"][0]["metrics"]["precision"] == 0.8
    state = fixtures / "devops" / "state"
    assert main(["devops", str(state / "baseline.json"), "--tool", "drift", "--opt",
                 f"compare_to={state / 'current.json'}", "--fail-on", "high"]) == 2
