import pytest

from core.loaders import load_jsonl
from core.soc.sigma import (
    SigmaError,
    analyze_file,
    compile_rule,
    evaluate_rule,
    lint_rule,
    load_rule,
    selection_matches,
)


def rule(detection, **extra):
    return {"title": "t", "id": "x", "level": "low", "falsepositives": ["none"], "logsource": {"product": "p"},
            "description": "d", "detection": detection, **extra}


EVENT = {"process": {"name": "sshd", "command_line": "/usr/sbin/sshd -D"}, "user": {"name": "Root"},
         "message": "Failed password for root"}


def matches(detection):
    matcher, _ = compile_rule(rule(detection))
    return matcher(EVENT)


def test_modifiers_and_case_insensitivity():
    assert selection_matches({"user.name": "root"}, EVENT)
    assert selection_matches({"process.command_line|startswith": "/usr/sbin"}, EVENT)
    assert selection_matches({"process.command_line|endswith": "-d"}, EVENT)
    assert selection_matches({"message|contains": "FAILED"}, EVENT)
    assert selection_matches({"process.command_line|re": r"sshd\s+-D$"}, EVENT)
    assert not selection_matches({"process.command_line|re": r"^sshd"}, EVENT)
    assert selection_matches({"process.name": "ss*"}, EVENT)
    assert selection_matches({"message|contains|all": ["failed", "root"]}, EVENT)
    assert not selection_matches({"message|contains|all": ["failed", "admin"]}, EVENT)
    assert selection_matches({"missing.field": None}, EVENT)


def test_lists_or_maps_and():
    assert selection_matches({"user.name": ["admin", "root"]}, EVENT)
    assert not selection_matches({"user.name": "root", "process.name": "cron"}, EVENT)
    assert selection_matches([{"process.name": "cron"}, {"process.name": "sshd"}], EVENT)
    assert selection_matches(["failed password"], EVENT)


def test_conditions():
    sel = {"process.name": "sshd"}
    flt = {"user.name": "root"}
    other = {"process.name": "cron"}
    assert matches({"selection": sel, "condition": "selection"})
    assert not matches({"selection": sel, "filter": flt, "condition": "selection and not filter"})
    assert matches({"selection_a": other, "selection_b": sel, "condition": "1 of selection*"})
    assert not matches({"selection_a": other, "selection_b": sel, "condition": "all of selection*"})
    assert matches({"a": sel, "b": flt, "condition": "all of them"})
    assert matches({"a": other, "b": sel, "condition": "(a or b) and not (a and b)"})


@pytest.mark.parametrize("condition", ["selection |count() > 5", "unknown", "selection and", "1 of nothing*", "(selection"])
def test_bad_conditions(condition):
    with pytest.raises(SigmaError):
        compile_rule(rule({"selection": {"a": 1}, "condition": condition}))


def test_unknown_modifier():
    with pytest.raises(SigmaError):
        matches({"selection": {"message|base64": "x"}, "condition": "selection"})


def test_evaluation_metrics_exact(fixtures):
    report = analyze_file(fixtures / "soc" / "rules" / "ssh_bruteforce.yml")
    m = report.metrics
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (4, 1, 1, 4)
    assert (m["precision"], m["recall"], m["false_positive_rate"], m["f1"]) == (0.8, 0.8, 0.2, 0.8)
    fps = [f for f in report.findings if f.rule_id == "SIGMA-FP"]
    assert len(fps) == 1 and fps[0].evidence["event"]["source"]["ip"] == "172.16.4.20"
    assert "label" not in fps[0].evidence["event"]
    assert [f.evidence["event_index"] for f in report.findings if f.rule_id == "SIGMA-FN"] == [5]
    assert not [f for f in report.findings if f.rule_id.startswith("SIGMA-LINT")]


def test_tuning_the_filter_removes_the_fp(fixtures):
    tuned = load_rule(fixtures / "soc" / "rules" / "ssh_bruteforce.yml")
    tuned["detection"]["filter_internal"]["source.ip|startswith"].append("172.16.")
    metrics, findings = evaluate_rule(tuned, load_jsonl(fixtures / "soc" / "labeled_events.jsonl"))
    assert (metrics["fp"], metrics["precision"], metrics["false_positive_rate"]) == (0, 1.0, 0.0)
    assert not [f for f in findings if f.rule_id == "SIGMA-FP"]


def test_lint_broad_rule(fixtures):
    findings = lint_rule(load_rule(fixtures / "soc" / "rules" / "broad_rule.yml"))
    ids = {f.rule_id for f in findings}
    assert ids == {"SIGMA-LINT-ID", "SIGMA-LINT-LEVEL", "SIGMA-LINT-FALSEPOSITIVES", "SIGMA-LINT-DESCRIPTION",
                   "SIGMA-LINT-BROAD", "SIGMA-LINT-UNUSED"}
    broad = next(f for f in findings if f.rule_id == "SIGMA-LINT-BROAD")
    assert broad.evidence["values"] == ["selection_cmd.process.command_line|contains='a'"]


def test_lint_invalid_condition_and_unlabeled_events():
    findings = lint_rule(rule({"selection": {"a": 1}, "condition": "nope"}))
    assert [f.rule_id for f in findings] == ["SIGMA-LINT-CONDITION"]
    with pytest.raises(SigmaError):
        evaluate_rule(rule({"selection": {"a": 1}, "condition": "selection"}), [{"a": 1}])


def test_lint_only_without_events(tmp_path, fixtures):
    target = tmp_path / "r.yml"
    target.write_text((fixtures / "soc" / "rules" / "ssh_bruteforce.yml").read_text())
    report = analyze_file(target)
    assert report.summary.startswith("lint only") and "tp" not in report.metrics
