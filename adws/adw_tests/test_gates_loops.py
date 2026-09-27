from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

import pytest

from adws.adw_modules.data_types import GateResult, TestResult
from adws.adw_modules.gates import parse_junit, run_unit_tests
from adws.adw_modules.kpis import KPIRow, summary
from adws.adw_modules.memory import Lesson, load_lessons, relevant, write_lesson
from adws.adw_modules.redteam import detect_test_tampering
from adws.adw_modules.repair import repair_loop
from adws.adw_modules.state import ADWState
from adws.adw_modules.worktree_ops import BACKEND_BASE, FRONTEND_BASE, SLOTS, allocate_ports
from adws.adw_triggers.trigger_todone import eligible, parse_tasks
from adws.adw_triggers.trigger_webhook import decide, verify_signature

JUNIT = """<testsuites><testsuite>
<testcase classname="tests.test_a" name="test_ok"/>
<testcase classname="tests.test_a" name="test_bad"><failure message="boom">trace</failure></testcase>
</testsuite></testsuites>"""


def test_parse_junit() -> None:
    results = parse_junit(JUNIT)
    assert [r.passed for r in results] == [True, False]
    assert results[1].test_name == "tests/test_a.py::test_bad" and "boom" in (results[1].error or "")


@pytest.mark.parametrize("bad", ["", "<not xml", "<testsuites></testsuites>"])
def test_unparseable_junit_is_failure(bad: str) -> None:
    """tac-7 regression: unparseable test output was treated as zero failures (a pass)."""
    with pytest.raises(ValueError):
        parse_junit(bad)


def test_unit_gate_fails_without_report(tac_root: Path) -> None:
    (tac_root / "tests" / "test_ok.py").write_text("import nonexistent_module_xyz\n")
    gate, results = run_unit_tests(tac_root, tac_root / "reports")
    assert gate.status == "failed" and results and not all(r.passed for r in results)


def test_unit_gate_passes(tac_root: Path) -> None:
    gate, results = run_unit_tests(tac_root, tac_root / "reports")
    assert gate.status == "passed" and all(r.passed for r in results)


def test_repair_loop_stops_on_no_progress(tac_root: Path) -> None:
    ADWState("ab12cd34").save()
    runs = {"n": 0}

    def always_failing() -> list[TestResult]:
        runs["n"] += 1
        return [TestResult(test_name="t1", passed=False, execution_command="x", error="e")]

    ok, _ = repair_loop("ab12cd34", str(tac_root), always_failing, "/resolve_failed_test", max_attempts=5)
    assert not ok and runs["n"] == 2  # second identical failure set -> stop


def test_repair_loop_succeeds_after_fix(tac_root: Path) -> None:
    ADWState("ab12cd34").save()
    runs = {"n": 0}

    def flaky() -> list[TestResult]:
        runs["n"] += 1
        return [TestResult(test_name="t1", passed=runs["n"] > 1, execution_command="x")]

    ok, _ = repair_loop("ab12cd34", str(tac_root), flaky, "/resolve_failed_test", max_attempts=3)
    assert ok and runs["n"] == 2


def test_redteam_detects_test_tampering() -> None:
    diff = """diff --git a/tests/test_x.py b/tests/test_x.py
--- a/tests/test_x.py
+++ b/tests/test_x.py
-    assert compute() == 4
-    assert other() == 1
+@pytest.mark.skip(reason="flaky")
+    pass
diff --git a/tests/test_gone.py b/tests/test_gone.py
deleted file mode 100644
"""
    findings = detect_test_tampering(diff)
    titles = {f.title for f in findings}
    assert "Test file deleted" in titles
    assert "Check suppressed or test skipped" in titles
    assert "Net assertions removed from tests" in titles
    assert all(f.severity == "high" for f in findings)


def test_redteam_clean_diff() -> None:
    diff = "diff --git a/app.py b/app.py\n+def f():\n+    return 1\n"
    assert detect_test_tampering(diff) == []


def test_lessons_memory(tac_root: Path) -> None:
    write_lesson(Lesson(slug="pin-uv-lock", title="Pin uv.lock before tests", tags=["python", "tests"],
                        lesson="Run uv sync before pytest in fresh worktrees.", why="stale venv", how_to_apply="always"))
    write_lesson(Lesson(slug="pin-uv-lock", title="Pin uv.lock before tests (updated)", tags=["python"],
                        lesson="Updated.", why="w", how_to_apply="h"))
    lessons = load_lessons()
    assert len(lessons) == 1 and lessons[0].title.endswith("(updated)")
    assert relevant("python dependency issue", tags=["python"])[0].slug == "pin-uv-lock"
    assert relevant("kubernetes") == []
    with pytest.raises(ValueError):
        write_lesson(Lesson(slug="../evil", title="x", lesson="x"))


def test_kpi_summary_math() -> None:
    rows = [KPIRow(adw_id=f"0000000{i}", date="2026-01-01", domain="swe", attempts=a, plan_size=10,
                   added=5, removed=1, gates_passed=7, gates_total=8) for i, a in enumerate([1, 3, 1, 2, 1])]
    s = summary(rows)
    assert s["current_streak"] == 3 and s["longest_streak"] == 3
    assert s["average_presence"] == 1.6 and s["total_diff_size"] == 30 and s["gate_pass_rate"] == 0.875


def test_ports_in_range(tac_root: Path) -> None:
    be, fe = allocate_ports("ab12cd34")
    assert BACKEND_BASE <= be < BACKEND_BASE + SLOTS and fe == be + (FRONTEND_BASE - BACKEND_BASE)
    assert 9100 <= be <= 9149 and 9150 <= fe <= 9199


def test_webhook_signature() -> None:
    body = b'{"a":1}'
    sig = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert verify_signature("s3cret", body, sig)
    assert not verify_signature("s3cret", body, "sha256=deadbeef")
    assert not verify_signature("", body, sig)  # no secret configured -> fail closed
    assert not verify_signature("s3cret", body, None)


def test_webhook_decisions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAC_TRIGGER_ALLOWED_USERS", "les")

    def comment(body: str, user: str = "les", labels: list[str] | None = None) -> dict:
        return {"action": "created", "comment": {"body": body, "user": {"login": user}},
                "issue": {"number": 1, "labels": [{"name": n} for n in labels or []]}}

    assert decide("issue_comment", comment("/adw sdlc")) == ("adw_sdlc_iso", "base")
    assert decide("issue_comment", comment("/adw sdlc heavy")) == ("adw_sdlc_iso", "heavy")
    assert decide("issue_comment", comment("/adw sdlc", user="stranger")) is None
    assert decide("issue_comment", comment("/adw zte")) is None  # needs tac:zte label
    assert decide("issue_comment", comment("/adw zte", labels=["tac:zte"])) == ("adw_sdlc_zte_iso", "base")
    assert decide("issue_comment", comment("[TAC-ADW] /adw sdlc")) is None  # bot loop guard
    assert decide("issue_comment", comment("please run adw_sdlc_ZTE_iso")) is None


def test_todone_parsing() -> None:
    text = """## Queue api
- [ ] add endpoint {heavy}
- [⏰] update docs
## Queue ui
- [✅ ab12cd34] done task
- [⏰] follow-up
- [🟡 ffff0000] running
"""
    queues = parse_tasks(text)
    assert queues["api"][0].tags == {"heavy"} and queues["api"][0].text == "add endpoint"
    names = [t.text for t in eligible(queues)]
    assert names == ["add endpoint", "follow-up"]  # "update docs" blocked behind a pending task


def test_gate_report_all_green() -> None:
    from adws.adw_modules.data_types import GateReport

    r = GateReport(adw_id="ab12cd34")
    assert not r.all_green  # empty report is never green
    r.upsert(GateResult(name="unit", status="passed"))
    r.upsert(GateResult(name="client", status="skipped", required_for_zte=False))
    assert r.all_green
    r.upsert(GateResult(name="e2e", status="skipped"))
    assert not r.all_green
