"""Domain runner end-to-end with the mock agent: the new packs analyze, fence untrusted data, and stay isolated."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from adws import adw_domain_iso
from adws.adw_modules.state import ADWState
from adws.adw_modules.utils import agent_dir

FIXTURES = Path(__file__).resolve().parents[2] / "core" / "fixtures"


@pytest.mark.parametrize(("pack", "rel", "command"), [
    ("mcp_gov", "mcp_gov", "mcp_connector_review"),
    ("gcp_sre", "gcp_sre", "gcp_sre_triage"),
])
def test_domain_run_writes_reports_and_assessment(tac_root: Path, pack: str, rel: str, command: str) -> None:
    ok = adw_domain_iso.run(pack, str(FIXTURES / rel), adw_id="ab12cd34")
    assert ok  # no --fail-on: report only
    out = agent_dir() / "reports" / "ab12cd34"
    findings = json.loads((out / "findings.json").read_text())
    assert {r["pack"] for r in findings} == {pack}
    assert json.loads((out / "findings.sarif").read_text())["version"] == "2.1.0"
    report = (out / "report.md").read_text()
    assert "## Agent assessment" in report
    # findings reach the agent as a file path under the run's inputs dir, never inline in the prompt
    prompt = (tac_root / "agent" / "runs" / "ab12cd34" / f"{pack}_analyst" / "prompt.md").read_text()
    assert "inputs/findings.json" in prompt
    assert "acme-crm-connector" not in prompt and "kafka" not in prompt.lower()
    assert (tac_root / "agent" / "runs" / "ab12cd34" / "inputs" / "findings.json").exists()
    state = ADWState.load("ab12cd34")
    assert state is not None and state.data.domain == pack
    assert state.data.phases["analyze"] == "passed" and state.data.phases["interpret"] == "passed"


def test_hostile_content_is_inert_in_the_markdown_report(tac_root: Path) -> None:
    adw_domain_iso.run("mcp_gov", str(FIXTURES / "mcp_gov" / "servers" / "risky_server.json"), adw_id="ab12cd34",
                       use_agent=False)
    report = (agent_dir() / "reports" / "ab12cd34" / "report.md").read_text()
    outside_code_spans = re.sub(r"(`+).+?\1", "", report)
    assert "<IMPORTANT>" in report  # the evidence is shown...
    assert "<important>" not in outside_code_spans.lower()  # ...only inside inline code, where markup is inert


def test_fail_on_gates_the_run(tac_root: Path) -> None:
    ok = adw_domain_iso.run("gcp_sre", str(FIXTURES / "gcp_sre" / "state.tfstate.json"), adw_id="ab12cd34",
                            use_agent=False, fail_on="high")
    assert not ok
    state = ADWState.load("ab12cd34")
    assert state is not None
    gate = next(g for g in state.gate_report().gates if g.name == "gcp_sre_analysis")
    assert gate.status == "failed"


def test_propose_uses_isolated_worktree_and_leaves_main_clean(tac_root: Path) -> None:
    adw_domain_iso.run("mcp_gov", str(FIXTURES / "mcp_gov" / "connectors"), adw_id="ab12cd34", use_agent=False,
                       propose=True)
    state = ADWState.load("ab12cd34")
    assert state is not None
    wt = Path(state.data.worktree_path or "")
    assert wt.is_relative_to(tac_root / "trees")
    assert (wt / "reports" / "mcp_gov" / "ab12cd34.md").exists()
    assert (wt / "reports" / "mcp_gov" / "ab12cd34.sarif").exists()
    assert state.data.branch_name == "chore-mcp_gov-review-adw-ab12cd34"
    assert subprocess.run(["git", "branch", "--show-current"], cwd=tac_root, capture_output=True,
                          text=True).stdout.strip() == "main"
    assert not (tac_root / "reports").exists()


def test_unrecognized_input_fails_loudly(tac_root: Path, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "data.bin").write_bytes(b"\x00\x01")
    with pytest.raises(Exception, match="no recognizable"):
        adw_domain_iso.run("gcp_sre", str(empty), adw_id="ab12cd34", use_agent=False)
