"""Isolated project root per test: temp git repo, mock agent runner, no telemetry push."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

TEMPLATES = {
    "classify_issue": "Classify $1",
    "generate_branch_name": "Branch for $1 from $2",
    "feature": "Plan issue $1 adw $2 from $3 into $4",
    "bug": "Plan bug $1 adw $2 from $3 into $4",
    "chore": "Plan chore $1 adw $2 from $3 into $4",
    "implement": "Implement $1",
    "resolve_failed_test": "Fix $1",
    "resolve_failed_e2e_test": "Fix e2e $1",
    "test_e2e": "E2E $1 $2 $3 $4",
    "review": "Review $1 $2 $3 $4",
    "patch": "Patch $1 $2 $3 $4",
    "document": "Document $1 $2 $3 $4",
    "commit": "Commit $1 $2 $3",
    "redteam": "Red team $1 $2 $3 $4",
    "reflect": "Reflect $1 $2",
    "soc_triage": "Triage $1 $2",
    "iam_access_review": "IAM $1 $2",
    "devops_iac_plan": "IaC $1 $2",
}

PYPROJECT = """
[project]
name = "sandbox"
version = "0.0.0"

[tool.tac.gates]
lint = ["python3", "-c", "print('lint ok')"]
types = ["python3", "-c", "print('types ok')"]
unit = ["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"]

[tool.tac]
e2e_specs = ".claude/commands/e2e"
max_test_repairs = 2
max_e2e_repairs = 1
max_review_patches = 1
"""


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


@pytest.fixture
def tac_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repo"
    (root / ".claude" / "commands").mkdir(parents=True)
    for name, body in TEMPLATES.items():
        (root / ".claude" / "commands" / f"{name}.md").write_text(body + "\n")
    (root / "pyproject.toml").write_text(PYPROJECT)
    (root / "tests").mkdir()
    (root / "tests" / "test_ok.py").write_text("def test_ok():\n    assert 1 + 1 == 2\n")
    (root / ".gitignore").write_text("agent/runs/\ntrees/\n__pycache__/\n")
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "t@example.com")
    git(root, "config", "user.name", "t")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "init")
    monkeypatch.setenv("TAC_PROJECT_ROOT", str(root))
    monkeypatch.setenv("TAC_AGENT_RUNNER", "mock")
    monkeypatch.setenv("TAC_TELEMETRY_PUSH", "0")
    monkeypatch.setenv("TAC_ZTE_ENABLED", "0")
    monkeypatch.delenv("TAC_ALLOW_SKIP_PERMISSIONS", raising=False)
    monkeypatch.delenv("GITHUB_REPO_URL", raising=False)
    return root
