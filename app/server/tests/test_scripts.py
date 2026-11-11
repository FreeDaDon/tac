"""Operator scripts (scripts/*.sh) run against a throwaway git repo that holds a copy of them."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
ADW_ID = "a1b2c3d4"


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=cwd, check=True, capture_output=True, text=True,
    ).stdout.strip()


def _run(repo: Path, script: str, *args: str, shell: str = "bash") -> subprocess.CompletedProcess[str]:
    return subprocess.run([shell, str(repo / "scripts" / script), *args], capture_output=True, text=True, timeout=60)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "README.md").write_text("hi\n")
    (tmp_path / ".gitignore").write_text("trees/\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "init")
    shutil.copytree(SCRIPTS, tmp_path / "scripts")
    return tmp_path


def _worktree(repo: Path, branch: str | None) -> Path:
    tree = repo / "trees" / ADW_ID
    if branch:
        _git(repo, "worktree", "add", "-q", "-b", branch, str(tree))
    else:
        _git(repo, "worktree", "add", "-q", "--detach", str(tree))
    return tree


def _branches(repo: Path) -> set[str]:
    return set(_git(repo, "branch", "--format=%(refname:short)").splitlines())


def test_purge_refuses_dirty_worktree_without_force(repo: Path) -> None:
    tree = _worktree(repo, "feat-x")
    (tree / "wip.txt").write_text("uncommitted work\n")
    refused = _run(repo, "purge_tree.sh", ADW_ID, "--delete-branch")
    assert refused.returncode == 1 and "uncommitted" in refused.stderr
    assert (tree / "wip.txt").exists() and "feat-x" in _branches(repo)
    forced = _run(repo, "purge_tree.sh", ADW_ID, "--delete-branch", "--force")
    assert forced.returncode == 0, forced.stderr
    assert not tree.exists() and "feat-x" not in _branches(repo)


def test_purge_detached_head_keeps_branches(repo: Path) -> None:
    tree = _worktree(repo, None)
    result = _run(repo, "purge_tree.sh", ADW_ID, "--delete-branch")
    assert result.returncode == 0, result.stderr
    assert not tree.exists() and _branches(repo) == {"main"}
    assert "kept branch '<detached HEAD>'" in result.stderr


def test_purge_refuses_unmerged_branch_without_force(repo: Path) -> None:
    tree = _worktree(repo, "feat-y")
    (tree / "new.txt").write_text("committed on the branch only\n")
    _git(tree, "add", ".")
    _git(tree, "commit", "-q", "-m", "work")
    refused = _run(repo, "purge_tree.sh", ADW_ID, "--delete-branch")
    assert refused.returncode == 1 and "not merged" in refused.stderr
    assert tree.exists() and "feat-y" in _branches(repo)
    assert _run(repo, "purge_tree.sh", ADW_ID, "--delete-branch", "--force").returncode == 0
    assert "feat-y" not in _branches(repo)


def test_purge_merged_branch(repo: Path) -> None:
    tree = _worktree(repo, "feat-z")
    result = _run(repo, "purge_tree.sh", ADW_ID, "--delete-branch")
    assert result.returncode == 0, result.stderr
    assert not tree.exists() and _branches(repo) == {"main"}


def test_list_runs_tolerates_corrupt_state(repo: Path) -> None:
    runs = repo / "agent" / "runs"
    for adw_id in ("0badf00d", "a1b2c3d4", "deadbeef"):
        (runs / adw_id).mkdir(parents=True)
    (runs / "0badf00d" / "state.json").write_text('{"adw_id": ')
    good = {"adw_id": "a1b2c3d4", "domain": "swe", "phases": {"plan": "passed"}, "usage": {"cost_usd": 1.5}}
    (runs / "a1b2c3d4" / "state.json").write_text(json.dumps(good))
    (runs / "deadbeef" / "state.json").write_text(json.dumps({"adw_id": "deadbeef"}))
    result = _run(repo, "list_runs.sh")
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert lines[0] == "0badf00d  unreadable state.json (JSONDecodeError)"
    assert lines[1].split() == ["a1b2c3d4", "swe", "$1.5000", "plan:passed"]
    assert lines[2].split() == ["deadbeef", "swe", "$0.0000"]


def test_start_rejects_non_numeric_backend_port(repo: Path) -> None:
    (repo / ".ports.env").write_text("BACKEND_PORT=$(touch pwned)\n")
    result = _run(repo, "start.sh", shell="sh")
    assert result.returncode == 2 and "invalid BACKEND_PORT" in result.stderr
    assert not (repo / "pwned").exists() and not (repo / "scripts" / "pwned").exists()


def _free_ports(count: int) -> list[int]:
    ports = []
    for port in range(9100, 9200):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
        ports.append(port)
        if len(ports) == count:
            return ports
    pytest.skip("not enough free ports in 9100-9199")


@pytest.fixture()
def listeners() -> Iterator[dict[int, subprocess.Popen[str]]]:
    procs: dict[int, subprocess.Popen[str]] = {}
    code = (
        "import socket, sys, time\n"
        "s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "s.bind(('127.0.0.1', int(sys.argv[1]))); s.listen(); print('ready', flush=True); time.sleep(120)\n"
    )
    for port in _free_ports(2):
        proc = subprocess.Popen([sys.executable, "-c", code, str(port)], stdout=subprocess.PIPE, text=True)
        assert proc.stdout and proc.stdout.readline().strip() == "ready"
        procs[port] = proc
    yield procs
    for proc in procs.values():
        proc.kill()
        proc.wait()


@pytest.mark.skipif(shutil.which("lsof") is None, reason="lsof not installed")
def test_stop_worktrees_only_kills_declared_ports(repo: Path, listeners: dict[int, subprocess.Popen[str]]) -> None:
    declared, undeclared = listeners
    tree = repo / "trees" / ADW_ID
    tree.mkdir(parents=True)
    (tree / ".ports.env").write_text(f"BACKEND_PORT={declared}\nFRONTEND_PORT=22\n")
    result = _run(repo, "stop_worktrees.sh")
    assert result.returncode == 0, result.stderr
    assert listeners[declared].wait(timeout=10) != 0
    assert listeners[undeclared].poll() is None
    assert "ignoring port 22" in result.stderr
