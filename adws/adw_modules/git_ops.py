"""Git operations. Every call is an argv list (no shell) with validated identifiers."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .security import validate_branch_name
from .utils import base_branch, project_root


class GitError(RuntimeError):
    pass


def git(*args: str, cwd: str | Path | None = None, check: bool = True, timeout: int = 120) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=str(cwd or project_root()), capture_output=True, text=True, timeout=timeout
    )
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc.stdout.strip()


def has_remote(cwd: str | Path | None = None, remote: str = "origin") -> bool:
    return remote in git("remote", cwd=cwd, check=False).split()


def current_branch(cwd: str | Path | None = None) -> str:
    return git("rev-parse", "--abbrev-ref", "HEAD", cwd=cwd)


def base_ref(cwd: str | Path | None = None) -> str:
    """origin/<base> when a remote exists (after fetch), else the local base branch."""
    if has_remote(cwd):
        git("fetch", "origin", base_branch(), cwd=cwd, check=False, timeout=300)
        ref = f"origin/{base_branch()}"
        if git("rev-parse", "--verify", "--quiet", ref, cwd=cwd, check=False):
            return ref
    return base_branch()


def commit_all(message: str, cwd: str | Path) -> bool:
    """Stage and commit everything in the worktree. Returns False when there was nothing to commit."""
    git("add", "-A", cwd=cwd)
    if not git("status", "--porcelain", cwd=cwd):
        return False
    git("commit", "-m", message, cwd=cwd)
    return True


def push_branch(branch: str, cwd: str | Path) -> None:
    validate_branch_name(branch)
    if base_branch() == branch:
        raise GitError("refusing to push directly to the base branch")
    if not has_remote(cwd):
        return
    git("push", "-u", "origin", branch, cwd=cwd, timeout=300)


def diff_stat(cwd: str | Path) -> dict[str, int]:
    """Added/removed/files of the branch vs the base ref (KPI: size)."""
    out = git("diff", "--shortstat", f"{base_ref(cwd)}...HEAD", cwd=cwd, check=False)
    stats = {"files": 0, "added": 0, "removed": 0}
    for part in out.split(","):
        part = part.strip()
        num = int(part.split()[0]) if part and part.split()[0].isdigit() else 0
        if "file" in part:
            stats["files"] = num
        elif "insertion" in part:
            stats["added"] = num
        elif "deletion" in part:
            stats["removed"] = num
    return stats


def changed_files(cwd: str | Path) -> list[str]:
    out = git("diff", "--name-only", f"{base_ref(cwd)}...HEAD", cwd=cwd, check=False)
    return [line for line in out.splitlines() if line.strip()]


def branch_diff(cwd: str | Path, max_chars: int = 200_000) -> str:
    out = git("diff", f"{base_ref(cwd)}...HEAD", cwd=cwd, check=False, timeout=120)
    return out[:max_chars]
