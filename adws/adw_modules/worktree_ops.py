"""Isolated execution environments: one git worktree, one port pair, one database per ADW run.

Port range 9100-9199 is split: backend 9100-9149, frontend 9150-9199 (50 concurrent slots).
Slots are chosen deterministically from the adw_id, probed with bind(), and recorded in state.
"""

from __future__ import annotations

import shutil
import socket
from pathlib import Path

from .git_ops import GitError, base_ref, git
from .security import validate_adw_id, validate_branch_name
from .state import ADWState
from .utils import project_root, trees_dir

BACKEND_BASE = 9100
FRONTEND_BASE = 9150
SLOTS = 50


def is_port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _ports_in_use_by_runs() -> set[int]:
    """Ports already assigned to other active worktrees (their apps may not be running yet)."""
    used: set[int] = set()
    root = trees_dir()
    if not root.exists():
        return used
    for tree in root.iterdir():
        env = tree / ".ports.env"
        if env.exists():
            for line in env.read_text().splitlines():
                if line.startswith(("BACKEND_PORT=", "FRONTEND_PORT=")):
                    used.add(int(line.split("=", 1)[1]))
    return used


def allocate_ports(adw_id: str) -> tuple[int, int]:
    validate_adw_id(adw_id)
    start = int(adw_id, 16) % SLOTS
    reserved = _ports_in_use_by_runs()
    for offset in range(SLOTS):
        slot = (start + offset) % SLOTS
        be, fe = BACKEND_BASE + slot, FRONTEND_BASE + slot
        if be in reserved or fe in reserved:
            continue
        if is_port_available(be) and is_port_available(fe):
            return be, fe
    raise RuntimeError("no free port slot in 9100-9199; clean up finished worktrees")


def worktree_path(adw_id: str) -> Path:
    return trees_dir() / validate_adw_id(adw_id)


def create_worktree(adw_id: str, branch: str) -> Path:
    validate_branch_name(branch)
    path = worktree_path(adw_id)
    if path.exists():
        return path
    trees_dir().mkdir(parents=True, exist_ok=True)
    ref = base_ref()
    try:
        git("worktree", "add", "-b", branch, str(path), ref)
    except GitError as exc:
        if "already exists" not in str(exc):
            raise
        git("worktree", "add", str(path), branch)
    return path


def setup_environment(path: Path, backend_port: int, frontend_port: int, adw_id: str) -> None:
    """Per-run ports and database file. Secrets are NOT copied into worktrees."""
    db_dir = path / "agent_data"
    db_dir.mkdir(exist_ok=True)
    (path / ".ports.env").write_text(
        f"BACKEND_PORT={backend_port}\n"
        f"FRONTEND_PORT={frontend_port}\n"
        f"VITE_BACKEND_URL=http://127.0.0.1:{backend_port}\n"
        f"TAC_DB_PATH={db_dir / f'{adw_id}.db'}\n"
        f"TAC_ADW_ID={adw_id}\n"
    )


def validate_worktree(state: ADWState) -> tuple[bool, str]:
    wt = state.data.worktree_path
    if not wt:
        return False, "no worktree_path in state"
    if not Path(wt).exists():
        return False, f"worktree directory missing: {wt}"
    listing = git("worktree", "list", "--porcelain", cwd=project_root(), check=False)
    if f"worktree {Path(wt).resolve()}" not in listing:
        return False, "worktree not registered with git"
    return True, ""


def remove_worktree(adw_id: str) -> None:
    path = worktree_path(adw_id)
    git("worktree", "remove", "--force", str(path), check=False)
    if path.exists():
        shutil.rmtree(path)
    git("worktree", "prune", check=False)
