"""Launch workflows as detached `uv run` processes with a concurrency cap shared by every trigger.

The webhook, cron and Todone triggers run as separate processes, so the cap and the one-run-per-issue
rule live on disk: one pidfile per live launch under agent/runs/_triggers/active/, read and written
under an exclusive lock.
"""

from __future__ import annotations

import fcntl
import json
import os
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from adws.adw_modules.security import validate_adw_id, validate_issue_number
from adws.adw_modules.utils import project_root, runs_dir

ALLOWED_WORKFLOWS = {
    "adw_plan_iso", "adw_sdlc_iso", "adw_sdlc_zte_iso", "adw_build_iso", "adw_test_iso",
    "adw_review_iso", "adw_redteam_iso", "adw_document_iso",
}

_children: list[subprocess.Popen] = []


def _active_dir() -> Path:
    path = runs_dir() / "_triggers" / "active"
    path.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def _locked() -> Iterator[None]:
    with open(_active_dir() / ".lock", "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0] != "Z"
    except (OSError, IndexError):
        return True


def active_launches() -> list[dict]:
    """Live launches across all trigger processes; pidfiles of finished runs are removed."""
    for child in _children:
        child.poll()
    _children[:] = [c for c in _children if c.returncode is None]
    live = []
    for pidfile in _active_dir().glob("*.json"):
        try:
            info = json.loads(pidfile.read_text())
            pid = int(info["pid"])
        except (OSError, ValueError, KeyError, TypeError):
            pidfile.unlink(missing_ok=True)
            continue
        if _alive(pid):
            live.append(info)
        else:
            pidfile.unlink(missing_ok=True)
    return live


def active_count() -> int:
    return len(active_launches())


def launch(workflow: str, issue: str | None = None, issue_file: str | None = None, adw_id: str | None = None,
           model_set: str = "base", max_concurrent: int = 5) -> subprocess.Popen:
    if workflow not in ALLOWED_WORKFLOWS:
        raise ValueError(f"workflow {workflow!r} is not allowed")
    argv = ["uv", "run", str(project_root() / "adws" / f"{workflow}.py")]
    if issue:
        issue = validate_issue_number(issue)
        argv += ["--issue", issue]
    if issue_file:
        argv += ["--issue-file", str(Path(issue_file).resolve())]
    if adw_id:
        argv += ["--adw-id", validate_adw_id(adw_id)]
    if model_set in ("base", "heavy") and workflow not in {"adw_build_iso", "adw_test_iso", "adw_review_iso",
                                                          "adw_redteam_iso", "adw_document_iso"}:
        argv += ["--model-set", model_set]
    log_dir = runs_dir() / "_triggers"
    log_dir.mkdir(parents=True, exist_ok=True)
    with _locked():
        live = active_launches()
        if len(live) >= max_concurrent:
            raise RuntimeError(f"concurrency limit reached ({max_concurrent})")
        if issue and any(info.get("issue") == issue for info in live):
            raise RuntimeError(f"a run for issue #{issue} is already active")
        with open(log_dir / f"{workflow}.log", "a") as log:
            proc = subprocess.Popen(argv, cwd=project_root(), stdout=log, stderr=subprocess.STDOUT,
                                    start_new_session=True)
        _children.append(proc)
        (_active_dir() / f"{proc.pid}.json").write_text(
            json.dumps({"pid": proc.pid, "workflow": workflow, "issue": issue or ""}))
    return proc
