"""Launch workflows as detached `uv run` processes with a concurrency cap."""

from __future__ import annotations

import subprocess
from pathlib import Path

from adws.adw_modules.security import validate_adw_id, validate_issue_number
from adws.adw_modules.utils import project_root, runs_dir

ALLOWED_WORKFLOWS = {
    "adw_plan_iso", "adw_sdlc_iso", "adw_sdlc_zte_iso", "adw_build_iso", "adw_test_iso",
    "adw_review_iso", "adw_redteam_iso", "adw_document_iso",
}

_running: list[subprocess.Popen] = []


def active_count() -> int:
    _running[:] = [p for p in _running if p.poll() is None]
    return len(_running)


def launch(workflow: str, issue: str | None = None, issue_file: str | None = None, adw_id: str | None = None,
           model_set: str = "base", max_concurrent: int = 5) -> subprocess.Popen:
    if workflow not in ALLOWED_WORKFLOWS:
        raise ValueError(f"workflow {workflow!r} is not allowed")
    if active_count() >= max_concurrent:
        raise RuntimeError(f"concurrency limit reached ({max_concurrent})")
    argv = ["uv", "run", str(project_root() / "adws" / f"{workflow}.py")]
    if issue:
        argv += ["--issue", validate_issue_number(issue)]
    if issue_file:
        argv += ["--issue-file", str(Path(issue_file).resolve())]
    if adw_id:
        argv += ["--adw-id", validate_adw_id(adw_id)]
    if model_set in ("base", "heavy") and workflow not in {"adw_build_iso", "adw_test_iso", "adw_review_iso",
                                                          "adw_redteam_iso", "adw_document_iso"}:
        argv += ["--model-set", model_set]
    log_dir = runs_dir() / "_triggers"
    log_dir.mkdir(parents=True, exist_ok=True)
    log = open(log_dir / f"{workflow}.log", "a")  # noqa: SIM115 - handed to the child process
    proc = subprocess.Popen(argv, cwd=project_root(), stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    _running.append(proc)
    return proc
