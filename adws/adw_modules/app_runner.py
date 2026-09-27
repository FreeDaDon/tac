"""Start the application under test inside a worktree on its allocated port (for E2E and review)."""

from __future__ import annotations

import os
import signal
import subprocess
import time
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .security import safe_subprocess_env

START_TIMEOUT_S = 90


def _healthy(url: str) -> bool:
    try:
        with urllib.request.urlopen(url + "/api/health", timeout=2) as resp:  # noqa: S310 - local http only
            return bool(resp.status == 200)
    except OSError:
        return False


@contextmanager
def running_app(worktree: str | Path, port: int, log_path: Path) -> Iterator[str]:
    """Build the client (if present) and serve the dashboard app from the worktree on 127.0.0.1:port."""
    wt = Path(worktree)
    env = safe_subprocess_env()
    env.pop("ANTHROPIC_API_KEY", None)
    env.update({"TAC_DASHBOARD_HOST": "127.0.0.1", "TAC_DASHBOARD_PORT": str(port), "TAC_PROJECT_ROOT": str(wt),
                "TAC_DASHBOARD_DB": str(wt / "agent_data" / "dashboard.db"), "VIRTUAL_ENV": ""})
    log_path.parent.mkdir(parents=True, exist_ok=True)
    client = wt / "app" / "client"
    with open(log_path, "a") as log:
        if (client / "package.json").exists() and not (client / "dist").exists():
            subprocess.run(["bash", "-c", "npm ci --silent --no-audit --no-fund && npm run build --silent"],
                           cwd=client, stdout=log, stderr=log, env=env, timeout=600, check=False)
        proc = subprocess.Popen(["uv", "run", "python", "app/server/run.py"], cwd=wt, stdout=log, stderr=log,
                                env=env, start_new_session=True)
    url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + START_TIMEOUT_S
        while not _healthy(url):
            if proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(f"app failed to start on {url}; see {log_path}")
            time.sleep(1)
        yield url
    finally:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=10)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
