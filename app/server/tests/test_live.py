"""Producers and logging against the app served by a real uvicorn with TAC_DASHBOARD_TOKEN set."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest
from conftest import RUN_A, TOKEN
from fastapi import FastAPI

from adws.adw_modules import telemetry

HOOK = Path(__file__).resolve().parents[3] / ".claude" / "hooks" / "post_tool_use.py"


def _messages(app: FastAPI) -> list[str]:
    return [e["message"] for e in app.state.store.recent()]


def test_emit_sends_token_to_auth_enabled_dashboard(
    live_server: tuple[str, FastAPI], root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    url, app = live_server
    monkeypatch.setenv("TAC_DASHBOARD_URL", url)
    monkeypatch.setenv("TAC_PROJECT_ROOT", str(root))
    monkeypatch.setenv("TAC_QUIET", "1")
    monkeypatch.delenv("TAC_TELEMETRY_PUSH", raising=False)
    monkeypatch.setattr(telemetry, "_auth_warned", False)

    monkeypatch.delenv("TAC_DASHBOARD_TOKEN")
    telemetry.emit(RUN_A, "gate", "test", "no token")
    assert "rejected events (401)" in capsys.readouterr().err

    monkeypatch.setenv("TAC_DASHBOARD_TOKEN", TOKEN)
    telemetry.emit(RUN_A, "gate", "test", "with token")
    assert _messages(app) == ["with token"]


@pytest.mark.parametrize(("token", "stored"), [(None, False), (TOKEN, True)])
def test_post_tool_use_hook_sends_token(live_server: tuple[str, FastAPI], token: str | None, stored: bool) -> None:
    url, app = live_server
    env = {k: v for k, v in os.environ.items() if k != "TAC_DASHBOARD_TOKEN"}
    env["TAC_DASHBOARD_URL"] = url
    if token:
        env["TAC_DASHBOARD_TOKEN"] = token
    hook_input = {"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "ls"}}
    subprocess.run(
        [sys.executable, str(HOOK)], input=json.dumps(hook_input), env=env, text=True, check=True, timeout=30
    )
    events = app.state.store.recent()
    assert [e["data"]["payload"]["tool_name"] for e in events] == (["Bash"] if stored else [])


def test_access_log_redacts_token(live_server: tuple[str, FastAPI], caplog: pytest.LogCaptureFixture) -> None:
    url, _ = live_server
    caplog.set_level(logging.INFO, logger="uvicorn.access")
    urllib.request.urlopen(f"{url}/api/health?token={TOKEN}&view=runs", timeout=5).close()  # noqa: S310
    deadline = time.monotonic() + 5
    while not any("view=runs" in r.getMessage() for r in caplog.records) and time.monotonic() < deadline:
        time.sleep(0.02)
    lines = [r.getMessage() for r in caplog.records if r.name == "uvicorn.access"]
    assert any("token=[redacted]&view=runs" in line for line in lines), lines
    assert not any(TOKEN in line for line in lines)
