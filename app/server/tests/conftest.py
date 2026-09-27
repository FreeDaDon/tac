from __future__ import annotations

import json
import sqlite3
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SERVER_DIR = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from dashboard.main import create_app  # noqa: E402

RUN_A = "a1b2c3d4"
RUN_B = "deadbeef"
RUN_CORRUPT = "0badf00d"

KPIS_MD = """# Agentic KPIs

## Agentic KPIs

| Metric            | Value     | Last Updated |
| ----------------- | --------- | ------------ |
| Current Streak    | 3         | 2026-09-01   |
| Longest Streak    | 5         | 2026-09-01   |
| Average Presence  | 1.5       | 2026-09-01   |

## ADW KPIs

| Date       | ADW ID   | Issue Number | Issue Class | Attempts |
| ---------- | -------- | ------------ | ----------- | -------- |
| 2026-09-01 | a1b2c3d4 | 12           | /feature    | 1        |
| 2026-09-02 | deadbeef | 13           | /bug        | 2        |
"""

LESSON = """---
name: pin-port-ranges
description: Keep worktree ports inside 9100-9199
tags: [worktrees, ports]
---
Always allocate ports deterministically from the adw_id.
"""


def _state(adw_id: str, **extra: object) -> dict[str, object]:
    base: dict[str, object] = {
        "adw_id": adw_id,
        "domain": "swe",
        "issue_number": "12",
        "issue_title": "Add <script>alert(1)</script> widget",
        "issue_class": "/feature",
        "phases": {"plan": "passed", "build": "passed", "test": "running"},
        "all_adws": ["adw_plan", "adw_build"],
        "usage": {"cost_usd": 1.25, "input_tokens": 100, "output_tokens": 50},
        "budget_usd": 5.0,
        "updated": "2026-09-02T10:00:00+00:00",
        "gate_report": {
            "adw_id": adw_id,
            "gates": [
                {"name": "tests", "status": "passed"},
                {"name": "review", "status": "failed", "detail": "1 blocker"},
                {"name": "e2e", "status": "skipped", "required_for_zte": False},
            ],
        },
    }
    base.update(extra)
    return base


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    runs = tmp_path / "agent" / "runs"
    for adw_id in (RUN_A, RUN_B, RUN_CORRUPT):
        (runs / adw_id).mkdir(parents=True)
    (runs / RUN_A / "state.json").write_text(json.dumps(_state(RUN_A)))
    (runs / RUN_B / "state.json").write_text(
        json.dumps(_state(RUN_B, usage={"cost_usd": 6.0}, updated="2026-09-03T00:00:00+00:00"))
    )
    (runs / RUN_CORRUPT / "state.json").write_text('{"adw_id": "0badf00d", "phases": {')
    events = [
        {"adw_id": RUN_A, "event_type": "phase_start", "phase": "plan", "message": "start"},
        {"adw_id": RUN_A, "event_type": "phase_end", "phase": "plan", "message": "done"},
    ]
    (runs / RUN_A / "events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n{not json\n"
    )
    (runs / "not-an-id").mkdir()
    (tmp_path / "agent" / "agentic_kpis.md").write_text(KPIS_MD)
    lessons = tmp_path / "agent" / "lessons"
    lessons.mkdir()
    (lessons / "ports.md").write_text(LESSON)
    (lessons / "plain.md").write_text("No frontmatter here.\n")
    tree = tmp_path / "trees" / RUN_A
    tree.mkdir(parents=True)
    (tree / ".ports.env").write_text("BACKEND_PORT=9142\nFRONTEND_PORT=9192\nTAC_ADW_ID=a1b2c3d4\n")
    (tmp_path / "trees" / "junk").mkdir()
    with sqlite3.connect(tmp_path / "agent" / "cache.db") as c:
        c.execute("CREATE TABLE cache (key TEXT PRIMARY KEY, command TEXT, response TEXT, created REAL, hits INTEGER)")
        c.execute("INSERT INTO cache VALUES ('k1', '/review', '{}', 0, 3)")
        c.execute("INSERT INTO cache VALUES ('k2', '/classify_issue', '{}', 0, 1)")
    return tmp_path


def _client(root: Path, monkeypatch: pytest.MonkeyPatch, token: str | None) -> TestClient:
    monkeypatch.delenv("TAC_DASHBOARD_DB", raising=False)
    monkeypatch.delenv("TAC_DASHBOARD_HOST", raising=False)
    monkeypatch.delenv("TAC_DASHBOARD_CLIENT_PORT", raising=False)
    if token:
        monkeypatch.setenv("TAC_DASHBOARD_TOKEN", token)
    else:
        monkeypatch.delenv("TAC_DASHBOARD_TOKEN", raising=False)
    app = create_app(root=root, db_path=root / "agent" / "dashboard.db")
    return TestClient(app, base_url="http://localhost")


@pytest.fixture()
def client(root: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    with _client(root, monkeypatch, None) as c:
        yield c


@pytest.fixture()
def auth_client(root: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    with _client(root, monkeypatch, "s3cret-token") as c:
        yield c
