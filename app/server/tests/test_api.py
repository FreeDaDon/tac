from __future__ import annotations

import asyncio
import json
import os
import socket
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
from conftest import RUN_A, RUN_B, RUN_CORRUPT, TOKEN, _client, _state
from dashboard import runs as runs_mod
from dashboard import store as store_mod
from dashboard.kpis import parse_tables
from dashboard.lessons import parse_lesson
from dashboard.main import create_app
from dashboard.store import EventStore
from dashboard.ws import ConnectionManager
from fastapi import WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

WS = "ws://localhost/ws/events"
EVENT = {"adw_id": RUN_A, "event_type": "gate", "phase": "test", "message": "tests passed", "data": {"n": 3}}


def test_health(client: TestClient) -> None:
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["auth_required"] is False


def test_post_and_get_events(client: TestClient) -> None:
    r = client.post("/api/events", json=EVENT)
    assert r.status_code == 201, r.text
    saved = r.json()
    assert saved["id"] >= 1 and saved["data"] == {"n": 3} and saved["source"] == "adw" and saved["timestamp"]
    client.post("/api/events", json={**EVENT, "adw_id": RUN_B, "event_type": "error"})
    all_events = client.get("/api/events").json()
    assert [e["adw_id"] for e in all_events] == [RUN_B, RUN_A]  # newest first
    assert [e["event_type"] for e in client.get("/api/events", params={"adw_id": RUN_A}).json()] == ["gate"]
    assert len(client.get("/api/events", params={"event_type": "error"}).json()) == 1
    assert len(client.get("/api/events", params={"limit": 1}).json()) == 1
    assert client.get("/api/events", params={"limit": 0}).status_code == 422
    opts = client.get("/api/events/filter-options").json()
    assert set(opts["adw_id"]) == {RUN_A, RUN_B} and set(opts["event_type"]) == {"gate", "error"}


@pytest.mark.parametrize(
    "payload",
    [
        {"event_type": "gate"},  # missing adw_id
        {"adw_id": "NOT-HEX!", "event_type": "gate"},
        {"adw_id": "../../etc", "event_type": "gate"},
        {"adw_id": RUN_A, "event_type": "bad type with spaces"},
        {"adw_id": RUN_A, "event_type": "gate", "unexpected": 1},
        {"adw_id": RUN_A, "event_type": "gate", "data": "not-a-dict"},
        ["not", "an", "object"],
    ],
)
def test_post_event_rejects_malformed(client: TestClient, payload: object) -> None:
    assert client.post("/api/events", json=payload).status_code == 422


def test_post_event_rejects_invalid_json(client: TestClient) -> None:
    r = client.post("/api/events", content=b"{nope", headers={"Content-Type": "application/json"})
    assert r.status_code == 400


def test_post_event_rejects_oversize(client: TestClient) -> None:
    big = {**EVENT, "message": "x" * (70 * 1024)}
    assert client.post("/api/events", json=big).status_code == 413
    # streamed body without a trustworthy content-length is also capped
    def gen() -> Iterator[bytes]:
        yield json.dumps(big).encode()

    assert client.post("/api/events", content=gen(), headers={"Content-Type": "application/json"}).status_code == 413
    assert client.get("/api/events").json() == []


def test_hook_events(client: TestClient) -> None:
    hook = {
        "source_app": "tac",
        "session_id": "sess-1",
        "hook_event_type": "PreToolUse",
        "payload": {"tool_name": "Bash", "adw_id": RUN_A},
        "summary": "running ls",
    }
    r = client.post("/api/hook-events", json=hook)
    assert r.status_code == 201, r.text
    saved = r.json()
    assert saved["event_type"] == "hook" and saved["phase"] == "PreToolUse" and saved["adw_id"] == RUN_A
    assert saved["source"] == "tac" and saved["message"] == "running ls"
    assert saved["data"]["payload"]["tool_name"] == "Bash"
    no_id = client.post("/api/hook-events", json={**hook, "payload": {"adw_id": "../x"}}).json()
    assert no_id["adw_id"] == ""
    assert client.post("/api/hook-events", json={"source_app": "tac"}).status_code == 422


def test_runs_list(client: TestClient) -> None:
    runs = client.get("/api/runs").json()
    ids = [r["adw_id"] for r in runs]
    assert set(ids) == {RUN_A, RUN_B, RUN_CORRUPT}  # "not-an-id" dir ignored
    assert ids[0] == RUN_B  # most recently updated first
    a = next(r for r in runs if r["adw_id"] == RUN_A)
    assert a["phases"]["plan"] == "passed" and a["attempts"] == 2
    assert a["gates"] == {"passed": 1, "failed": 1, "skipped": 1, "error": 0, "total": 3, "all_green": False}
    assert a["cost_usd"] == 1.25 and a["budget_fraction"] == 0.25
    bad = next(r for r in runs if r["adw_id"] == RUN_CORRUPT)
    assert bad["error"] and bad["phases"] == {}


def test_run_detail(client: TestClient) -> None:
    r = client.get(f"/api/runs/{RUN_A}")
    assert r.status_code == 200
    body = r.json()
    assert body["state"]["issue_class"] == "/feature"
    assert [e["event_type"] for e in body["events"]] == ["phase_start", "phase_end"]  # corrupt line skipped
    assert {g["name"] for g in body["gate_report"]["gates"]} == {"tests", "review", "e2e"}
    corrupt = client.get(f"/api/runs/{RUN_CORRUPT}").json()
    assert corrupt["state"] is None and corrupt["events"] == []


@pytest.mark.parametrize("bad", ["ABCDEF12", "a1b2c3d", "a1b2c3d4e", "..%2F..%2Fetc", "zzzzzzzz"])
def test_run_detail_invalid_id(client: TestClient, bad: str) -> None:
    assert client.get(f"/api/runs/{bad}").status_code in (400, 404)
    if "%" not in bad:
        assert client.get(f"/api/runs/{bad}").status_code == 400


def test_run_detail_not_found(client: TestClient) -> None:
    assert client.get("/api/runs/12345678").status_code == 404


def test_kpis(client: TestClient) -> None:
    body = client.get("/api/kpis").json()
    assert body["exists"] is True
    assert body["summary"]["Current Streak"] == "3"
    assert body["highlights"]["current_streak"] == 3
    assert body["highlights"]["average_presence"] == 1.5
    assert body["highlights"]["average_attempts"] == 1.5
    assert len(body["tables"]["ADW KPIs"]) == 2


def test_kpis_missing(client: TestClient, root: Path) -> None:
    (root / "agent" / "agentic_kpis.md").unlink()
    assert client.get("/api/kpis").json()["exists"] is False


def test_budget(client: TestClient) -> None:
    body = client.get("/api/budget").json()
    statuses = {r["adw_id"]: r["status"] for r in body["runs"]}
    assert statuses[RUN_A] == "ok" and statuses[RUN_B] == "over"
    assert body["totals"]["over_budget"] == 1 and body["totals"]["cost_usd"] == 7.25


@pytest.mark.parametrize(("cost", "status"), [(3.99, "ok"), (4.0, "warn"), (4.99, "warn"), (5.0, "over")])
def test_budget_thresholds(client: TestClient, root: Path, cost: float, status: str) -> None:
    _write_state(root, RUN_A, usage={"cost_usd": cost})
    body = client.get("/api/budget").json()
    assert {r["adw_id"]: r["status"] for r in body["runs"]}[RUN_A] == status
    assert body["totals"]["near_budget"] == (status == "warn")


def _write_state(root: Path, adw_id: str, **extra: object) -> None:
    path = root / "agent" / "runs" / adw_id / "state.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(_state(adw_id, **extra)))
    os.replace(tmp, path)


def test_run_summaries_reparsed_only_when_state_changes(
    client: TestClient, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed: list[str] = []
    real = runs_mod.summarize

    def spy(run: Path, adw_id: str) -> dict[str, Any]:
        parsed.append(adw_id)
        return real(run, adw_id)

    monkeypatch.setattr(runs_mod, "summarize", spy)
    client.get("/api/runs")
    client.get("/api/budget")
    client.get("/api/runs")
    assert sorted(parsed) == sorted([RUN_A, RUN_B, RUN_CORRUPT])
    _write_state(root, RUN_A, usage={"cost_usd": 2.5})
    runs = client.get("/api/runs").json()
    assert next(r for r in runs if r["adw_id"] == RUN_A)["cost_usd"] == 2.5
    assert parsed[3:] == [RUN_A]


def test_symlinked_run_dir_rejected(client: TestClient, root: Path, tmp_path_factory: pytest.TempPathFactory) -> None:
    outside = tmp_path_factory.mktemp("outside")
    (outside / "state.json").write_text(json.dumps(_state("cafebabe")))
    (root / "agent" / "runs" / "cafebabe").symlink_to(outside, target_is_directory=True)
    assert "cafebabe" not in {r["adw_id"] for r in client.get("/api/runs").json()}
    assert client.get("/api/runs/cafebabe").status_code == 404


def test_state_json_symlink_and_size_capped(
    client: TestClient, root: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    secret = tmp_path_factory.mktemp("outside") / "secret.json"
    secret.write_text(json.dumps(_state(RUN_A, issue_title="leaked")))
    state = root / "agent" / "runs" / RUN_A / "state.json"
    state.unlink()
    state.symlink_to(secret)
    detail = client.get(f"/api/runs/{RUN_A}").json()
    assert detail["state"] is None and "outside" in detail["summary"]["error"]
    assert "leaked" not in json.dumps(detail)
    big = root / "agent" / "runs" / RUN_B / "state.json"
    big.write_text(json.dumps(_state(RUN_B, issue_title="x" * runs_mod.MAX_STATE_BYTES)))
    run_b = next(r for r in client.get("/api/runs").json() if r["adw_id"] == RUN_B)
    assert run_b["issue_title"] is None and "exceeds" in run_b["error"]


def test_run_events_tail_large_file(client: TestClient, root: Path) -> None:
    padding = "x" * 10_000
    lines = [json.dumps({"event_type": "first"})]
    lines += [json.dumps({"event_type": "pad", "message": padding}) for _ in range(600)]
    lines.append(json.dumps({"event_type": "last"}))
    path = root / "agent" / "runs" / RUN_A / "events.jsonl"
    path.write_text("\n".join(lines) + "\n")
    assert path.stat().st_size > runs_mod.MAX_EVENTS_BYTES
    events = client.get(f"/api/runs/{RUN_A}").json()["events"]
    types = [e["event_type"] for e in events]
    assert types[-1] == "last" and "first" not in types
    assert set(types) == {"pad", "last"}
    assert len(events) < 600


def test_worktrees(client: TestClient) -> None:
    trees = client.get("/api/worktrees").json()
    assert len(trees) == 1  # "junk" dir ignored
    t = trees[0]
    assert t["adw_id"] == RUN_A and t["backend_port"] == 9142 and t["frontend_port"] == 9192
    assert isinstance(t["backend_live"], bool) and t["has_run"] is True


def test_worktree_live_port(client: TestClient, root: Path) -> None:
    with socket.socket() as listening, socket.socket() as closed:
        listening.bind(("127.0.0.1", 0))
        listening.listen()
        closed.bind(("127.0.0.1", 0))
        live_port, dead_port = listening.getsockname()[1], closed.getsockname()[1]
        (root / "trees" / RUN_A / ".ports.env").write_text(f"BACKEND_PORT={live_port}\nFRONTEND_PORT={dead_port}\n")
        tree = client.get("/api/worktrees").json()[0]
    assert tree["backend_live"] is True and tree["frontend_live"] is False


def test_event_store_retention(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store_mod, "PRUNE_EVERY", 5)
    store = EventStore(tmp_path / "e.db", max_rows=10)
    for i in range(23):
        store.insert({"adw_id": RUN_A, "event_type": "gate", "message": str(i)})
    kept = store.recent(limit=1000)
    assert [e["message"] for e in kept] == [str(i) for i in range(22, 9, -1)]
    assert store.count() == len(kept) == 13
    reopened = EventStore(tmp_path / "e.db", max_rows=4)
    assert [e["message"] for e in reopened.recent(limit=1000)] == ["22", "21", "20", "19"]
    assert reopened.count() == 4
    assert EventStore(tmp_path / "empty.db").count() == 0


def test_health_counts_events(client: TestClient) -> None:
    for _ in range(3):
        client.post("/api/events", json=EVENT)
    assert client.get("/api/health").json()["events"] == 3
def test_version_normal(client: TestClient) -> None:
    r = client.get("/api/version")
    assert r.status_code == 200
    assert r.json() == {"name": "tac", "version": "9.9.9-test"}


def test_version_missing_pyproject(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAC_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("TAC_DASHBOARD_HOST", raising=False)
    app = create_app(root=tmp_path, db_path=tmp_path / "dashboard.db")
    with TestClient(app, base_url="http://localhost") as c:
        r = c.get("/api/version")
        assert r.status_code == 200
        assert r.json() == {"name": "tac", "version": "unknown"}


def test_lessons(client: TestClient, root: Path) -> None:
    outside = root / "secret.md"
    outside.write_text("---\nname: leaked\n---\nsecret")
    (root / "agent" / "lessons" / "escape.md").symlink_to(outside)
    lessons = client.get("/api/lessons").json()
    by_name = {lesson["name"]: lesson for lesson in lessons}
    assert "leaked" not in by_name
    assert by_name["pin-port-ranges"]["tags"] == ["worktrees", "ports"]
    assert by_name["pin-port-ranges"]["body"].startswith("Always allocate")
    assert by_name["plain"]["description"] == ""


def test_cache(client: TestClient, root: Path) -> None:
    body = client.get("/api/cache").json()
    assert body["exists"] is True and body["entries"] == 2 and body["hits"] == 4
    (root / "agent" / "cache.db").unlink()
    assert client.get("/api/cache").json() == {"exists": False, "entries": 0, "hits": 0, "by_command": []}


def test_ws_initial_and_broadcast(client: TestClient) -> None:
    client.post("/api/events", json=EVENT)
    with client.websocket_connect(WS + "") as ws:
        initial = ws.receive_json()
        assert initial["type"] == "initial" and len(initial["data"]) == 1
        client.post("/api/events", json={**EVENT, "message": "live"})
        msg = ws.receive_json()
        assert msg["type"] == "event" and msg["data"]["message"] == "live"


def test_ws_rejects_foreign_origin(client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(WS + "", headers={"Origin": "http://evil.example"}) as ws:
            ws.receive_json()
    with client.websocket_connect(WS + "", headers={"Origin": "http://localhost:5173"}) as ws:
        assert ws.receive_json()["type"] == "initial"


def test_untrusted_host_rejected(client: TestClient) -> None:
    assert client.get("/api/health", headers={"Host": "attacker.example"}).status_code == 400


def test_cors(client: TestClient) -> None:
    ok = client.options(
        "/api/events",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"},
    )
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    bad = client.get("/api/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in bad.headers


PROTECTED_GETS = [
    "/api/events",
    "/api/events/filter-options",
    "/api/runs",
    f"/api/runs/{RUN_A}",
    "/api/kpis",
    "/api/budget",
    "/api/worktrees",
    "/api/lessons",
    "/api/cache",
    "/api/docs",
    "/api/openapi.json",
]
GOOD = {"Authorization": f"Bearer {TOKEN}"}


def test_token_auth_posts(auth_client: TestClient) -> None:
    assert auth_client.get("/api/health").json()["auth_required"] is True
    assert auth_client.post("/api/events", json=EVENT).status_code == 401
    bad = {"Authorization": "Bearer wrong"}
    assert auth_client.post("/api/events", json=EVENT, headers=bad).status_code == 401
    assert auth_client.post("/api/events", json=EVENT, headers=GOOD).status_code == 201
    hook = {"source_app": "a", "session_id": "s", "hook_event_type": "Stop", "payload": {}}
    assert auth_client.post("/api/hook-events", json=hook).status_code == 401
    assert auth_client.post("/api/hook-events", json=hook, headers=GOOD).status_code == 201


@pytest.mark.parametrize("path", PROTECTED_GETS)
def test_token_auth_gets(auth_client: TestClient, path: str) -> None:
    missing = auth_client.get(path)
    assert missing.status_code == 401 and missing.headers["www-authenticate"] == "Bearer"
    assert auth_client.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert auth_client.get(path, params={"token": TOKEN}).status_code == 401
    assert auth_client.get(path, headers=GOOD).status_code == 200


def test_token_auth_keeps_cors_preflight(auth_client: TestClient) -> None:
    r = auth_client.options(
        "/api/runs",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
        },
    )
    assert r.status_code == 200 and r.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_ws_token_auth(auth_client: TestClient) -> None:
    for kwargs in (
        {},
        {"subprotocols": ["bearer", "nope"]},
        {"headers": {"Authorization": "Bearer nope"}},
    ):
        with pytest.raises(WebSocketDisconnect):
            with auth_client.websocket_connect(WS, **kwargs) as ws:
                ws.receive_json()
    with pytest.raises(WebSocketDisconnect):
        with auth_client.websocket_connect(f"{WS}?token={TOKEN}") as ws:
            ws.receive_json()
    with auth_client.websocket_connect(WS, subprotocols=["bearer", TOKEN]) as ws:
        assert ws.accepted_subprotocol == "bearer"
        assert ws.receive_json()["type"] == "initial"
    with auth_client.websocket_connect(WS, headers=GOOD) as ws:
        assert ws.receive_json()["type"] == "initial"


def test_ws_accepts_bearer_subprotocol_without_token(client: TestClient) -> None:
    with client.websocket_connect(WS, subprotocols=["bearer", "stale"]) as ws:
        assert ws.accepted_subprotocol == "bearer"
        assert ws.receive_json()["type"] == "initial"


def test_ws_client_cap(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAC_DASHBOARD_MAX_WS_CLIENTS", "1")
    with _client(root, monkeypatch, None) as c, c.websocket_connect(WS) as first:
        assert first.receive_json()["type"] == "initial"
        with pytest.raises(WebSocketDisconnect) as rejected:
            with c.websocket_connect(WS) as second:
                second.receive_json()
        assert rejected.value.code == 1013
        assert c.get("/api/health").json()["ws_clients"] == 1
        c.post("/api/events", json=EVENT)
        assert first.receive_json()["type"] == "event"


def test_ws_skips_nothing_between_snapshot_and_live(client: TestClient) -> None:
    with client.websocket_connect(WS) as ws:
        assert ws.receive_json()["data"] == []
        ids = [client.post("/api/events", json={**EVENT, "message": str(i)}).json()["id"] for i in range(5)]
        assert [ws.receive_json()["data"]["id"] for _ in ids] == ids


class FakeSocket:
    def __init__(self, *, stall: bool = False, fail: bool = False) -> None:
        self.stall, self.fail = stall, fail
        self.sent: list[dict[str, Any]] = []
        self.closed: list[int] = []

    async def send_json(self, message: dict[str, Any]) -> None:
        if self.fail:
            raise RuntimeError("connection lost")
        if self.stall:
            await asyncio.Event().wait()
        self.sent.append(message)

    async def close(self, code: int = 1000) -> None:
        self.closed.append(code)


def test_broadcast_drops_slow_and_dead_clients_without_waiting() -> None:
    async def scenario() -> tuple[ConnectionManager, FakeSocket, FakeSocket, FakeSocket]:
        manager = ConnectionManager(max_clients=5, queue_size=3)
        fast, slow, dead = FakeSocket(), FakeSocket(stall=True), FakeSocket(fail=True)
        for fake in (fast, slow, dead):
            assert manager.connect(cast(WebSocket, fake))
            manager.start(cast(WebSocket, fake))
        started = time.monotonic()
        for i in range(10):
            manager.broadcast({"n": i})
            await asyncio.sleep(0)
        assert time.monotonic() - started < 0.5
        await asyncio.sleep(0.05)
        return manager, fast, slow, dead

    manager, fast, slow, dead = asyncio.run(scenario())
    assert [m["n"] for m in fast.sent] == list(range(10))
    assert slow.sent == [] and slow.closed == [1013]
    assert dead.sent == [] and dead.closed == []
    assert manager.count == 1


def test_connection_manager_cap() -> None:
    async def scenario() -> list[bool]:
        manager = ConnectionManager(max_clients=2)
        return [manager.connect(cast(WebSocket, FakeSocket())) for _ in range(3)]

    assert asyncio.run(scenario()) == [True, True, False]


def test_parsers_are_tolerant() -> None:
    assert parse_tables("no tables here") == {}
    meta, body = parse_lesson("---\nname: [unclosed\ntags: a, b\n---\nbody")
    assert meta["tags"] == "a, b" and body == "body"


def test_security_headers(client: TestClient) -> None:
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"


def test_serves_built_client(root: Path, monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> None:
    from dashboard.main import Settings, create_app

    dist = tmp_path_factory.mktemp("dist")
    (dist / "index.html").write_text("<!doctype html><title>ADW</title>")
    (root / "outside.txt").write_text("secret")
    original = Settings.from_env

    def patched(*args: object, **kwargs: object) -> Settings:
        s = original(*args, **kwargs)  # type: ignore[arg-type]
        s.dist_dir = dist
        return s

    monkeypatch.setattr(Settings, "from_env", staticmethod(patched))
    with TestClient(create_app(root=root, db_path=root / "d.db"), base_url="http://localhost") as c:
        r = c.get("/")
        assert r.status_code == 200 and "ADW" in r.text
        assert "default-src 'self'" in r.headers["content-security-policy"]
        assert c.get("/../outside.txt").status_code == 404
        assert c.get("/%2e%2e/outside.txt").status_code == 404
        assert c.get("/api/health").status_code == 200  # API routes win over the static mount
