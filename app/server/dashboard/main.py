"""FastAPI app factory for the ADW control-plane dashboard."""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:  # allow `python -m dashboard` from app/server without an install
    sys.path.insert(0, str(REPO_ROOT))

from adws.adw_modules.data_types import TelemetryEvent  # noqa: E402

from . import kpis as kpis_mod  # noqa: E402
from . import lessons as lessons_mod  # noqa: E402
from . import runs as runs_mod  # noqa: E402
from . import worktrees as worktrees_mod  # noqa: E402
from .store import EventStore  # noqa: E402
from .ws import ConnectionManager  # noqa: E402

log = logging.getLogger("dashboard")

MAX_PAYLOAD_BYTES = 64 * 1024
INITIAL_EVENTS = 200
_EVENT_TYPE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


# --- ingest models -------------------------------------------------------------------------
class IngestEvent(TelemetryEvent):
    """TelemetryEvent as accepted over HTTP: strict keys, bounded fields, validated adw_id."""

    model_config = ConfigDict(extra="forbid")

    @field_validator("adw_id")
    @classmethod
    def _adw_id(cls, v: str) -> str:
        if not runs_mod.is_valid_adw_id(v):
            raise ValueError("adw_id must match ^[a-f0-9]{8}$")
        return v

    @field_validator("event_type")
    @classmethod
    def _event_type(cls, v: str) -> str:
        if not _EVENT_TYPE_RE.match(v):
            raise ValueError("event_type must be 1-64 chars of [A-Za-z0-9_.:-]")
        return v

    @field_validator("phase", "source")
    @classmethod
    def _short(cls, v: str) -> str:
        if len(v) > 128:
            raise ValueError("too long (max 128)")
        return v

    @field_validator("timestamp")
    @classmethod
    def _ts(cls, v: str) -> str:
        if len(v) > 64:
            raise ValueError("too long (max 64)")
        return v


class HookEvent(BaseModel):
    """Claude Code hook event (the multi-agent observability shape)."""

    model_config = ConfigDict(extra="ignore")

    source_app: str = Field(min_length=1, max_length=64)
    session_id: str = Field(min_length=1, max_length=128)
    hook_event_type: str = Field(min_length=1, max_length=64)
    payload: dict[str, Any]
    summary: str | None = Field(default=None, max_length=4000)
    timestamp: str | None = Field(default=None, max_length=64)

    def to_event(self) -> TelemetryEvent:
        raw_id = self.payload.get("adw_id")
        adw_id = raw_id if isinstance(raw_id, str) and runs_mod.is_valid_adw_id(raw_id) else ""
        extra = {"timestamp": self.timestamp} if self.timestamp else {}
        return TelemetryEvent(
            adw_id=adw_id,
            event_type="hook",
            phase=self.hook_event_type,
            message=self.summary or self.hook_event_type,
            data={"session_id": self.session_id, "hook_event_type": self.hook_event_type, "payload": self.payload},
            source=self.source_app,
            **extra,
        )


# --- settings ------------------------------------------------------------------------------
@dataclass
class Settings:
    root: Path
    db_path: Path
    token: str | None
    cors_origins: list[str]
    allowed_hosts: list[str]
    dist_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parents[2] / "client" / "dist")

    @classmethod
    def from_env(cls, root: Path | None = None, db_path: Path | None = None) -> Settings:
        if root is None:
            env_root = os.getenv("TAC_PROJECT_ROOT")
            root = Path(env_root) if env_root else REPO_ROOT
        root = root.resolve()
        if db_path is None:
            env_db = os.getenv("TAC_DASHBOARD_DB")
            db_path = Path(env_db) if env_db else root / "agent" / "dashboard.db"
        client_port = os.getenv("TAC_DASHBOARD_CLIENT_PORT", "5173")
        cors = [f"http://localhost:{client_port}", f"http://127.0.0.1:{client_port}"]
        hosts = ["localhost", "127.0.0.1", "::1", "[::1]"]
        bind = os.getenv("TAC_DASHBOARD_HOST", "127.0.0.1")
        if bind not in hosts and bind not in {"0.0.0.0", "::"}:  # noqa: S104 - comparison, not a bind
            hosts.append(bind)
        hosts += [h.strip() for h in os.getenv("TAC_DASHBOARD_ALLOWED_HOSTS", "").split(",") if h.strip()]
        return cls(
            root=root,
            db_path=db_path,
            token=os.getenv("TAC_DASHBOARD_TOKEN") or None,
            cors_origins=cors,
            allowed_hosts=hosts,
        )


def _token_ok(expected: str | None, supplied: str | None) -> bool:
    if not expected:
        return True
    if not supplied:
        return False
    return hmac.compare_digest(expected.encode(), supplied.encode())


def _bearer(value: str | None) -> str | None:
    if value and value.lower().startswith("bearer "):
        return value[7:].strip()
    return None


async def _read_json_capped(request: Request) -> Any:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_PAYLOAD_BYTES:
        raise HTTPException(413, f"payload exceeds {MAX_PAYLOAD_BYTES} bytes")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_PAYLOAD_BYTES:
            raise HTTPException(413, f"payload exceeds {MAX_PAYLOAD_BYTES} bytes")
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(400, "body is not valid JSON") from exc


def _validation_error(exc: ValidationError) -> HTTPException:
    errors = [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()[:20]]
    return HTTPException(422, errors)


def _cache_stats(root: Path) -> dict[str, Any]:
    path = root / "agent" / "cache.db"
    empty: dict[str, Any] = {"exists": False, "entries": 0, "hits": 0, "by_command": []}
    if not path.is_file():
        return empty
    try:
        conn = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=2)
        try:
            entries, hits = conn.execute("SELECT COUNT(*), COALESCE(SUM(hits), 0) FROM cache").fetchone()
            rows = conn.execute(
                "SELECT command, COUNT(*), COALESCE(SUM(hits), 0) FROM cache GROUP BY command ORDER BY 3 DESC"
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return {**empty, "exists": True, "error": exc.__class__.__name__}
    return {
        "exists": True,
        "entries": int(entries),
        "hits": int(hits),
        "by_command": [{"command": r[0], "entries": int(r[1]), "hits": int(r[2])} for r in rows],
    }


# --- app factory ---------------------------------------------------------------------------
def create_app(root: Path | None = None, db_path: Path | None = None) -> FastAPI:
    settings = Settings.from_env(root, db_path)
    store = EventStore(settings.db_path)
    manager = ConnectionManager()

    app = FastAPI(title="TAC ADW Control Plane", version="0.1.0", docs_url="/api/docs", redoc_url=None,
                  openapi_url="/api/openapi.json")
    app.state.settings = settings
    app.state.store = store
    app.state.manager = manager

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        if not request.url.path.startswith("/api/"):  # the built client; /api/docs needs its CDN assets
            host = request.headers.get("host", "")
            response.headers.setdefault(
                "Content-Security-Policy",
                f"default-src 'self'; connect-src 'self' ws://{host} wss://{host}; img-src 'self' data:; "
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            )
        return response

    def require_token(request: Request) -> None:
        if not _token_ok(settings.token, _bearer(request.headers.get("authorization"))):
            raise HTTPException(401, "missing or invalid bearer token", headers={"WWW-Authenticate": "Bearer"})

    async def ingest(event: TelemetryEvent) -> dict[str, Any]:
        saved = store.insert(event.model_dump(mode="json"))
        await manager.broadcast({"type": "event", "data": saved})
        return saved

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "root": settings.root.name,
            "events": store.count(),
            "ws_clients": manager.count,
            "auth_required": bool(settings.token),
        }

    @app.post("/api/events", status_code=201, dependencies=[Depends(require_token)])
    async def post_event(request: Request) -> dict[str, Any]:
        body = await _read_json_capped(request)
        try:
            event = IngestEvent.model_validate(body)
        except ValidationError as exc:
            raise _validation_error(exc) from exc
        return await ingest(event)

    @app.post("/api/hook-events", status_code=201, dependencies=[Depends(require_token)])
    async def post_hook_event(request: Request) -> dict[str, Any]:
        body = await _read_json_capped(request)
        try:
            hook = HookEvent.model_validate(body)
        except ValidationError as exc:
            raise _validation_error(exc) from exc
        return await ingest(hook.to_event())

    @app.get("/api/events")
    def get_events(
        limit: int = Query(100, ge=1, le=1000),
        adw_id: str | None = Query(None, max_length=64),
        event_type: str | None = Query(None, max_length=64),
    ) -> list[dict[str, Any]]:
        return store.recent(limit=limit, adw_id=adw_id or None, event_type=event_type or None)

    @app.get("/api/events/filter-options")
    def event_filter_options() -> dict[str, list[str]]:
        return store.filter_options()

    @app.get("/api/runs")
    def get_runs() -> list[dict[str, Any]]:
        return runs_mod.list_runs(settings.root)

    @app.get("/api/runs/{adw_id}")
    def get_run(adw_id: str) -> dict[str, Any]:
        if not runs_mod.is_valid_adw_id(adw_id):
            raise HTTPException(400, "adw_id must match ^[a-f0-9]{8}$")
        detail = runs_mod.run_detail(settings.root, adw_id)
        if detail is None:
            raise HTTPException(404, "run not found")
        return detail

    @app.get("/api/kpis")
    def get_kpis() -> dict[str, Any]:
        return kpis_mod.load_kpis(settings.root)

    @app.get("/api/budget")
    def get_budget() -> dict[str, Any]:
        return runs_mod.budget(settings.root)

    @app.get("/api/worktrees")
    def get_worktrees() -> list[dict[str, Any]]:
        return worktrees_mod.list_worktrees(settings.root)

    @app.get("/api/lessons")
    def get_lessons() -> list[dict[str, Any]]:
        return lessons_mod.list_lessons(settings.root)

    @app.get("/api/cache")
    def get_cache() -> dict[str, Any]:
        return _cache_stats(settings.root)

    @app.websocket("/ws/events")
    async def ws_events(websocket: WebSocket) -> None:
        origin = websocket.headers.get("origin")
        host = websocket.headers.get("host", "")
        if origin and origin not in settings.cors_origins and origin not in {f"http://{host}", f"https://{host}"}:
            await websocket.close(code=1008)
            return
        supplied = websocket.query_params.get("token") or _bearer(websocket.headers.get("authorization"))
        if not _token_ok(settings.token, supplied):
            await websocket.close(code=1008)
            return
        await websocket.accept()
        await websocket.send_json({"type": "initial", "data": store.recent(limit=INITIAL_EVENTS)})
        await manager.connect(websocket)
        try:
            while True:
                await websocket.receive_text()  # clients may ping; content is ignored
        except WebSocketDisconnect:
            pass
        finally:
            await manager.disconnect(websocket)

    if settings.dist_dir.is_dir():
        app.mount("/", StaticFiles(directory=settings.dist_dir, html=True), name="client")

    if not settings.token and os.getenv("TAC_DASHBOARD_HOST", "127.0.0.1") not in {"127.0.0.1", "localhost", "::1"}:
        log.warning("dashboard bound to a non-loopback host without TAC_DASHBOARD_TOKEN set")
    return app


app = create_app()
