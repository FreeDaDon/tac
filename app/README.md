# ADW Control Plane Dashboard

A local operator console for AI Developer Workflows (ADWs). It ingests telemetry events, reads run state straight from the filesystem, and streams new events to the browser over a WebSocket.

```
ADW telemetry.emit() / Claude Code hooks
        │  POST /api/events, /api/hook-events
        ▼
FastAPI (app/server/dashboard) ──► SQLite (agent/dashboard.db)
        │                      └─► WebSocket /ws/events ──► Vite + vanilla TS client (app/client)
        └─ reads agent/runs/*/state.json, events.jsonl, agent/agentic_kpis.md,
           agent/lessons/*.md, trees/*/.ports.env, agent/cache.db
```

The filesystem stays the source of truth (`agent/runs/<adw_id>/events.jsonl`); the SQLite store only holds events that were pushed to the API, which is what the live feed shows.

## Run

From the repository root:

```bash
uv sync
# API (and the built client at / if app/client/dist exists)
uv run python app/server/run.py                 # 127.0.0.1:8000
# or: cd app/server && uv run python -m dashboard

# Client dev server with hot reload (proxies /api and /ws to the API)
cd app/client && npm install && npm run dev     # http://localhost:5173

# Production-style: build once, then just run the API and open http://127.0.0.1:8000
cd app/client && npm run build
```

Point ADWs at it so events are pushed live:

```bash
export TAC_DASHBOARD_URL=http://127.0.0.1:8000
```

## Quality gates

```bash
uv run ruff check app/server && uv run mypy app/server && uv run pytest app/server/tests -q
cd app/client && npm install && npx tsc --noEmit && npm run build
```

## Endpoints

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/health` | Status, stored event count, connected WebSocket clients, whether auth is on |
| POST | `/api/events` | Body is a `TelemetryEvent` (`adw_id`, `event_type`, `phase`, `message`, `data`, `source`, `timestamp`). Unknown keys rejected, `adw_id` must match `^[a-f0-9]{8}$`, 64 KB cap. Returns 201 with the stored row. Token-protected when configured |
| POST | `/api/hook-events` | Claude Code hook shape `{source_app, session_id, hook_event_type, payload, summary?}`; stored as `event_type: "hook"` with `phase = hook_event_type`. `adw_id` is taken from `payload.adw_id` if valid. Same cap and auth |
| GET | `/api/events?limit=&adw_id=&event_type=` | Newest first, `limit` 1-1000 (default 100) |
| GET | `/api/events/filter-options` | Distinct `adw_id`, `event_type`, `source` values |
| WS | `/ws/events` | Sends `{type:"initial", data:[200 most recent]}` on connect, then `{type:"event", data}` for each ingested event |
| GET | `/api/runs` | One summary per `agent/runs/<adw_id>/`: phases, gate counts, cost vs budget, attempts; newest first |
| GET | `/api/runs/{adw_id}` | Full state, gate report and `events.jsonl`. 400 for an invalid id, 404 if missing |
| GET | `/api/kpis` | `agent/agentic_kpis.md` tables as JSON plus highlights (streaks, average presence and attempts) |
| GET | `/api/budget` | Per-run cost vs budget (`ok` / `warn` at 80% / `over`) and totals |
| GET | `/api/worktrees` | `trees/<adw_id>/.ports.env` with a live listening check per port |
| GET | `/api/lessons` | `agent/lessons/*.md` frontmatter (`name`, `description`, `tags`) and body |
| GET | `/api/cache` | `agent/cache.db` entries and hit counts (read-only), per command |
| GET | `/api/version` | `{name, version}` from pyproject.toml, read once at startup and cached |
| GET | `/api/docs` | OpenAPI UI |

Corrupt or partial files never break an endpoint: a malformed `state.json` shows up as a run with an `error` field, bad `events.jsonl` lines are skipped, and large event files are tailed (last 5 MB).

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `TAC_DASHBOARD_HOST` | `127.0.0.1` | Bind address |
| `TAC_DASHBOARD_PORT` | `8000` | API port (also the Vite proxy target) |
| `TAC_DASHBOARD_CLIENT_PORT` | `5173` | Vite port; the only extra CORS origins allowed |
| `TAC_DASHBOARD_TOKEN` | unset | When set, POST endpoints need `Authorization: Bearer <token>` and the WebSocket needs `?token=<token>` |
| `TAC_DASHBOARD_DB` | `<root>/agent/dashboard.db` | SQLite event store path |
| `TAC_DASHBOARD_ALLOWED_HOSTS` | unset | Extra comma-separated `Host` header values to accept (for example a LAN hostname) |
| `TAC_PROJECT_ROOT` | repo root | Root containing `agent/` and `trees/` |
| `TAC_DASHBOARD_URL` | unset | Read by ADWs (`adws/adw_modules/telemetry.py`), not by the server |

With a token set, open the UI once as `http://127.0.0.1:8000/?token=...`; the client keeps it in `sessionStorage` and removes it from the address bar.

## Security notes

- Binds to loopback by default. Binding elsewhere without `TAC_DASHBOARD_TOKEN` logs a warning.
- `Host` header allow-list (localhost, 127.0.0.1, ::1, the bind host) blocks DNS-rebinding attacks.
- CORS is limited to `http://localhost:<client port>` and `http://127.0.0.1:<client port>`.
- The WebSocket rejects foreign `Origin` headers (CORS does not cover WebSockets) and checks the token when one is set.
- Tokens are compared with `hmac.compare_digest`.
- Request bodies are streamed and cut off at 64 KB (413); invalid JSON is 400, schema violations are 422.
- `adw_id` is validated with `^[a-f0-9]{8}$` before it becomes a path component; lesson files that are symlinks pointing outside `agent/lessons/` are skipped; the built client is served by Starlette `StaticFiles`, which refuses paths outside `app/client/dist`.
- All SQL is parameterized. `cache.db` is opened read-only.
- The client never uses `innerHTML`: every value is rendered through `textContent` or text nodes. The served client gets a strict Content-Security-Policy (no external scripts, styles or CDNs), plus `nosniff`, `DENY` framing and `no-referrer`.
- GET endpoints are not token-protected: they rely on the loopback bind, host allow-list and CORS. Set a token and a firewall before exposing the port beyond localhost.
