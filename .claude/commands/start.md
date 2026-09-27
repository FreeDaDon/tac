---
description: Start the observability dashboard (interactive)
---
# Start the Dashboard

`scripts/start.sh` serves the API and the built client together (it builds `app/client` on first run).

## Instructions
1. Port: if `.ports.env` exists, use its `BACKEND_PORT`; otherwise `TAC_DASHBOARD_PORT` or 8000.
2. If `http://127.0.0.1:<port>/api/health` already responds, do not start a second copy.
3. Otherwise start it in the background so you don't block: `nohup sh ./scripts/start.sh > agent/start.log 2>&1 &`.
4. Wait up to 60 seconds for `http://127.0.0.1:<port>/api/health` to respond.
5. For client hot reload instead: `cd app/client && npm run dev` (Vite on 5173, proxies `/api` and `/ws`).

## Report
- The dashboard URL (`http://127.0.0.1:<port>`).
- If it failed to start, the last 20 lines of `agent/start.log`.
