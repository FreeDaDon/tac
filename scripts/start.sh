#!/usr/bin/env bash
# Start the control-plane dashboard (API + built client) on 127.0.0.1.
# Ports: TAC_DASHBOARD_PORT (default 8000). Inside a worktree, .ports.env overrides it.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f .ports.env ]; then
  # shellcheck disable=SC1091
  set -a; source .ports.env; set +a
  export TAC_DASHBOARD_PORT="${BACKEND_PORT:-8000}"
fi
if [ -f app/client/package.json ] && [ ! -d app/client/dist ]; then
  (cd app/client && npm ci --silent --no-audit --no-fund && npm run build --silent)
fi
exec uv run python app/server/run.py
