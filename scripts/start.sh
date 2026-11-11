#!/usr/bin/env bash
# Start the control-plane dashboard (API + built client) on 127.0.0.1.
# Ports: TAC_DASHBOARD_PORT (default 8000). Inside a worktree, BACKEND_PORT from .ports.env overrides it.
# The client is rebuilt whenever its sources are newer than app/client/dist.
[ -n "${BASH_VERSION:-}" ] || exec bash "$0" "$@"
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f .ports.env ]; then
  port="$(grep -E '^BACKEND_PORT=' .ports.env | tail -n 1 | cut -d= -f2- || true)"
  if [ -n "$port" ]; then
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || { echo "invalid BACKEND_PORT in .ports.env: $port" >&2; exit 2; }
    export TAC_DASHBOARD_PORT="$port"
  fi
  # A worktree serves a throwaway app under test for E2E/review: no dashboard auth there.
  unset TAC_DASHBOARD_TOKEN
fi
client=app/client
if [ -f "$client/package.json" ]; then
  stale="$(find "$client/src" "$client/index.html" "$client/package.json" "$client/package-lock.json" \
    "$client/vite.config.ts" "$client/tsconfig.json" -newer "$client/dist/index.html" -print -quit 2>/dev/null || true)"
  if [ ! -f "$client/dist/index.html" ] || [ -n "$stale" ]; then
    (cd "$client" && npm ci --silent --no-audit --no-fund && npm run build --silent)
  fi
fi
exec uv run python app/server/run.py
