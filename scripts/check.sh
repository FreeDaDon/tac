#!/usr/bin/env bash
# Run every validation gate locally, exactly as the ADWs do (minus agent-backed gates).
set -euo pipefail
cd "$(dirname "$0")/.."
echo "== lint";   uv run ruff check .
echo "== types";  uv run mypy adws core app/server
echo "== unit";   uv run pytest -q
echo "== secrets"; uv run python -m core.registry swe . --tool secret_scan --fail-on high
if [ -f app/client/package.json ]; then
  echo "== client"
  (cd app/client && npm ci --silent --no-audit --no-fund && npx tsc --noEmit && npm run build --silent)
fi
echo "all gates passed"
