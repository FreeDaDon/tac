#!/usr/bin/env bash
# Stop app processes listening on the ports declared in trees/*/.ports.env (ADW range 9100-9199 only).
set -euo pipefail
cd "$(dirname "$0")/.."
shopt -s nullglob
for env in trees/*/.ports.env; do
  for port in $(grep -E '^(BACKEND|FRONTEND)_PORT=[0-9]{1,5}$' "$env" | cut -d= -f2 || true); do
    if (( 10#$port < 9100 || 10#$port > 9199 )); then
      echo "$env: ignoring port $port outside 9100-9199" >&2
      continue
    fi
    pids="$(lsof -t -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
    if [ -n "$pids" ]; then echo "$env port $port: stopping $pids"; kill $pids || true; fi
  done
done
