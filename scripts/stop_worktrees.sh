#!/usr/bin/env bash
# Stop any app processes listening on the ADW port range (9100-9199).
set -euo pipefail
for port in $(seq 9100 9199); do
  pids="$(lsof -t -iTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
  if [ -n "$pids" ]; then echo "port $port: stopping $pids"; kill $pids || true; fi
done
