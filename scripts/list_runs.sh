#!/usr/bin/env bash
# One line per ADW run: id, domain, phases, cost.
set -euo pipefail
cd "$(dirname "$0")/.."
shopt -s nullglob
for f in agent/runs/*/state.json; do
  uv run --quiet python - "$f" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
phases = " ".join(f"{k}:{v}" for k, v in d.get("phases", {}).items())
print(f"{d['adw_id']}  {d.get('domain','swe'):6}  ${d.get('usage',{}).get('cost_usd',0):.4f}  {phases}")
PY
done
