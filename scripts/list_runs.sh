#!/usr/bin/env bash
# One line per ADW run: id, domain, cost, phases. Unreadable state files are reported, not fatal.
set -euo pipefail
cd "$(dirname "$0")/.."
exec uv run --quiet python - <<'PY'
import json
from pathlib import Path

for path in sorted(Path("agent/runs").glob("*/state.json")):
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        phases = " ".join(f"{k}:{v}" for k, v in (d.get("phases") or {}).items())
        cost = float((d.get("usage") or {}).get("cost_usd") or 0)
        print(f"{d.get('adw_id', path.parent.name)}  {d.get('domain') or 'swe':6}  ${cost:.4f}  {phases}")
    except Exception as exc:
        print(f"{path.parent.name}  unreadable state.json ({exc.__class__.__name__})")
PY
