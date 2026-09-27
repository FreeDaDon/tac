#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Stop hook: append a session-end record to agent/hook_logs/stop.jsonl. Always exits 0."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        if not isinstance(payload, dict):
            payload = {}
        root = Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
        log_dir = root / "agent" / "hook_logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "session_id": str(payload.get("session_id", "")),
            "stop_hook_active": bool(payload.get("stop_hook_active", False)),
        }
        with open(log_dir / "stop.jsonl", "a") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception:  # noqa: BLE001, S110 - logging only
        pass


if __name__ == "__main__":
    main()
    sys.exit(0)
