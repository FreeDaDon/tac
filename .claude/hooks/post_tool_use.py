#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""PostToolUse telemetry. Best effort, never blocks: always exits 0.

POSTs {source_app, session_id, hook_event_type, payload:{tool_name, input}} to
$TAC_DASHBOARD_URL/api/hook-events with a 1s timeout. Input is truncated and never
includes file contents (Write/Edit bodies are dropped).
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request

MAX_INPUT_CHARS = 300
DROP_KEYS = {"content", "new_string", "old_string", "edits", "new_source"}


def truncated_input(tool_input: object) -> dict:
    if not isinstance(tool_input, dict):
        return {}
    out = {}
    for key, val in tool_input.items():
        if key in DROP_KEYS:
            continue
        text = val if isinstance(val, str) else json.dumps(val, default=str)
        out[key] = text[:MAX_INPUT_CHARS]
    return out


def main() -> None:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        url = os.environ.get("TAC_DASHBOARD_URL", "").rstrip("/")
        if not url.startswith(("http://", "https://")) or not isinstance(payload, dict):
            return
        body = {
            "source_app": "tac",
            "session_id": str(payload.get("session_id", "")),
            "hook_event_type": "PostToolUse",
            "payload": {
                "tool_name": str(payload.get("tool_name", "")),
                "input": truncated_input(payload.get("tool_input")),
            },
        }
        req = urllib.request.Request(  # noqa: S310 - scheme checked above, URL is operator-configured
            f"{url}/api/hook-events",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=1).close()  # noqa: S310 - scheme checked above
    except Exception:  # noqa: BLE001, S110 - telemetry must never break the agent
        pass


if __name__ == "__main__":
    main()
    sys.exit(0)
