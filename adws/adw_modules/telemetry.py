"""Event stream: local JSONL (source of truth) + best-effort push to the control-plane dashboard."""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from typing import Any

from .data_types import TelemetryEvent
from .utils import run_dir


def emit(adw_id: str, event_type: str, phase: str = "", message: str = "", **data: Any) -> TelemetryEvent:
    """Record an event. Never raises: telemetry must not break a workflow."""
    event = TelemetryEvent(adw_id=adw_id, event_type=event_type, phase=phase, message=message, data=data)
    try:
        path = run_dir(adw_id) / "events.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as fh:
            fh.write(event.model_dump_json() + "\n")
    except Exception:  # noqa: BLE001, S110 - telemetry is best effort by design
        pass
    _echo(event)
    _push(event)
    return event


_ECHO_TYPES = {"phase_start", "phase_end", "agent_call", "repair", "error", "budget", "pipeline", "gate"}


def _echo(event: TelemetryEvent) -> None:
    """Human-readable progress on stderr (silence with TAC_QUIET=1)."""
    if event.event_type not in _ECHO_TYPES or os.getenv("TAC_QUIET") == "1":
        return
    extra = ""
    if event.event_type == "agent_call":
        extra = f" [{event.data.get('model', '')} ${event.data.get('cost_usd', 0) or 0:.4f}]"
    elif event.event_type == "phase_end":
        extra = f" ({event.data.get('status', '')}, {event.data.get('duration_s', '')}s)"
    print(f"[{event.adw_id}] {event.event_type:<11} {event.phase:<9} {event.message}{extra}"[:300],
          file=sys.stderr, flush=True)


def _push(event: TelemetryEvent) -> None:
    url = os.getenv("TAC_DASHBOARD_URL")
    if not url or os.getenv("TAC_TELEMETRY_PUSH", "1") == "0":
        return
    if not url.startswith(("http://", "https://")):
        return
    try:
        req = urllib.request.Request(  # noqa: S310 - scheme validated above
            url.rstrip("/") + "/api/events",
            data=event.model_dump_json().encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=1.5).close()  # noqa: S310
    except Exception:  # noqa: BLE001, S110
        pass


def read_events(adw_id: str) -> list[dict[str, Any]]:
    path = run_dir(adw_id) / "events.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
