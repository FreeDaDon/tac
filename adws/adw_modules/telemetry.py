"""Event stream: local JSONL (source of truth) + best-effort push to the control-plane dashboard."""

from __future__ import annotations

import json
import os
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
    _push(event)
    return event


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
