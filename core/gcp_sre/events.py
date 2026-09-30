"""Load log events from Splunk exports (JSON / JSONL / CSV), GCP Cloud Logging exports, or plain text.

Every field is untrusted. Loaders only parse and normalize; sanitizing happens where evidence is built.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.loaders import get_field

MAX_FILE_BYTES = 100_000_000
MAX_EVENTS = 500_000
MAX_MESSAGE_CHARS = 8_000
LEVELS = ("FATAL", "CRITICAL", "ERROR", "WARN", "WARNING", "INFO", "DEBUG", "TRACE")
ERROR_LEVELS = frozenset({"FATAL", "CRITICAL", "ERROR", "EMERGENCY", "ALERT"})
_LEVEL_RE = re.compile(r"\b(FATAL|CRITICAL|ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE)\b")
_TS_RE = re.compile(r"^\s*\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})?)\]?")
_MESSAGE_KEYS = ("_raw", "message", "textPayload", "msg", "log", "event")
_TIME_KEYS = ("_time", "timestamp", "time", "@timestamp", "ts", "receiveTimestamp")
_HOST_KEYS = ("host", "hostname", "resource.labels.instance_id", "resource.labels.pod_name",
              "resource.labels.service_name", "resource.labels.container_name", "kubernetes.pod_name")
_SOURCE_KEYS = ("sourcetype", "source", "logName", "resource.type")
_LEVEL_KEYS = ("level", "severity", "log_level", "loglevel", "log.level")
SNIFF_KEYS = ("_raw", "_time", "textPayload", "jsonPayload", "protoPayload")


@dataclass
class Event:
    line: int
    message: str
    ts: datetime | None = None
    host: str = ""
    source: str = ""
    level: str = ""


def parse_ts(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{9,13}(?:\.\d+)?", value.strip())):
        seconds = float(value)
        seconds = seconds / 1000 if seconds > 1e11 else seconds
        try:
            return datetime.fromtimestamp(seconds, UTC)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip().replace(",", ".")
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    text = text.replace("Z", "+00:00")
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def infer_level(message: str) -> str:
    m = _LEVEL_RE.search(message[:200])
    if not m:
        return ""
    level = m.group(1)
    return "WARN" if level.startswith("WARN") else level


def _first_value(record: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = get_field(record, key)
        if value not in (None, ""):
            return value
    return None


def record_to_event(record: dict[str, Any], line: int) -> Event | None:
    if isinstance(record.get("result"), dict):  # Splunk streaming export: {"preview":false,"result":{...}}
        record = record["result"]
    message = _first_value(record, _MESSAGE_KEYS)
    if message is None:
        payload = record.get("jsonPayload") or record.get("protoPayload")
        message = (get_field(record, "jsonPayload.message") or get_field(record, "protoPayload.status.message")
                   or (json.dumps(payload, default=str) if payload else None))
    if message is None:
        return None
    text = message if isinstance(message, str) else json.dumps(message, default=str)
    level = str(_first_value(record, _LEVEL_KEYS) or "").upper() or infer_level(text)
    return Event(line=line, message=text[:MAX_MESSAGE_CHARS], ts=parse_ts(_first_value(record, _TIME_KEYS)),
                 host=str(_first_value(record, _HOST_KEYS) or ""), source=str(_first_value(record, _SOURCE_KEYS) or ""),
                 level="WARN" if level.startswith("WARN") else level)


def _from_records(records: list[Any]) -> list[Event]:
    events = (record_to_event(r, i) for i, r in enumerate(records, start=1) if isinstance(r, dict))
    return [e for e in events if e]


def _from_text(text: str) -> list[Event]:
    """One event per log line; indented lines (stack frames) and `Caused by:` lines join the previous event."""
    events: list[Event] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if events and (line[0] in " \t" or line.startswith(("Caused by:", "\t"))) and len(events[-1].message) < MAX_MESSAGE_CHARS:
            events[-1].message += "\n" + line
            continue
        ts_match = _TS_RE.match(line)
        events.append(Event(line=line_no, message=line[:MAX_MESSAGE_CHARS], level=infer_level(line),
                            ts=parse_ts(ts_match.group(1)) if ts_match else None))
        if len(events) >= MAX_EVENTS:
            break
    return events


def load_events(path: Path) -> list[Event]:
    path = Path(path)
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"{path} exceeds {MAX_FILE_BYTES} bytes")
    text = path.read_text(encoding="utf-8", errors="replace")
    suffix = path.suffix.lower()
    stripped = text.lstrip()
    if suffix == ".csv":
        return _from_records(list(csv.DictReader(io.StringIO(text))))[:MAX_EVENTS]
    json_ext = suffix in {".json", ".jsonl", ".ndjson"}
    if json_ext or stripped[:1] in "[{":
        try:
            data = json.loads(text)
        except ValueError:
            data = None
            if not json_ext:  # e.g. a plain log whose lines start with "[2025-..."
                return _from_text(text)
        if isinstance(data, list):
            return _from_records(data)[:MAX_EVENTS]
        if isinstance(data, dict):
            rows = data.get("results") or data.get("entries") or data.get("events")
            return _from_records(rows if isinstance(rows, list) else [data])[:MAX_EVENTS]
        records = []
        for line in text.splitlines():
            try:
                records.append(json.loads(line))
            except ValueError:
                records.append({"message": line})
        return _from_records(records)[:MAX_EVENTS]
    return _from_text(text)


def sniff(path: Path, size: int = 20_000) -> str:
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            return fh.read(size)
    except OSError:
        return ""
