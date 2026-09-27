"""SQLite event store. All SQL is parameterized; the connection is opened lazily."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    adw_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    phase TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT '',
    data TEXT NOT NULL DEFAULT '{}',
    source TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_adw_id ON events(adw_id);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
"""

MAX_LIMIT = 1000


class EventStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._ready = False

    def _init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=10)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()
        self._ready = True

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if not self._ready:
                self._init()
            conn = sqlite3.connect(self.path, timeout=10)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        try:
            item["data"] = json.loads(item["data"] or "{}")
        except json.JSONDecodeError:
            item["data"] = {}
        return item

    def insert(self, event: dict[str, Any]) -> dict[str, Any]:
        record = {
            "adw_id": str(event.get("adw_id", "")),
            "event_type": str(event.get("event_type", "")),
            "phase": str(event.get("phase", "")),
            "message": str(event.get("message", "")),
            "data": json.dumps(event.get("data") or {}),
            "source": str(event.get("source", "")),
            "timestamp": str(event.get("timestamp", "")),
        }
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO events (adw_id, event_type, phase, message, data, source, timestamp)"
                " VALUES (:adw_id, :event_type, :phase, :message, :data, :source, :timestamp)",
                record,
            )
            new_id = cur.lastrowid
            row = c.execute("SELECT * FROM events WHERE id = ?", (new_id,)).fetchone()
        return self._row(row)

    def recent(
        self, limit: int = 100, adw_id: str | None = None, event_type: str | None = None
    ) -> list[dict[str, Any]]:
        """Newest first."""
        limit = max(1, min(int(limit), MAX_LIMIT))
        clauses: list[str] = []
        params: list[Any] = []
        if adw_id:
            clauses.append("adw_id = ?")
            params.append(adw_id)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        sql = f"SELECT * FROM events{where} ORDER BY id DESC LIMIT ?"  # noqa: S608 - clauses are constants
        with self._conn() as c:
            return [self._row(r) for r in c.execute(sql, params).fetchall()]

    def filter_options(self) -> dict[str, list[str]]:
        with self._conn() as c:
            out: dict[str, list[str]] = {}
            for col in ("adw_id", "event_type", "source"):
                rows = c.execute(
                    f"SELECT DISTINCT {col} FROM events WHERE {col} != '' ORDER BY {col} LIMIT 500"  # noqa: S608
                ).fetchall()
                out[col] = [r[0] for r in rows]
        return out

    def count(self) -> int:
        with self._conn() as c:
            return int(c.execute("SELECT COUNT(*) FROM events").fetchone()[0])
