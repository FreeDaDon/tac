"""WebSocket fan-out: every client gets a bounded queue drained by its own sender task."""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from typing import Any

from fastapi import WebSocket

TRY_AGAIN_LATER = 1013


@dataclass
class _Client:
    queue: asyncio.Queue[dict[str, Any]]
    sender: asyncio.Task[None] | None = None


class ConnectionManager:
    def __init__(self, max_clients: int = 50, queue_size: int = 256) -> None:
        self.max_clients = max_clients
        self.queue_size = queue_size
        self._clients: dict[WebSocket, _Client] = {}
        self._closing: set[asyncio.Task[None]] = set()

    @property
    def count(self) -> int:
        return len(self._clients)

    def connect(self, ws: WebSocket) -> bool:
        """Start queueing broadcasts for ws. False when the client cap is reached."""
        if len(self._clients) >= self.max_clients:
            return False
        self._clients[ws] = _Client(asyncio.Queue(self.queue_size))
        return True

    def start(self, ws: WebSocket) -> None:
        """Deliver queued broadcasts from now on; call once whatever must arrive first has been sent."""
        client = self._clients.get(ws)
        if client and client.sender is None:
            client.sender = asyncio.create_task(self._send(ws, client.queue))

    def disconnect(self, ws: WebSocket) -> None:
        client = self._clients.pop(ws, None)
        if client and client.sender:
            client.sender.cancel()

    def broadcast(self, message: dict[str, Any]) -> None:
        """Never waits on a client: one whose queue is full is too slow and gets dropped."""
        for ws, client in list(self._clients.items()):
            try:
                client.queue.put_nowait(message)
            except asyncio.QueueFull:
                self.disconnect(ws)
                task = asyncio.create_task(self._close(ws))
                self._closing.add(task)
                task.add_done_callback(self._closing.discard)

    async def _send(self, ws: WebSocket, queue: asyncio.Queue[dict[str, Any]]) -> None:
        try:
            while True:
                await ws.send_json(await queue.get())
        except Exception:  # noqa: BLE001 - any send failure means the client is gone
            self._clients.pop(ws, None)

    @staticmethod
    async def _close(ws: WebSocket) -> None:
        with contextlib.suppress(Exception):
            await asyncio.wait_for(ws.close(code=TRY_AGAIN_LATER), timeout=5)
