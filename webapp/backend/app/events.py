from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any


class EventBroker:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def subscribe(self, scan_id: str) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
        async with self._lock:
            self._subscribers[scan_id].add(queue)
        return queue

    async def unsubscribe(self, scan_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        async with self._lock:
            subscribers = self._subscribers.get(scan_id)
            if subscribers:
                subscribers.discard(queue)
                if not subscribers:
                    self._subscribers.pop(scan_id, None)

    async def publish(self, scan_id: str, event: dict[str, Any]) -> None:
        async with self._lock:
            subscribers = tuple(self._subscribers.get(scan_id, ()))
        for queue in subscribers:
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass
