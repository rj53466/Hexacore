"""In-process event bus for live WebSocket streaming.

The engagement runner executes in a worker thread; WebSocket handlers are async. `publish` is
therefore threadsafe — it schedules delivery onto the event loop via `call_soon_threadsafe`.
Each WebSocket subscriber gets its own queue. This is the relay the dashboard's live feed reads
(Brain/01 §3.1). A Redis pub/sub swaps in here for multi-process later (Epic I6).
"""
from __future__ import annotations

import asyncio
from typing import Optional


class EventBus:
    def __init__(self) -> None:
        self._subs: dict[str, set[asyncio.Queue]] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self, engagement_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subs.setdefault(engagement_id, set()).add(q)
        return q

    def unsubscribe(self, engagement_id: str, q: asyncio.Queue) -> None:
        subs = self._subs.get(engagement_id)
        if subs:
            subs.discard(q)
            if not subs:
                self._subs.pop(engagement_id, None)

    def publish(self, engagement_id: str, message: dict) -> None:
        """Deliver to all subscribers. Safe to call from any thread."""
        loop = self._loop
        if loop is None:
            return
        for q in list(self._subs.get(engagement_id, ())):
            loop.call_soon_threadsafe(q.put_nowait, message)
