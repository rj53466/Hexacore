"""Audit Log — append-only record of every safety decision & tool run (Brain/05 §8, Epic A8).

Write-once semantics: the writer only ever appends a line; it exposes no update or delete. Events
are JSON lines (one object per line) so the file is greppable and tail-followable. An optional
in-memory mirror makes assertions easy in tests and lets the API relay recent events.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class AuditEvent:
    type: str
    actor: str                       # "agent" | "user:<id>" | "system"
    engagement_id: Optional[str]
    payload: dict
    at: str = field(default_factory=_now_iso)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))


class AuditLog:
    """Thread-safe append-only JSONL writer with an in-memory mirror."""

    def __init__(self, path: Optional[str | os.PathLike] = None, *, mirror: bool = True):
        self._path = Path(path) if path is not None else None
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._mirror_enabled = mirror
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()

    def record(
        self,
        event_type: str,
        *,
        actor: str,
        engagement_id: Optional[str] = None,
        **payload: object,
    ) -> AuditEvent:
        event = AuditEvent(
            type=event_type,
            actor=actor,
            engagement_id=engagement_id,
            payload=dict(payload),
        )
        line = json.dumps(asdict(event), sort_keys=True, default=str)
        with self._lock:
            if self._path is not None:
                # Append + flush + fsync so a crash can't lose an already-acknowledged event.
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            if self._mirror_enabled:
                self._events.append(event)
        return event

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        """Read-only snapshot of the in-memory mirror."""
        with self._lock:
            return tuple(self._events)

    def events_of_type(self, event_type: str) -> list[AuditEvent]:
        return [e for e in self.events if e.type == event_type]
