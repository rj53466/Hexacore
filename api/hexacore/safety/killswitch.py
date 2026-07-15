"""Kill Switch — global + per-engagement halt (Brain/05 §6, Epic A7).

A tripped switch must be checked before every tool run so nothing new starts, in addition to the
runtime terminating in-flight containers (that container-teardown side lands with the executor in
a later phase). This class is the authoritative flag + audit hook.
"""
from __future__ import annotations

from typing import Callable, Optional

# Called on every trip so the event reaches the append-only audit log.
KillListener = Callable[[Optional[str]], None]


class KillSwitch:
    def __init__(self, on_trip: Optional[KillListener] = None) -> None:
        self._global = False
        self._engagements: set[str] = set()
        self._on_trip = on_trip

    def trip(self, engagement_id: Optional[str] = None) -> None:
        """Trip globally (``engagement_id=None``) or for a single engagement."""
        if engagement_id is None:
            self._global = True
        else:
            self._engagements.add(engagement_id)
        if self._on_trip is not None:
            self._on_trip(engagement_id)

    def reset(self, engagement_id: Optional[str] = None) -> None:
        """Clear a switch (operational recovery). Global reset also clears per-engagement flags."""
        if engagement_id is None:
            self._global = False
            self._engagements.clear()
        else:
            self._engagements.discard(engagement_id)

    def is_killed(self, engagement_id: Optional[str] = None) -> bool:
        if self._global:
            return True
        return engagement_id is not None and engagement_id in self._engagements
