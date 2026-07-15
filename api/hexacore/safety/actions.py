"""Action classification vocabulary.

Every intended tool action is labelled with exactly one of these classes, ordered by how
dangerous it is. The ordering is load-bearing: an engagement's ``max_action_class`` is a
ceiling, and anything ``>= ACTIVE_EXPLOIT`` requires a human approval gate (Brain/05 §4).
"""
from __future__ import annotations

from enum import Enum
from functools import total_ordering


@total_ordering
class ActionClass(Enum):
    PASSIVE = "passive"
    ACTIVE_SCAN = "active-scan"
    ACTIVE_EXPLOIT = "active-exploit"
    DESTRUCTIVE = "destructive"

    @property
    def rank(self) -> int:
        return _ORDER.index(self)

    def __lt__(self, other: "ActionClass") -> bool:
        if not isinstance(other, ActionClass):
            return NotImplemented
        return self.rank < other.rank

    @classmethod
    def parse(cls, value: "str | ActionClass") -> "ActionClass":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError(
                f"unknown action class {value!r}; expected one of "
                f"{[c.value for c in cls]}"
            ) from exc


# Least -> most dangerous. ActionClass.rank / comparisons depend on this order.
_ORDER = [
    ActionClass.PASSIVE,
    ActionClass.ACTIVE_SCAN,
    ActionClass.ACTIVE_EXPLOIT,
    ActionClass.DESTRUCTIVE,
]

# Anything at or above this class must pass a human approval gate before running.
GATE_THRESHOLD = ActionClass.ACTIVE_EXPLOIT


def requires_gate(action_class: ActionClass) -> bool:
    """True if the class needs an approved human gate before it may execute."""
    return action_class >= GATE_THRESHOLD
