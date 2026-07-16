"""Approval Gate — human-in-the-loop control for exploit/destructive actions (Brain/05 §4, A6).

The gate is a control-flow interrupt, not a prompt the model can talk past. An action that
requires a gate cannot proceed unless a *persisted* Approval for that exact request exists and
has been resolved APPROVED by someone other than the agent. The agent cannot self-approve.
"""
from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

AGENT_ACTOR = "agent"


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ApprovalState(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


class GateError(Exception):
    """Raised on an illegal gate operation (e.g. an attempt to self-approve)."""


@dataclass
class Approval:
    tool_run_id: str
    engagement_id: str
    capability: str
    target: str
    action_class: str
    resume_token: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: ApprovalState = ApprovalState.PENDING
    requested_at: datetime = field(default_factory=_now)
    decided_at: Optional[datetime] = None
    decided_by: Optional[str] = None
    limits: dict = field(default_factory=dict)

    @property
    def is_approved(self) -> bool:
        return self.state is ApprovalState.APPROVED


class ApprovalGate:
    """In-memory Approval store + gate logic. A persistent backend (Postgres, Epic A6) swaps in
    behind the same interface later; the safety semantics live here."""

    def __init__(self) -> None:
        self._by_token: dict[str, Approval] = {}
        self._by_tool_run: dict[str, Approval] = {}

    def request(
        self,
        *,
        tool_run_id: str,
        engagement_id: str,
        capability: str,
        target: str,
        action_class: str,
    ) -> Approval:
        """Create a PENDING approval and return it (with a resume token for the console)."""
        approval = Approval(
            tool_run_id=tool_run_id,
            engagement_id=engagement_id,
            capability=capability,
            target=target,
            action_class=action_class,
        )
        self._by_token[approval.resume_token] = approval
        self._by_tool_run[tool_run_id] = approval
        return approval

    def resolve(
        self,
        resume_token: str,
        *,
        decision: ApprovalState,
        decided_by: str,
        limits: Optional[dict] = None,
    ) -> Approval:
        approval = self._by_token.get(resume_token)
        if approval is None:
            raise GateError("unknown resume token")
        if decision not in (ApprovalState.APPROVED, ApprovalState.DENIED):
            raise GateError("decision must be APPROVED or DENIED")
        if not decided_by or decided_by == AGENT_ACTOR:
            # Structural guarantee: the agent cannot approve its own gate.
            raise GateError("gate must be resolved by a human actor, not the agent")
        if approval.state is not ApprovalState.PENDING:
            raise GateError(f"approval already {approval.state.value}")
        approval.state = decision
        approval.decided_by = decided_by
        approval.decided_at = _now()
        approval.limits = dict(limits or {})
        return approval

    def is_cleared(self, tool_run_id: str) -> bool:
        """True only if this tool run has an APPROVED gate."""
        approval = self._by_tool_run.get(tool_run_id)
        return approval is not None and approval.is_approved

    def get(self, tool_run_id: str) -> Optional[Approval]:
        return self._by_tool_run.get(tool_run_id)

    def pending(self) -> list[Approval]:
        """All approvals still awaiting a human decision."""
        return [a for a in self._by_token.values() if a.state is ApprovalState.PENDING]
