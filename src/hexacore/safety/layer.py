"""SafetyLayer — the single choke point every tool invocation must pass (Brain/01 §3.8).

`authorize()` composes the whole conscience in one call: kill-switch check -> scope validation ->
action classification -> ceiling enforcement -> approval gate. It writes an audit event for every
decision and returns an Authorization telling the executor whether it may run, or (for gated
actions with no approval yet) that it must pause. There is intentionally no code path that runs a
tool without going through here.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .actions import ActionClass, requires_gate
from .approval import Approval, ApprovalGate
from .audit import AuditLog
from .classifier import ActionClassifier
from .killswitch import KillSwitch
from .scope import ScopeValidator


class Verdict(Enum):
    ALLOW = "allow"           # run it
    GATE = "gate"             # pause; a human must approve first
    DENY = "deny"             # blocked (out of scope / ceiling / killed)


@dataclass(frozen=True)
class Authorization:
    verdict: Verdict
    action_class: ActionClass
    reason: str
    approval: Optional[Approval] = None

    @property
    def may_run(self) -> bool:
        return self.verdict is Verdict.ALLOW


class SafetyViolation(Exception):
    """Raised when execution is attempted despite a non-ALLOW verdict."""


class SafetyLayer:
    def __init__(
        self,
        *,
        scope_validator: ScopeValidator,
        classifier: ActionClassifier,
        gate: ApprovalGate,
        kill_switch: KillSwitch,
        audit: AuditLog,
    ):
        self.scope = scope_validator
        self.classifier = classifier
        self.gate = gate
        self.kill_switch = kill_switch
        self.audit = audit

    def authorize(
        self,
        *,
        engagement_id: str,
        tool_run_id: str,
        capability: str,
        target: str,
        params: Optional[dict] = None,
        actor: str = "agent",
    ) -> Authorization:
        params = params or {}
        action_class = self.classifier.classify(capability, params)

        def deny(reason: str) -> Authorization:
            self.audit.record(
                "scope.denied", actor=actor, engagement_id=engagement_id,
                capability=capability, target=target,
                action_class=action_class.value, reason=reason,
            )
            return Authorization(Verdict.DENY, action_class, reason)

        # 1. Kill switch halts everything.
        if self.kill_switch.is_killed(engagement_id):
            return deny("kill switch is engaged")

        # 2. Scope + ceiling (the validator also enforces max_action_class).
        decision = self.scope.check(target, action_class)
        if not decision.allowed:
            return deny(decision.reason)

        # 3. Gate for exploit/destructive classes.
        if requires_gate(action_class):
            if self.gate.is_cleared(tool_run_id):
                approval = self.gate.get(tool_run_id)
                self.audit.record(
                    "gate.resolved", actor=actor, engagement_id=engagement_id,
                    capability=capability, target=target,
                    action_class=action_class.value, approval_id=approval.id,
                    decided_by=approval.decided_by,
                )
                return Authorization(Verdict.ALLOW, action_class,
                                     "approved by " + str(approval.decided_by), approval)
            approval = self.gate.request(
                tool_run_id=tool_run_id, engagement_id=engagement_id,
                capability=capability, target=target, action_class=action_class.value,
            )
            self.audit.record(
                "gate.requested", actor=actor, engagement_id=engagement_id,
                capability=capability, target=target,
                action_class=action_class.value, approval_id=approval.id,
            )
            return Authorization(
                Verdict.GATE, action_class,
                f"{action_class.value} requires human approval", approval,
            )

        # 4. Passive / active-scan within ceiling — allowed, audited.
        self.audit.record(
            "command.authorized", actor=actor, engagement_id=engagement_id,
            capability=capability, target=target, action_class=action_class.value,
        )
        return Authorization(Verdict.ALLOW, action_class, decision.reason)

    def enforce(self, authz: Authorization) -> Authorization:
        """Call this immediately before running a tool. Raises unless the verdict is ALLOW,
        making 'run without authorization' impossible to express by accident."""
        if not authz.may_run:
            raise SafetyViolation(f"{authz.verdict.value}: {authz.reason}")
        return authz
