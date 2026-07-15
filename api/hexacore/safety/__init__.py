"""HexaCore safety layer — the conscience (Brain/05).

Build order rule (Brain/04): this layer exists before any tool wrapper, and every tool call goes
through ``SafetyLayer.authorize`` / ``enforce``.
"""
from .actions import ActionClass, GATE_THRESHOLD, requires_gate
from .approval import Approval, ApprovalGate, ApprovalState, GateError
from .audit import AuditEvent, AuditLog
from .classifier import ActionClassifier, CapabilitySpec, UnknownCapability
from .killswitch import KillSwitch
from .layer import Authorization, SafetyLayer, SafetyViolation, Verdict
from .scope import Decision, Scope, ScopeValidator

__all__ = [
    "ActionClass", "GATE_THRESHOLD", "requires_gate",
    "Scope", "ScopeValidator", "Decision",
    "ActionClassifier", "CapabilitySpec", "UnknownCapability",
    "ApprovalGate", "Approval", "ApprovalState", "GateError",
    "KillSwitch",
    "AuditLog", "AuditEvent",
    "SafetyLayer", "Authorization", "Verdict", "SafetyViolation",
]
