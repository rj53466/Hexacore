"""End-to-end SafetyLayer tests — the two guarantees Brain/03 puts in CI:

  H1: out-of-scope targets are denied + audited.
  H2: exploit-class actions cannot run without an approved gate.
"""
import pytest

from hexacore.safety import (
    ActionClass,
    ActionClassifier,
    ApprovalGate,
    ApprovalState,
    AuditLog,
    KillSwitch,
    SafetyLayer,
    SafetyViolation,
    Scope,
    ScopeValidator,
    Verdict,
)


def build_layer(max_action_class=ActionClass.ACTIVE_EXPLOIT):
    scope = Scope(
        allow_domains=["*.acme-staging.com"],
        allow_cidrs=["10.20.30.0/24"],
        deny_list=["10.20.30.5"],
        max_action_class=max_action_class,
    )
    return SafetyLayer(
        scope_validator=ScopeValidator(scope),
        classifier=ActionClassifier(),
        gate=ApprovalGate(),
        kill_switch=KillSwitch(),
        audit=AuditLog(),
    )


def authorize(layer, capability, target, params=None, tool_run_id="tr-1"):
    return layer.authorize(
        engagement_id="eng-1", tool_run_id=tool_run_id,
        capability=capability, target=target, params=params or {},
    )


# --- happy path ----------------------------------------------------------

def test_passive_recon_in_scope_allowed():
    layer = build_layer()
    authz = authorize(layer, "recon.subdomains", "api.acme-staging.com")
    assert authz.verdict is Verdict.ALLOW
    assert layer.enforce(authz).may_run


def test_active_scan_in_scope_allowed_and_audited():
    layer = build_layer()
    authz = authorize(layer, "scan.web_nuclei", "https://portal.acme-staging.com")
    assert authz.verdict is Verdict.ALLOW
    assert layer.audit.events_of_type("command.authorized")


# --- H1: out-of-scope denial --------------------------------------------

def test_out_of_scope_denied_and_audited():
    layer = build_layer()
    authz = authorize(layer, "scan.web_nuclei", "https://prod.example.com")
    assert authz.verdict is Verdict.DENY
    assert layer.audit.events_of_type("scope.denied")
    with pytest.raises(SafetyViolation):
        layer.enforce(authz)


def test_deny_list_target_denied():
    layer = build_layer()
    authz = authorize(layer, "scan.ports", "10.20.30.5")
    assert authz.verdict is Verdict.DENY


def test_scan_above_ceiling_denied():
    # Engagement ceiling is active-scan; an exploit-class action is denied by the ceiling.
    layer = build_layer(max_action_class=ActionClass.ACTIVE_SCAN)
    authz = authorize(layer, "verify.web_sqli", "api.acme-staging.com", {"mode": "exploit"})
    assert authz.verdict is Verdict.DENY


# --- H2: gate-bypass prevention -----------------------------------------

def test_exploit_class_requires_gate_not_allowed_by_default():
    layer = build_layer()
    authz = authorize(layer, "verify.web_sqli", "api.acme-staging.com", {"mode": "exploit"})
    assert authz.verdict is Verdict.GATE
    assert not authz.may_run
    with pytest.raises(SafetyViolation):
        layer.enforce(authz)


def test_unknown_capability_never_runs_unattended():
    # Unknown => DESTRUCTIVE. Under an active-exploit ceiling it is denied by the ceiling;
    # under a destructive ceiling it still must pass a human gate. Either way, never ALLOW.
    layer = build_layer()  # ceiling = active-exploit
    denied = authorize(layer, "mystery.capability", "api.acme-staging.com")
    assert denied.action_class is ActionClass.DESTRUCTIVE
    assert denied.verdict is Verdict.DENY

    layer2 = build_layer(max_action_class=ActionClass.DESTRUCTIVE)
    gated = authorize(layer2, "mystery.capability", "api.acme-staging.com")
    assert gated.verdict is Verdict.GATE
    assert not gated.may_run


def test_gate_clears_after_human_approval():
    layer = build_layer()
    first = authorize(layer, "verify.web_sqli", "api.acme-staging.com", {"mode": "exploit"})
    assert first.verdict is Verdict.GATE

    # A human approves via the resume token.
    layer.gate.resolve(
        first.approval.resume_token,
        decision=ApprovalState.APPROVED, decided_by="user:alice",
    )

    second = authorize(layer, "verify.web_sqli", "api.acme-staging.com", {"mode": "exploit"})
    assert second.verdict is Verdict.ALLOW
    assert layer.enforce(second).may_run
    assert layer.audit.events_of_type("gate.resolved")


def test_agent_cannot_self_approve_through_layer():
    from hexacore.safety import GateError
    layer = build_layer()
    first = authorize(layer, "verify.web_sqli", "api.acme-staging.com", {"mode": "exploit"})
    with pytest.raises(GateError):
        layer.gate.resolve(
            first.approval.resume_token,
            decision=ApprovalState.APPROVED, decided_by="agent",
        )


# --- kill switch ---------------------------------------------------------

def test_kill_switch_denies_everything():
    layer = build_layer()
    layer.kill_switch.trip("eng-1")
    authz = authorize(layer, "recon.subdomains", "api.acme-staging.com")
    assert authz.verdict is Verdict.DENY
    assert "kill switch" in authz.reason
