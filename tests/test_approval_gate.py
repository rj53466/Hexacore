import pytest

from hexacore.safety import ApprovalGate, ApprovalState, GateError


def _request(gate, tool_run_id="tr-1"):
    return gate.request(
        tool_run_id=tool_run_id, engagement_id="eng-1",
        capability="verify.web_sqli", target="portal.acme-staging.com",
        action_class="active-exploit",
    )


def test_pending_gate_is_not_cleared():
    gate = ApprovalGate()
    _request(gate)
    assert not gate.is_cleared("tr-1")


def test_human_approval_clears_gate():
    gate = ApprovalGate()
    approval = _request(gate)
    gate.resolve(approval.resume_token, decision=ApprovalState.APPROVED, decided_by="user:alice")
    assert gate.is_cleared("tr-1")


def test_agent_cannot_self_approve():
    gate = ApprovalGate()
    approval = _request(gate)
    with pytest.raises(GateError):
        gate.resolve(approval.resume_token, decision=ApprovalState.APPROVED, decided_by="agent")
    assert not gate.is_cleared("tr-1")


def test_empty_actor_rejected():
    gate = ApprovalGate()
    approval = _request(gate)
    with pytest.raises(GateError):
        gate.resolve(approval.resume_token, decision=ApprovalState.APPROVED, decided_by="")


def test_denied_gate_stays_blocked():
    gate = ApprovalGate()
    approval = _request(gate)
    gate.resolve(approval.resume_token, decision=ApprovalState.DENIED, decided_by="user:alice")
    assert not gate.is_cleared("tr-1")


def test_cannot_resolve_twice():
    gate = ApprovalGate()
    approval = _request(gate)
    gate.resolve(approval.resume_token, decision=ApprovalState.APPROVED, decided_by="user:alice")
    with pytest.raises(GateError):
        gate.resolve(approval.resume_token, decision=ApprovalState.DENIED, decided_by="user:bob")


def test_unknown_token_rejected():
    gate = ApprovalGate()
    with pytest.raises(GateError):
        gate.resolve("nope", decision=ApprovalState.APPROVED, decided_by="user:alice")
