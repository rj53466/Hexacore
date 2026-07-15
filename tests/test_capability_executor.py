"""The CapabilityExecutor must never run a tool that hasn't cleared the safety layer.

Proves: in-scope active-scan runs and yields parsed findings; out-of-scope is denied (no run);
an exploit-class capability is gated (no run) until a human approves.
"""
import pytest

from hexacore.safety import (
    ActionClass, ActionClassifier, ApprovalGate, ApprovalState, AuditLog,
    KillSwitch, SafetyLayer, SafetyViolation, Scope, ScopeValidator,
)
from hexacore_tools import (
    CapabilityExecutor, CapabilityRegistry, ExecutionStatus, RunResult,
)
from hexacore_tools.adapters import NmapPortsAdapter, NucleiAdapter

NMAP_XML = (
    '<?xml version="1.0"?><nmaprun><host>'
    '<address addr="10.20.30.11" addrtype="ipv4"/>'
    '<ports><port protocol="tcp" portid="22"><state state="open"/>'
    '<service name="ssh" product="OpenSSH" version="7.2p2"/></port></ports>'
    '</host></nmaprun>'
)


class FakeSandbox:
    """Records the argv it was asked to run and returns canned output. Nothing executes."""
    def __init__(self, stdout=""):
        self.stdout = stdout
        self.calls = []

    def run(self, argv, *, timeout=None, allowed_egress=None, runtime=None):
        self.calls.append(argv)
        return RunResult(stdout=self.stdout, exit_code=0)


def build(sandbox, max_action_class=ActionClass.ACTIVE_EXPLOIT):
    scope = Scope(allow_domains=["*.acme-staging.com"], allow_cidrs=["10.20.30.0/24"],
                  deny_list=["10.20.30.5"], max_action_class=max_action_class)
    safety = SafetyLayer(
        scope_validator=ScopeValidator(scope), classifier=ActionClassifier(),
        gate=ApprovalGate(), kill_switch=KillSwitch(), audit=AuditLog(),
    )
    registry = CapabilityRegistry()
    registry.register(NmapPortsAdapter())
    registry.register(NucleiAdapter())
    executor = CapabilityExecutor(safety=safety, registry=registry, sandbox=sandbox)
    return safety, executor


def exec_ports(executor, target, tool_run_id="tr-1"):
    return executor.execute(
        engagement_id="eng-1", tool_run_id=tool_run_id,
        capability="scan.ports", target=target,
    )


def test_in_scope_scan_runs_and_parses():
    sandbox = FakeSandbox(stdout=NMAP_XML)
    _, executor = build(sandbox)
    result = exec_ports(executor, "10.20.30.11")
    assert result.status is ExecutionStatus.COMPLETED
    assert sandbox.calls  # the tool actually ran
    assert result.findings and result.findings[0].evidence["port"] == "22"


def test_out_of_scope_target_never_runs():
    sandbox = FakeSandbox(stdout=NMAP_XML)
    _, executor = build(sandbox)
    with pytest.raises(SafetyViolation):
        exec_ports(executor, "8.8.8.8")
    assert sandbox.calls == []  # nothing executed


def test_deny_listed_target_never_runs():
    sandbox = FakeSandbox(stdout=NMAP_XML)
    _, executor = build(sandbox)
    with pytest.raises(SafetyViolation):
        exec_ports(executor, "10.20.30.5")
    assert sandbox.calls == []


def test_exploit_capability_is_gated_not_run():
    sandbox = FakeSandbox(stdout="")
    _, executor = build(sandbox)
    result = executor.execute(
        engagement_id="eng-1", tool_run_id="tr-x", capability="verify.web_sqli",
        target="portal.acme-staging.com", params={"mode": "exploit"},
    )
    assert result.status is ExecutionStatus.GATED
    assert result.approval is not None
    assert sandbox.calls == []  # gated => nothing ran


def test_scan_above_ceiling_denied():
    sandbox = FakeSandbox(stdout=NMAP_XML)
    _, executor = build(sandbox, max_action_class=ActionClass.PASSIVE)
    with pytest.raises(SafetyViolation):
        exec_ports(executor, "10.20.30.11")  # active-scan > passive ceiling
    assert sandbox.calls == []
