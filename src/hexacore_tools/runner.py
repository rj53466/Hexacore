"""CapabilityExecutor — the only path from "agent wants to run a capability" to a tool running.

It composes the safety layer with an adapter: classify + scope-validate + gate FIRST, and only
on an ALLOW verdict does it build the command, hand it to a sandboxed runner, and parse the
output into findings. A GATE verdict returns the pending approval (no execution); a DENY raises.

The `SandboxRunner` protocol is the seam where the ephemeral-Docker/Kali runner plugs in
(Epic C16). Tests inject a fake runner, so the whole safety-routing + parsing path is exercised
without running any real tool.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Protocol

from hexacore.safety import SafetyLayer, SafetyViolation, Verdict
from hexacore.safety.approval import Approval
# Reuse the Scope Validator's own target->host normalization so the container egress firewall
# allows exactly the host the safety layer just authorized (no second, divergent parser).
from hexacore.safety.scope import _extract_host, _normalize_host

from .base import CapabilityRegistry, Finding
from .backends.contract import RunResult  # shared run contract


class SandboxRunner(Protocol):
    """Any tool-execution backend. `hexacore_tools.backends` provides Docker/VM/local/dryrun
    implementations, but anything with this method works."""
    def run(self, argv: list[str], *, timeout: Optional[float] = None,
            allowed_egress: Optional[list[str]] = None,
            runtime: Optional[str] = None) -> RunResult: ...


class ExecutionStatus(Enum):
    COMPLETED = "completed"
    GATED = "gated"        # paused for human approval; nothing ran


@dataclass
class ExecutionResult:
    status: ExecutionStatus
    capability: str
    target: str
    action_class: str
    findings: list[Finding] = field(default_factory=list)
    run: Optional[RunResult] = None
    approval: Optional[Approval] = None
    reason: str = ""


class CapabilityExecutor:
    def __init__(
        self,
        *,
        safety: SafetyLayer,
        registry: CapabilityRegistry,
        sandbox: SandboxRunner,
        runtime: Optional[str] = None,
    ):
        self.safety = safety
        self.registry = registry
        self.sandbox = sandbox
        self.runtime = runtime

    def execute(
        self,
        *,
        engagement_id: str,
        tool_run_id: str,
        capability: str,
        target: str,
        params: Optional[dict] = None,
        actor: str = "agent",
        timeout: Optional[float] = None,
    ) -> ExecutionResult:
        params = params or {}

        # 1. Safety FIRST — classify, scope-validate, gate. This only needs the capability
        #    name, so a gated/denied action need not have a runnable adapter yet.
        authz = self.safety.authorize(
            engagement_id=engagement_id, tool_run_id=tool_run_id,
            capability=capability, target=target, params=params, actor=actor,
        )

        if authz.verdict is Verdict.GATE:
            return ExecutionResult(
                status=ExecutionStatus.GATED, capability=capability, target=target,
                action_class=authz.action_class.value, approval=authz.approval,
                reason=authz.reason,
            )
        if authz.verdict is Verdict.DENY:
            # enforce() raises SafetyViolation — deny is not a runnable state.
            raise SafetyViolation(f"{authz.verdict.value}: {authz.reason}")

        self.safety.enforce(authz)  # belt-and-suspenders: guarantees ALLOW before running

        # 2. Only now (verdict ALLOW) do we need a runnable adapter.
        adapter = self.registry.get(capability)
        if adapter is None:
            raise KeyError(f"no adapter registered for capability {capability!r}")

        # 3. Build the command and run it in the sandbox, confining container egress to the
        #    single in-scope host we just authorized (defence-in-depth; backends that can't
        #    firewall simply ignore it).
        argv = adapter.build_command(target, params)
        egress_host = _normalize_host(_extract_host(target))
        result = self.sandbox.run(
            argv, timeout=timeout,
            allowed_egress=[egress_host] if egress_host else None,
            runtime=self.runtime,
        )

        # 3. Parse machine-readable output into normalized findings.
        findings = adapter.parse(result.stdout, target)
        return ExecutionResult(
            status=ExecutionStatus.COMPLETED, capability=capability, target=target,
            action_class=authz.action_class.value, findings=findings, run=result,
        )
