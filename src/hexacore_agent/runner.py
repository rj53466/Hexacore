"""Deterministic engagement runner — the Phase-1 golden path without an LLM.

Flow (Brain/01 §5, Brain/02 §3):
  RECON  : recon.subdomains + recon.http_probe on each seed domain -> discover live hosts
  SCAN   : scan.ports + scan.web_nuclei on in-scope seed/discovered hosts
  ANALYZE: dedup findings + severity rollup

Every capability call goes through `CapabilityExecutor`, so the safety layer classifies, scope-
validates, and gates *before* anything runs. A discovered host that is out of scope is denied
automatically (the executor raises) and recorded as a `scope.denied` event rather than crashing
the run. Emitted events mirror the dashboard's live feed (Brain/01 §3.1) so a WebSocket relay can
subscribe later.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from hexacore.findings import FindingStore, SeverityCounts
from hexacore.models import Engagement
from hexacore.safety import SafetyViolation
from hexacore_tools import CapabilityExecutor, ExecutionStatus
from .analyzer import enrich_findings
from .skill_advisor import load_index, next_capabilities

_SKILL_INDEX_CACHE: Optional[list] = None


def _skill_index() -> list:
    """Load the skills index once per process (empty list if it hasn't been built yet)."""
    global _SKILL_INDEX_CACHE
    if _SKILL_INDEX_CACHE is None:
        try:
            _SKILL_INDEX_CACHE = load_index()
        except Exception:
            _SKILL_INDEX_CACHE = []
    return _SKILL_INDEX_CACHE


@dataclass
class RunEvent:
    type: str            # phase.changed | command.started | command.finished | scope.denied |
                         # gate.requested | finding.created
    phase: str
    detail: str
    payload: dict = field(default_factory=dict)


@dataclass
class EngagementReport:
    engagement_id: str
    name: str
    counts: SeverityCounts
    findings: list
    events: list[RunEvent]
    gated: list                    # approvals raised (non-empty only above scan ceiling)
    denied_targets: list[str]


EventSink = Callable[[RunEvent], None]

# The fixed Phase-1 plan (Brain/06 §7). All <= active-scan; no gates.
_RECON_CAPS = ["recon.subdomains", "recon.http_probe", "recon.dns", "recon.tech", "recon.ct_logs"]
_SCAN_CAPS = ["scan.ports", "scan.web_nuclei", "scan.tls", "scan.web_dir", "scan.web_nikto", "scan.cloud.scoutsuite", "scan.api.kiterunner"]
# Phase 3: enumeration + expanded verification
_ENUM_CAPS = ["enum.netexec", "enum.bloodhound", "enum.cloud.cloudfox", "enum.linux_persistence"]
_VERIFY_CAPS = ["verify.web_sqli", "verify.msf_check", "verify.idor", "verify.ssrf",
                "verify.adcs_find"]

# --- Chaining rules -----------------------------------------------------------
# After the scan phase, inspect findings to decide which enum/verify caps to queue.
# Each rule: (pattern_in_finding_text, capability_to_queue).
_CHAIN_RULES: list[tuple[list[str], str]] = [
    (["smb", "445/tcp", "microsoft-ds"], "enum.netexec"),
    (["ldap", "389/tcp", "636/tcp", "active directory"], "enum.bloodhound"),
    (["certificate services", "adcs", "certsrv"], "verify.adcs_find"),
]


def _chain_capabilities(store) -> set[str]:
    """Inspect existing findings and return extra capabilities worth queuing."""
    extra: set[str] = set()
    for finding in store.all():
        text = f"{finding.title} {finding.description} {finding.evidence}".lower()
        for patterns, cap in _CHAIN_RULES:
            if any(p in text for p in patterns):
                extra.add(cap)
    return extra


class SimpleEngagementRunner:
    def __init__(self, executor: CapabilityExecutor, *, on_event: Optional[EventSink] = None):
        self.executor = executor
        self.on_event = on_event

    def _emit(self, events: list[RunEvent], ev: RunEvent) -> None:
        events.append(ev)
        if self.on_event is not None:
            self.on_event(ev)

    def _run_capability(self, *, engagement: Engagement, phase: str, capability: str,
                        target: str, store: FindingStore, events: list[RunEvent],
                        gated: list, denied: list, seq: list[int]) -> list:
        seq[0] += 1
        tool_run_id = f"{engagement.id}-{seq[0]}"
        self._emit(events, RunEvent("command.started", phase,
                                    f"{capability} -> {target}",
                                    {"capability": capability, "target": target}))
        try:
            result = self.executor.execute(
                engagement_id=engagement.id, tool_run_id=tool_run_id,
                capability=capability, target=target, actor="agent",
            )
        except SafetyViolation as exc:
            denied.append(target)
            self._emit(events, RunEvent("scope.denied", phase, f"{capability} -> {target}: {exc}",
                                        {"capability": capability, "target": target,
                                         "reason": str(exc)}))
            return []

        if result.status is ExecutionStatus.GATED:
            gated.append(result.approval)
            self._emit(events, RunEvent("gate.requested", phase,
                                        f"{capability} -> {target} needs approval",
                                        {"capability": capability, "target": target}))
            return []

        new = store.add_many(result.findings)
        self._emit(events, RunEvent("command.finished", phase,
                                    f"{capability} -> {target}: {len(result.findings)} findings "
                                    f"({new} new)",
                                    {"capability": capability, "target": target,
                                     "findings": len(result.findings)}))
        for f in result.findings:
            self._emit(events, RunEvent("finding.created", phase, f.title,
                                        {"severity": f.severity.value, "asset": f.affected_asset}))
        return result.findings

    def run(self, engagement: Engagement, *, seed_domains: list[str],
            seed_hosts: Optional[list[str]] = None) -> EngagementReport:
        seed_hosts = list(seed_hosts or [])
        store = FindingStore()
        events: list[RunEvent] = []
        gated: list = []
        denied: list[str] = []
        seq = [0]

        def cap(phase, capability, target):
            return self._run_capability(
                engagement=engagement, phase=phase, capability=capability, target=target,
                store=store, events=events, gated=gated, denied=denied, seq=seq)

        # --- RECON ---
        self._emit(events, RunEvent("phase.changed", "recon", "Recon phase"))
        discovered_hosts: set[str] = set(seed_hosts)
        for domain in seed_domains:
            for f in cap("recon", "recon.subdomains", domain):
                host = f.evidence.get("host")
                if host:
                    discovered_hosts.add(host)
            # Probe the domain itself over HTTP.
            for f in cap("recon", "recon.http_probe", domain):
                host = f.evidence.get("url") or f.affected_asset
                if host:
                    discovered_hosts.add(f.affected_asset)

        # --- SCAN --- (in-scope hosts; out-of-scope discoveries are denied by the executor)
        self._emit(events, RunEvent("phase.changed", "scan", "Scan phase"))
        for host in sorted(discovered_hosts):
            for capability in _SCAN_CAPS:
                cap("scan", capability, host)

        # --- SKILL-DRIVEN CHAINING ---
        # Match every finding so far to the Heart/ skill corpus; each matched skill selects which
        # already-vetted capability should run next. This is routing only — every selected
        # capability is still executed below through CapabilityExecutor + the safety layer (scope,
        # gate, kill switch). A skill can pick the next step; it can never inject a raw command.
        skill_next = next_capabilities(store, _skill_index(),
                                       available=set(_ENUM_CAPS) | set(_VERIFY_CAPS))
        # Legacy text-pattern rules supplement the skill signal.
        selected = set(skill_next) | _chain_capabilities(store)
        for capname, skname in sorted(skill_next.items()):
            self._emit(events, RunEvent("skill.chain", "enum",
                                        f"skill '{skname}' -> next step: {capname}",
                                        {"skill": skname, "capability": capname}))

        # --- ENUM --- (skill-selected caps; fall back to the full set if no skill matched)
        self._emit(events, RunEvent("phase.changed", "enum", "Enum phase"))
        enum_caps = [c for c in _ENUM_CAPS if c in selected] or _ENUM_CAPS
        for host in sorted(discovered_hosts):
            for capability in enum_caps:
                cap("enum", capability, host)

        # --- VERIFY --- (skill-selected gated exploitation; fall back to the full set)
        self._emit(events, RunEvent("phase.changed", "verify", "Verify phase"))
        verify_caps = [c for c in _VERIFY_CAPS if c in selected] or _VERIFY_CAPS
        for host in sorted(discovered_hosts):
            for capability in verify_caps:
                cap("verify", capability, host)

        # --- ANALYZE ---
        self._emit(events, RunEvent("phase.changed", "analyze", "Analyze phase"))
        enrich_findings(store)
        counts = store.counts()
        self._emit(events, RunEvent("phase.changed", "report",
                                    f"{counts.total} findings "
                                    f"(C{counts.critical}/H{counts.high}/M{counts.medium}/"
                                    f"L{counts.low}/I{counts.info})"))

        return EngagementReport(
            engagement_id=engagement.id, name=engagement.name, counts=counts,
            findings=store.all(), events=events, gated=gated, denied_targets=denied,
        )

