"""End-to-end: scope file -> loaded engagement -> deterministic runner -> findings + counts.

A fixture backend returns canned tool output keyed by which tool is in the argv, so the whole
recon->scan->analyze flow (and safety routing) runs without any real tool. Also proves an
out-of-scope discovered host is denied by the executor, not scanned.
"""
import textwrap

import pytest

from hexacore.engagements import EngagementError, EngagementService
from hexacore.loader import load_engagement
from hexacore.safety import (
    ActionClassifier, ApprovalGate, AuditLog, KillSwitch, SafetyLayer, ScopeValidator,
)
from hexacore.safety.approval import ApprovalState
from hexacore_tools import CapabilityExecutor
from hexacore_tools.adapters import default_registry
from hexacore_tools.backends.contract import RunResult
from hexacore_agent import RunSession, SimpleEngagementRunner

SUBFINDER_OUT = '{"host":"api.acme-staging.com"}\n{"host":"evil.example.com"}\n'  # 2nd is out-of-scope
NUCLEI_OUT = ('{"template-id":"CVE-2021-1","matched-at":"https://api.acme-staging.com",'
              '"info":{"name":"Example High","severity":"high",'
              '"classification":{"cwe-id":["CWE-79"]}}}\n')
NMAP_OUT = ('<?xml version="1.0"?><nmaprun><host>'
            '<address addr="api.acme-staging.com" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="443"><state state="open"/>'
            '<service name="https" product="nginx" version="1.18.0"/></port></ports>'
            '</host></nmaprun>')


class FixtureBackend:
    """Returns output based on which tool the argv starts with."""
    def __init__(self):
        self.ran = []

    def run(self, argv, *, timeout=None, allowed_egress=None, runtime=None):
        self.ran.append(argv)
        tool = argv[0]
        if tool == "subfinder":
            return RunResult(stdout=SUBFINDER_OUT)
        if tool == "nuclei":
            return RunResult(stdout=NUCLEI_OUT)
        if tool == "nmap":
            return RunResult(stdout=NMAP_OUT)
        return RunResult(stdout="")   # httpx etc. -> nothing


# allow_domains uses the apex form so it matches both the apex and any subdomain (suffix match);
# a "*." wildcard would deliberately exclude the apex seed.
_SCOPE_NO_AUTH = textwrap.dedent("""
    name: acme-staging
    client: ACME
    scope:
      allow_domains: ["acme-staging.com"]
      max_action_class: active-scan
    autonomy_profile: scan-only
    seeds:
      domains: ["acme-staging.com"]
""")

_AUTH_BLOCK = textwrap.dedent("""
    authorization:
      authorizer_name: Jane Doe
      authorizer_email: jane@acme.example
      method: click-sign
""")

SCOPE_YAML = _SCOPE_NO_AUTH + _AUTH_BLOCK


def build(tmp_path):
    scope_file = tmp_path / "eng.yaml"
    scope_file.write_text(SCOPE_YAML, encoding="utf-8")
    audit, kill = AuditLog(), KillSwitch()
    service = EngagementService(audit=audit, kill_switch=kill)
    loaded = load_engagement(scope_file, service)
    service.start(loaded.engagement.id, actor="operator")

    backend = FixtureBackend()
    safety = SafetyLayer(
        scope_validator=ScopeValidator(loaded.engagement.scope), classifier=ActionClassifier(),
        gate=ApprovalGate(), kill_switch=kill, audit=audit,
    )
    executor = CapabilityExecutor(safety=safety, registry=default_registry(), sandbox=backend)
    return loaded, backend, SimpleEngagementRunner(executor)


def test_runner_produces_findings_and_counts(tmp_path):
    loaded, backend, runner = build(tmp_path)
    report = runner.run(loaded.engagement, seed_domains=loaded.seed_domains,
                        seed_hosts=loaded.seed_hosts)
    # Found the nuclei High + the nmap open-port INFO.
    assert report.counts.high >= 1
    assert report.counts.info >= 1
    titles = {f.title for f in report.findings}
    assert any("Example High" in t for t in titles)


def test_out_of_scope_discovery_is_denied_not_scanned(tmp_path):
    loaded, backend, runner = build(tmp_path)
    report = runner.run(loaded.engagement, seed_domains=loaded.seed_domains,
                        seed_hosts=loaded.seed_hosts)
    # evil.example.com was discovered by subfinder but must never be scanned.
    assert "evil.example.com" in report.denied_targets
    for argv in backend.ran:
        assert "evil.example.com" not in argv


def test_events_include_phases_and_findings(tmp_path):
    loaded, backend, runner = build(tmp_path)
    report = runner.run(loaded.engagement, seed_domains=loaded.seed_domains,
                        seed_hosts=loaded.seed_hosts)
    types = {e.type for e in report.events}
    assert {"phase.changed", "command.started", "command.finished", "finding.created"} <= types


def test_resume_skips_completed_and_only_retries_approved_gates(tmp_path):
    """A RunSession carried across two run() calls must not replay already-completed capabilities,
    and after approving a gated one, a resume must execute exactly that (and nothing already
    finished) -- the whole point of session-based resume instead of restarting the golden path."""
    scope_file = tmp_path / "eng.yaml"
    scope_file.write_text(_SCOPE_NO_AUTH.replace("active-scan", "active-exploit") + _AUTH_BLOCK,
                          encoding="utf-8")
    audit, kill = AuditLog(), KillSwitch()
    service = EngagementService(audit=audit, kill_switch=kill)
    loaded = load_engagement(scope_file, service)
    service.start(loaded.engagement.id, actor="operator")

    backend = FixtureBackend()
    gate = ApprovalGate()
    safety = SafetyLayer(
        scope_validator=ScopeValidator(loaded.engagement.scope), classifier=ActionClassifier(),
        gate=gate, kill_switch=kill, audit=audit,
    )
    executor = CapabilityExecutor(safety=safety, registry=default_registry(), sandbox=backend)
    runner = SimpleEngagementRunner(executor)
    session = RunSession()

    report1 = runner.run(loaded.engagement, seed_domains=loaded.seed_domains,
                         seed_hosts=loaded.seed_hosts, session=session)
    assert report1.gated, "active-exploit capabilities must gate, not auto-run"
    commands_after_first_run = len(backend.ran)

    for approval in gate.pending():
        gate.resolve(approval.resume_token, decision=ApprovalState.APPROVED, decided_by="operator")

    report2 = runner.run(loaded.engagement, seed_domains=loaded.seed_domains,
                         seed_hosts=loaded.seed_hosts, session=session)
    assert not report2.gated, "everything should be resolved once approved"

    new_commands = len(backend.ran) - commands_after_first_run
    assert 0 < new_commands <= len(report1.gated), (
        "resume must run only the newly-approved gates, not replay recon/scan")
    # First run's findings persist into the resume; nothing from before is lost or duplicated.
    assert len(report2.findings) >= len(report1.findings)
    first_titles = [f.title for f in report1.findings]
    assert len(first_titles) == len(set(first_titles)), "no duplicate findings within report1 itself"


def test_start_denied_without_authorization(tmp_path):
    # Same scope, but no authorization block -> cannot start (deny-by-default).
    scope_file = tmp_path / "eng.yaml"
    scope_file.write_text(_SCOPE_NO_AUTH, encoding="utf-8")
    service = EngagementService(audit=AuditLog(), kill_switch=KillSwitch())
    loaded = load_engagement(scope_file, service)
    with pytest.raises(EngagementError):
        service.start(loaded.engagement.id, actor="operator")
