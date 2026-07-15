"""LangGraph engine parity with the deterministic runner + model-router seam."""
from hexacore.models import Engagement, EngagementStatus
from hexacore.safety import (
    ActionClassifier, ApprovalGate, AuditLog, KillSwitch, SafetyLayer, Scope, ScopeValidator,
    ActionClass,
)
from hexacore_tools import CapabilityExecutor
from hexacore_tools.adapters import default_registry
from hexacore_tools.backends.contract import RunResult
from hexacore_agent import LangGraphEngagementRunner, ModelRouter

SUBFINDER = '{"host":"api.acme-staging.com"}\n{"host":"evil.example.com"}\n'
NUCLEI = ('{"template-id":"CVE-1","matched-at":"https://api.acme-staging.com",'
          '"info":{"name":"Big Bug","severity":"high","classification":{"cwe-id":["CWE-79"]}}}\n')
NMAP = ('<?xml version="1.0"?><nmaprun><host><address addr="api.acme-staging.com" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="443"><state state="open"/>'
        '<service name="https"/></port></ports></host></nmaprun>')


class Fixture:
    def run(self, argv, *, timeout=None, allowed_egress=None, runtime=None):
        t = argv[0]
        if t == "subfinder": return RunResult(stdout=SUBFINDER)
        if t == "nuclei": return RunResult(stdout=NUCLEI)
        if t == "nmap": return RunResult(stdout=NMAP)
        return RunResult(stdout="")


def _executor():
    scope = Scope(allow_domains=["acme-staging.com"], allow_cidrs=["10.20.30.0/24"],
                  max_action_class=ActionClass.ACTIVE_SCAN)
    safety = SafetyLayer(scope_validator=ScopeValidator(scope), classifier=ActionClassifier(),
                         gate=ApprovalGate(), kill_switch=KillSwitch(), audit=AuditLog())
    return CapabilityExecutor(safety=safety, registry=default_registry(), sandbox=Fixture())


def _eng():
    return Engagement(name="acme", client="ACME", created_by="op",
                      status=EngagementStatus.RUNNING)


def test_langgraph_runs_and_finds():
    runner = LangGraphEngagementRunner(_executor())
    report = runner.run(_eng(), seed_domains=["acme-staging.com"], seed_hosts=[])
    assert report.counts.high >= 1          # nuclei High surfaced
    assert report.counts.info >= 1          # nmap open port + discovered hosts
    types = {e.type for e in report.events}
    assert {"phase.changed", "command.started", "finding.created"} <= types


def test_langgraph_denies_out_of_scope_discovery():
    runner = LangGraphEngagementRunner(_executor())
    report = runner.run(_eng(), seed_domains=["acme-staging.com"], seed_hosts=[])
    assert "evil.example.com" in report.denied_targets   # discovered but out of scope -> denied


def test_model_router_default_is_deterministic():
    r = ModelRouter(profile="deterministic")
    tasks = [("recon.dns", "a"), ("scan.ports", "b")]
    assert r.order(tasks) == tasks   # FIFO, no reordering without a model


TASKS = [("recon.dns", "a"), ("scan.ports", "b"), ("scan.tls", "c")]


def test_ollama_reorders_by_model_permutation():
    r = ModelRouter(profile="ollama", generate=lambda _p: "[2,0,1]")
    assert r.order(TASKS) == [TASKS[2], TASKS[0], TASKS[1]]


def test_ollama_accepts_object_wrapped_array():
    r = ModelRouter(profile="ollama", generate=lambda _p: '{"order": [1,2,0]}')
    assert r.order(TASKS) == [TASKS[1], TASKS[2], TASKS[0]]


def test_ollama_accepts_stringified_array_shapes():
    # Real llama3.2 output shapes observed live: a JSON-stringified array, bare and object-wrapped.
    for reply in ('"[1,2,0]"', '{"index": "[1,2,0]"}'):
        r = ModelRouter(profile="ollama", generate=lambda _p, x=reply: x)
        assert r.order(TASKS) == [TASKS[1], TASKS[2], TASKS[0]], reply


def test_ollama_falls_back_to_fifo_on_bad_permutation():
    # Dropped/duplicated/out-of-range indices must NOT be trusted — a model can't add or drop a
    # safety-approved task. Each returns the original FIFO order untouched.
    for bad in ("[0,1]", "[0,1,1]", "[0,1,5]", "not json", '{"nope": 1}'):
        r = ModelRouter(profile="ollama", generate=lambda _p, b=bad: b)
        assert r.order(TASKS) == TASKS


def test_ollama_falls_back_to_fifo_when_endpoint_errors():
    def boom(_p):
        raise ConnectionError("ollama down")
    r = ModelRouter(profile="ollama", generate=boom)
    assert r.order(TASKS) == TASKS   # a model outage never breaks or reorders the run
