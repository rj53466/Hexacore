"""LangGraph orchestrator (Brain/01 §3.3, work-order item 5).

A stateful graph with four nodes — ``planner`` -> ``execute`` -> ``scan_setup`` /
``verify_setup`` -> (loop back to ``execute``) — driven by a ModelRouter. ``execute`` runs one
queued capability per step through CapabilityExecutor (safety layer first); ``scan_setup`` and
``verify_setup`` build the next phase's queue from hosts discovered so far.

The router's default profile is `deterministic`: fixed phase capability lists, FIFO order, no LLM
call — the graph runs fully offline (the scan-only fallback the spec mandates). The `local`/`ollama`
profile lets a local Ollama model *reprioritise* the queue (`ModelRouter.order`); it only permutes
an already-safety-approved task set and falls back to FIFO on any error. Execution always goes
through CapabilityExecutor + the safety layer.

Returns the same EngagementReport shape as SimpleEngagementRunner, so it's a drop-in engine.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Callable, Optional, TypedDict

from langgraph.graph import END, START, StateGraph

from hexacore.findings import FindingStore
from hexacore.safety import SafetyViolation
from hexacore_tools import CapabilityExecutor, ExecutionStatus
from .runner import EngagementReport, RunEvent
from .analyzer import enrich_findings
from .skill_advisor import ollama_generate

_RECON_CAPS = ["recon.subdomains", "recon.http_probe", "recon.dns", "recon.tech", "recon.ct_logs"]
_SCAN_CAPS = ["scan.ports", "scan.web_nuclei", "scan.tls", "scan.web_dir", "scan.web_nikto"]
_ENUM_CAPS = ["enum.netexec", "enum.bloodhound"]
_VERIFY_CAPS = ["verify.web_sqli", "verify.msf_check", "verify.idor", "verify.ssrf",
                "verify.adcs_find"]


class ModelRouter:
    """Chooses the plan and prioritises tasks.

    `deterministic` (default) uses no model — fixed caps, FIFO order — so the graph runs fully
    offline. `local`/`ollama` (the value `.env.example` documents is `local`) asks a local Ollama
    model to *reprioritise* the task list by likely impact.
    The model can ONLY permute an already-fixed, safety-approved task set: it never picks which
    capabilities run (those stay the fixed Phase lists) and never invents targets, and every task
    it reorders still goes through CapabilityExecutor + the safety layer. Any model error, timeout,
    or non-permutation response falls back to deterministic FIFO — a model outage can't break or
    widen an engagement.
    """

    def __init__(self, profile: Optional[str] = None, *, model: Optional[str] = None,
                 host: Optional[str] = None,
                 generate: Optional[Callable[[str], str]] = None, timeout: float = 30.0):
        self.profile = profile or os.getenv("HEXACORE_MODEL_PROFILE", "deterministic")
        self.model = model or os.getenv("HEXACORE_OLLAMA_MODEL", "llama3.2")
        self.host = (host or os.getenv("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")
        self.timeout = timeout
        self._generate = generate or self._ollama_generate  # injectable for tests

    def recon_caps(self) -> list[str]:
        return list(_RECON_CAPS)

    def scan_caps(self) -> list[str]:
        return list(_SCAN_CAPS)

    def enum_caps(self) -> list[str]:
        return list(_ENUM_CAPS)

    def verify_caps(self) -> list[str]:
        return list(_VERIFY_CAPS)

    def order(self, tasks: list[tuple[str, str]]) -> list[tuple[str, str]]:
        # deterministic (and single-item queues) = FIFO. `ollama` reprioritises by likely impact.
        if self.profile not in ("ollama", "local") or len(tasks) < 2:
            return tasks
        try:
            idx = self._llm_priority(list(tasks))
        except Exception:
            return tasks  # fail-safe to deterministic FIFO — never let a model issue break a run
        return [tasks[i] for i in idx]

    def _llm_priority(self, tasks: list[tuple[str, str]]) -> list[int]:
        """Ask the model to return a permutation of task indices, ordered most-impactful first.
        Raises unless the reply is a strict permutation of 0..N-1 (guards against the model adding,
        dropping, or duplicating a task — the caller then falls back to FIFO)."""
        listing = "\n".join(f"{i}: {c} -> {t}" for i, (c, t) in enumerate(tasks))
        prompt = (
            "You are prioritising authorized penetration-testing tasks for an engagement. "
            "Order them so the highest-security-impact tasks run first. Do NOT add, remove, or "
            "invent tasks — only reorder the ones given.\n\n"
            f"Tasks (index: capability -> target):\n{listing}\n\n"
            f"Respond with ONLY a JSON array of all {len(tasks)} indices in the order to run "
            'them, e.g. [2,0,1]. No prose.'
        )
        parsed = self._coerce_indices(json.loads(self._generate(prompt)))
        if isinstance(parsed, list) and sorted(parsed) == list(range(len(tasks))):
            return parsed
        raise ValueError("model reply was not a permutation of the task indices")

    @staticmethod
    def _coerce_indices(parsed):
        # Real models are messy: the index array shows up bare ([2,0,1]), wrapped in an object
        # ({"order": [...]}), or JSON-stringified ("[2,0,1]" / {"index": "[2,0,1]"}). Dig the list
        # out of any of these; anything else falls through and fails the permutation check.
        if isinstance(parsed, str):
            parsed = json.loads(parsed)
        if isinstance(parsed, dict):
            parsed = next((v for v in parsed.values() if isinstance(v, (list, str))), None)
            if isinstance(parsed, str):
                parsed = json.loads(parsed)
        return parsed

    def _ollama_generate(self, prompt: str) -> str:
        return ollama_generate(prompt, host=self.host, model=self.model, timeout=self.timeout)


class GraphState(TypedDict):
    phase: str
    queue: list          # list[[capability, target]]
    steps: int


@dataclass
class _Ctx:
    executor: CapabilityExecutor
    engagement: object
    router: ModelRouter
    on_event: Optional[Callable[[RunEvent], None]]
    seed_domains: list
    seed_hosts: list
    store: FindingStore = field(default_factory=FindingStore)
    events: list = field(default_factory=list)
    gated: list = field(default_factory=list)
    denied: list = field(default_factory=list)
    discovered: set = field(default_factory=set)
    seq: int = 0

    def emit(self, ev: RunEvent) -> None:
        self.events.append(ev)
        if self.on_event:
            self.on_event(ev)


def _run_one(ctx: _Ctx, phase: str, capability: str, target: str) -> None:
    ctx.seq += 1
    ctx.emit(RunEvent("command.started", phase, f"{capability} -> {target}",
                      {"capability": capability, "target": target}))
    try:
        result = ctx.executor.execute(
            engagement_id=ctx.engagement.id, tool_run_id=f"{ctx.engagement.id}-{ctx.seq}",
            capability=capability, target=target, actor="agent")
    except SafetyViolation as exc:
        ctx.denied.append(target)
        ctx.emit(RunEvent("scope.denied", phase, f"{capability} -> {target}: {exc}",
                          {"capability": capability, "target": target}))
        return
    if result.status is ExecutionStatus.GATED:
        ctx.gated.append(result.approval)
        ctx.emit(RunEvent("gate.requested", phase, f"{capability} -> {target} needs approval", {}))
        return
    ctx.store.add_many(result.findings)
    ctx.emit(RunEvent("command.finished", phase,
                      f"{capability} -> {target}: {len(result.findings)} findings", {}))
    for f in result.findings:
        # Verifier: harvest in-scope hosts discovered during recon to feed the scan phase.
        host = f.evidence.get("host") if isinstance(f.evidence, dict) else None
        if host:
            ctx.discovered.add(host)
        elif phase == "recon" and f.affected_asset:
            ctx.discovered.add(f.affected_asset)
        ctx.emit(RunEvent("finding.created", phase, f.title,
                          {"severity": f.severity.value, "asset": f.affected_asset}))


def build_graph(ctx: _Ctx):
    def planner(_state: GraphState) -> GraphState:
        ctx.emit(RunEvent("phase.changed", "recon", "Recon phase"))
        tasks = [(c, d) for d in ctx.seed_domains for c in ctx.router.recon_caps()]
        ordered = ctx.router.order(tasks)
        return {"phase": "recon", "queue": [list(t) for t in ordered], "steps": 0}

    def execute(state: GraphState) -> GraphState:
        if not state["queue"]:
            return state
        cap, target = state["queue"][0]
        _run_one(ctx, state["phase"], cap, target)
        return {"phase": state["phase"], "queue": state["queue"][1:], "steps": state["steps"] + 1}

    def _phase_setup(phase: str, label: str, caps_fn):
        """Build a setup node: emit the phase change, then queue caps × discovered/seed hosts."""
        def setup(state: GraphState) -> GraphState:
            ctx.emit(RunEvent("phase.changed", phase, label))
            hosts = sorted(set(ctx.discovered) | set(ctx.seed_hosts))
            tasks = [(c, h) for h in hosts for c in caps_fn()]
            q = [list(t) for t in ctx.router.order(tasks)]
            return {"phase": phase, "queue": q, "steps": state["steps"]}
        return setup

    scan_setup = _phase_setup("scan", "Scan phase", ctx.router.scan_caps)
    enum_setup = _phase_setup("enum", "Enum phase", ctx.router.enum_caps)
    verify_setup = _phase_setup("verify", "Verify phase", ctx.router.verify_caps)

    def route(state: GraphState) -> str:
        if state["queue"]:
            return "continue"
        if state["phase"] == "recon":
            return "scan"
        if state["phase"] == "scan":
            return "enum"
        if state["phase"] == "enum":
            return "verify"
        return "done"

    g = StateGraph(GraphState)
    g.add_node("planner", planner)
    g.add_node("execute", execute)
    g.add_node("scan_setup", scan_setup)
    g.add_node("enum_setup", enum_setup)
    g.add_node("verify_setup", verify_setup)
    g.add_edge(START, "planner")
    g.add_edge("planner", "execute")
    g.add_conditional_edges("execute", route,
                            {"continue": "execute", "scan": "scan_setup",
                             "enum": "enum_setup", "verify": "verify_setup", "done": END})
    g.add_edge("scan_setup", "execute")
    g.add_edge("enum_setup", "execute")
    g.add_edge("verify_setup", "execute")
    return g.compile()


class LangGraphEngagementRunner:
    """Drop-in engine using a LangGraph state machine. Same API as SimpleEngagementRunner."""

    def __init__(self, executor: CapabilityExecutor, *, router: Optional[ModelRouter] = None,
                 on_event: Optional[Callable[[RunEvent], None]] = None):
        self.executor = executor
        self.router = router or ModelRouter()
        self.on_event = on_event

    def run(self, engagement, *, seed_domains: list, seed_hosts: Optional[list] = None
            ) -> EngagementReport:
        ctx = _Ctx(executor=self.executor, engagement=engagement, router=self.router,
                   on_event=self.on_event, seed_domains=list(seed_domains),
                   seed_hosts=list(seed_hosts or []))
        app = build_graph(ctx)
        app.invoke({"phase": "", "queue": [], "steps": 0}, {"recursion_limit": 500})
        ctx.emit(RunEvent("phase.changed", "analyze", "Analyze phase"))
        enrich_findings(ctx.store)
        counts = ctx.store.counts()
        return EngagementReport(
            engagement_id=engagement.id, name=engagement.name, counts=counts,
            findings=ctx.store.all(), events=ctx.events, gated=ctx.gated,
            denied_targets=ctx.denied)
