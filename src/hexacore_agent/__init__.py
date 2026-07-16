"""HexaCore orchestrator (agent/).

Two interchangeable engines, both driving capabilities through `CapabilityExecutor` + the safety
layer:
- `SimpleEngagementRunner` — deterministic recon->scan->analyze loop (scan-only fallback).
- `LangGraphEngagementRunner` — the LangGraph state machine (planner->execute->scan_setup/
  verify_setup) with a `ModelRouter` (deterministic by default; `local`/`ollama` reprioritises the
  task queue via a local Ollama model).
"""
from .runner import EngagementReport, RunEvent, SimpleEngagementRunner

__all__ = ["SimpleEngagementRunner", "EngagementReport", "RunEvent",
           "LangGraphEngagementRunner", "ModelRouter"]


def __getattr__(name: str):
    # Lazy import so `langgraph` is only required when the graph engine is actually used.
    if name in ("LangGraphEngagementRunner", "ModelRouter"):
        from . import graph
        return getattr(graph, name)
    raise AttributeError(name)
