# agent/ — LangGraph orchestrator (not yet built)

Phase 1+ (Epic D). Stateful graph: Planner → Skill-Retriever → Tool-Selector → Safety-Gate →
Executor → Verifier → Findings-Writer → Phase-Router. The Safety-Gate node calls
`api/hexacore/safety`. See `Brain/01-ARCHITECTURE.md §3.3` and `Brain/03-TASK-BREAKDOWN.md` Epic D.
