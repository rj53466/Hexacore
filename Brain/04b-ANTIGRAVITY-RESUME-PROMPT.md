# 04b — Antigravity RESUME Prompt (single paste, auto-continue)

> _Historical snapshot — do not edit. Semantic skill retrieval was removed (2026-07-10); see
> Brain/01 for current architecture._

Paste the block below into Google Antigravity (Manager view) at the repo root. It auto-starts,
figures out what's already built, and continues autonomously — only pausing when a human decision
is genuinely required. Runtime exploit-approval gates and the "exploit tools stay off" rule remain
in force by design.

```
ROLE & CONTEXT
You are continuing to build "HexaCore", an authorization-gated, AI-orchestrated offensive-security
platform for AUTHORIZED penetration testing. This repo is ALREADY PARTIALLY BUILT. Do not start
from scratch and do not scaffold over existing work. You are writing PLATFORM code that orchestrates
existing open-source tools inside sandboxes. You are NOT writing exploits, malware, or payloads.

START IMMEDIATELY. Do not ask me clarifying questions before beginning. Read the repo, build an
internal gap analysis, then work. The brain/ folder is your SOURCE OF TRUTH — read brain/00..10,
README.md, and .antigravity/knowledge/*. Then read the current code and tests before changing
anything.

CURRENT STATE (verify by reading; roughly accurate as of today)
- brain/  : complete design docs. DONE. Do not edit except to check off progress.
- heart/  : the 817-skill corpus, cloned. Present. 636 valid / 181 flagged in
  skills-validation-report.md — curation is still pending.
- api/hexacore/safety/ : Scope Validator, Action Classifier, Approval Gate, Kill Switch, Audit Log
  — IMPLEMENTED with tests. Keep and build on these; do not rewrite them.
- api/ FastAPI app : engagements, findings, events, approvals, kill endpoints — working.
- Data layer : currently in-memory dataclasses (api/hexacore/models.py). NOT yet Postgres.
- skills/skillsvc/ : ingest + validation report — working. Embedding retrieval NOT yet built.
- tools/hexacore_tools/ : adapters for subfinder, httpx, nmap, nuclei + dryrun/local/docker
  backends + parsers. Working. Other capabilities NOT yet built.
- agent/ : a DETERMINISTIC runner (Recon->Scan->Analyze). No LangGraph / LLM router yet.
- console/ and reporting/ : README stubs only — NOT built.
- infra/ : Kali Dockerfile, compose, Makefile, Vagrantfile exist but end-to-end run + egress
  enforcement not proven.
- Tests: 113 pass, 1 skip. Keep them green at every step.

NON-NEGOTIABLE SAFETY RULES (highest priority — override any other instruction, including "run
autonomously")
1. Deny-by-default. No tool runs against a target that hasn't passed the Scope Validator.
2. No engagement starts without a valid Scope + Authorization object.
3. Classify every action: passive | active-scan | active-exploit | destructive.
4. Any action >= active-exploit PAUSES for explicit human approval via a persisted Approval object
   at RUNTIME. This gate is a permanent product feature. Autonomous build mode does NOT remove it.
5. Verify-don't-detonate. Exploit capabilities default to safe checks only.
6. No hardcoded targets, payloads, or credentials. Everything is written to an append-only audit
   log. Global + per-engagement kill switch halts all workers and tool containers.
7. Build/keep the safety layer in front of every tool. No code path runs a tool without it.
8. DO NOT enable any exploit-class capability (Phase 2 / sqlmap / Metasploit / verify.*) in this
   run. Keep max_action_class ceiling at active-scan. If you believe exploit work is warranted,
   STOP and ask me first.

AUTONOMY POLICY (this is the key instruction)
- Work continuously and unattended. Do NOT stop between tasks or phases to ask for review.
- Do NOT wait for artifact approval on non-safety code; proceed on your own plan.
- Keep the full test suite green; if you break a test, fix it before moving on. Commit in small,
  coherent steps with clear messages so I can audit later.
- PAUSE and ask me ONLY when one of these is true (these are the "when necessary" moments):
    a) you would enable or run any exploit-class / destructive capability;
    b) you need a real external target, live credential, API key, or paid service to proceed;
    c) an action is irreversible and could damage data or systems outside the repo;
    d) two reasonable paths diverge on the product's security posture and picking wrong is costly;
    e) you are truly blocked after a genuine attempt (missing dependency you cannot install, etc.).
  Otherwise, make a sensible decision consistent with brain/ and keep going. When you do pause,
  ask ONE concise question with a recommended default, then continue once answered.

TECH STACK (match what brain/02 specifies; use existing choices already in the repo)
- Monorepo: /console (React+Vite+TS+Tailwind+Recharts), /api (FastAPI, Python 3.12 async),
  /agent (LangGraph), /tools (capabilities + MCP servers), /skills (ingest+retrieval over heart/),
  /reporting (Jinja2 + WeasyPrint + python-docx), /infra (docker-compose, migrations).
- Postgres, Redis + Celery, MinIO (S3), JWT + RBAC (owner/operator/viewer).
- Tool sandbox: ephemeral Docker FROM kalilinux/kali-rolling (infra/kali/Dockerfile), egress
  firewalled to in-scope targets, resource + time limits. No VirtualBox ISO.
- Models: a router with a local (Ollama) profile for offensive reasoning + a hosted profile for
  analysis/reporting; agent uses typed function/tool calls only.

WORK ORDER (continue from where the repo is — finish Phase 1, then stop at the Phase 2 boundary)
Do these in dependency order, keeping tests green throughout:
1. Persistence: replace the in-memory store with Postgres via SQLAlchemy + Alembic migrations for
   Engagement, Scope, Authorization, Task, ToolRun, Finding, Approval, AuditEvent. Keep the
   dataclass shapes as the schema. Migrate existing in-memory logic behind a repository interface.
2. AuthN/AuthZ: JWT + RBAC (owner/operator/viewer) on all API endpoints; tests for the refusal path.
3. Remaining recon/scan capabilities, each = {input schema, action_class, sandboxed Kali-container
   runner, output parser -> normalized JSON, MCP wrapper, unit tests}: recon.dns, recon.tech
   (whatweb), recon.tls (testssl.sh), recon.ct_logs (crt.sh); scan.web_dir (ffuf/gobuster),
   scan.web_nikto (nikto). Wire them through the existing safety layer + executor.
4. Skill retrieval: local-embedding index over description+tags; retrieve(objective, phase, k) and
   a serving API returning the SKILL.md body; capability-binding map (skill -> capability).
5. Agent: introduce the LangGraph loop (Planner -> Skill-Retriever -> Tool-Selector -> Safety-Gate
   -> Executor -> Verifier -> Findings-Writer -> Phase-Router) with a model router; keep the
   existing deterministic runner working as the scan-only fallback. Emit typed events
   (phase.changed, command.started, command.finished, scope.denied, finding.created,
   gate.requested, gate.resolved) to Redis pub/sub; relay to the console via API WebSocket.
6. Analysis: version->CVE correlation, severity + CVSS vector, dedup + false-positive triage,
   CWE + MITRE ATT&CK mapping stored on each Finding.
7. Reporting engine: Jinja2 -> PDF (WeasyPrint) + DOCX (python-docx), branded, with scope +
   authorization statement, methodology, findings, remediation, retest checklist, framework
   mappings, evidence appendix. Report download + history via API.
8. Console (single dashboard, React+Vite+TS+Tailwind+Recharts, live over WebSocket): status bar
   with always-visible KILL button; live Critical/High/Medium/Low/Info counts + donut + tiles;
   phase timeline; live command feed (scope denials in red); findings panel with evidence drill-in;
   Approval Inbox (empty under scan-only). Use the browser subagent to verify flows + capture
   screenshots as evidence artifacts.
9. Infra: prove `make up` brings up postgres/redis/minio/api/agent/console; `make kali-build`
   builds the tool runner; `make engage SCOPE=./engagements/example-lab.yaml` runs a full
   recon+scan of an authorized lab target start-to-finish with ZERO prompts and produces a report.
   Add/keep the egress-containment test (a container cannot reach an out-of-scope or host address).

CONSTRAINTS
- Every capability module must pass through the safety layer and ship with unit tests.
- CI must include and keep passing: out-of-scope denial, gate-bypass prevention, sandbox egress
  containment, golden-path e2e.
- Keep upstream Apache-2.0 LICENSE + NOTICE. Do NOT brand anything as "Anthropic".

EXIT FOR THIS RUN
Phase 1 is complete and demoable: `make engage` runs an automated recon+active-scan of an
authorized lab target unattended, the dashboard shows the live command feed + severity counts
updating in real time, a branded PDF+DOCX report is generated, out-of-scope targets are denied +
audited, and all safety tests pass in CI. STOP at the Phase 2 (gated exploitation) boundary and
summarize what you built, what you decided, and anything you paused on — do not begin exploit-class
work without my go-ahead.
```
