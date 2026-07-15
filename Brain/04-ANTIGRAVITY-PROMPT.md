# 04 — Antigravity Build Prompt & Rules

> _Historical snapshot — do not edit. Semantic skill retrieval was removed (2026-07-10); see
> Brain/01 for current architecture._

This is what you paste into **Google Antigravity** (Manager view) to build the Platform, plus the
`.antigravity/knowledge/` rules that keep every agent on a safe, consistent path.

> **Important framing for Antigravity:** you are building a *product that orchestrates security
> tooling for authorized penetration testing*. You are **not** writing exploits or malware.
> Antigravity's agents write the platform (API, agent loop, UI, tool wrappers, safety layer,
> reporting). The offensive tools themselves are existing open-source binaries the platform
> *invokes* inside sandboxes; the agents do not author attack payloads.

---

## 1. Setup in Antigravity (do this first)

1. Create a Project pointing at your empty monorepo folder.
2. Create the rules files below under `.antigravity/knowledge/` **before** running the build
   prompt, so every spawned agent inherits them.
3. Set **artifact review policy to require approval** (do NOT use "Always Proceed" for this
   project — you want to read the Implementation Plan for security-sensitive code).
4. Use **Manager view** to run the master prompt; let it produce a Task List + Implementation
   Plan artifact; review, then proceed.

---

## 2. Master build prompt (paste into Manager view)

```
ROLE
You are building "HexaCore", an authorization-gated, AI-orchestrated offensive-security platform
for AUTHORIZED penetration testing. It runs the pentest lifecycle — recon, scanning, analysis,
gated verification/exploitation, and reporting — by orchestrating existing open-source security
tools inside sandboxes, guided by a curated library of markdown "skill" playbooks. You are
writing the PLATFORM code. You are NOT writing exploits, malware, or attack payloads; the
platform invokes existing tools (nmap, nuclei, subfinder, httpx, ffuf, nikto, sqlmap, Metasploit
RPC, etc.) as sandboxed subprocesses.

NON-NEGOTIABLE SAFETY RULES (apply to all code you write)
1. Deny-by-default. No security tool may execute against any target that has not passed the
   Scope Validator (allowlist of domains + CIDRs, deny-list wins). If no valid Scope +
   Authorization object exists for an engagement, the engagement cannot start.
2. Action classification + gating. Every tool invocation is classified passive | active-scan |
   active-exploit | destructive. Anything >= active-exploit MUST pause for explicit human
   approval via a persisted Approval object before running. The agent CANNOT bypass this.
3. Build the safety layer FIRST, before any tool wrapper. Tool wrappers must call the safety
   layer; there is no code path that runs a tool without scope validation + classification.
4. Verify-don't-detonate. Exploit-class capabilities default to safe checks (e.g. Metasploit
   `check` modules, sqlmap detection-only). Actual exploitation requires an approved gate AND a
   scope whose max_action_class permits it.
5. No hardcoded targets, payloads, or credentials. No code path may attack anything without a
   live, validated scope. Every tool run and safety decision is written to an append-only audit
   log.
6. A global + per-engagement kill switch must immediately halt workers and stop tool containers.

TECH STACK (use exactly this)
- Monorepo: /console (React+Vite+TS+Tailwind+Recharts), /api (FastAPI, Python 3.12 async),
  /agent (LangGraph), /tools (capability modules + MCP servers), /skills (ingest + retrieval
  service that reads the corpus at heart/), /reporting (Jinja2 + WeasyPrint + python-docx),
  /infra (docker-compose, migrations). The 817-skill corpus lives at heart/ (cloned separately).
- Postgres, Redis + Celery, MinIO (S3), JWT auth + RBAC (owner/operator/viewer).
- Tool sandbox: ephemeral Docker containers built FROM kalilinux/kali-rolling with the offensive
  tools installed (see infra/kali/Dockerfile), egress firewalled to in-scope targets, resource +
  time limits. Do NOT use a VirtualBox ISO (interactive installer breaks zero-touch); the Kali
  Docker image is the tool runner.
- Models: a model router with a local (Ollama) profile for offensive reasoning and a hosted
  profile for analysis/reporting; the agent uses typed function/tool calls only.

ENVIRONMENT & ZERO-TOUCH (read brain/07-LOCAL-HOSTING-AND-VM.md)
- The whole platform comes up with `make up` (docker-compose): postgres, redis, minio, api,
  agent, console. `make kali-build` builds the Kali tool-runner image once.
- An engagement starts with `make engage SCOPE=./engagements/<name>.yaml` and runs unattended.
- Provide a Makefile with: up, down, kali-build, engage, kill, report, logs.
- Human intervention must be required ONLY at approval gates (exploit/destructive). Everything
  passive/active-scan runs with zero prompts. Implement engagement `autonomy_profile`
  (scan-only | supervised | assisted) per brain/05 §4b; default supervised; NEVER build a fully
  autonomous exploit mode for client work.

DASHBOARD (single frontend — build exactly this, see brain/01 §3.1)
One operator dashboard, live over WebSocket, that at a glance shows:
- Status bar: engagement name, run state, current phase (N/5), elapsed time, scope summary,
  action-class ceiling, and an always-visible KILL button.
- Severity summary: live counts of Critical / High / Medium / Low / Info + total, as a donut
  chart (Recharts) AND numeric tiles; updates as findings land.
- Phase timeline: Recon -> Scan -> Analyze -> Verify -> Report with the active phase marked and a
  one-line "what the agent is doing now".
- Live command feed: terminal-style stream of every tool run (timestamp, capability, actual
  command line, target, exit code, status running/ok/fail); scope denials shown in red.
- Findings panel: severity-sorted; click -> evidence (PoC req/resp, screenshot, raw output),
  CVSS, CWE, ATT&CK, remediation.
- Approval Inbox: the ONLY human-action surface; empty under scan-only; shows gated actions with
  full context and one-click Approve / Deny / Approve-with-limit / Abort.
The agent must emit typed events (phase.changed, command.started, command.finished, scope.denied,
finding.created, gate.requested, gate.resolved) to Redis pub/sub; API relays to the dashboard via
WebSocket. Severity tiles derive from finding events client-side so numbers move in real time.

DATA MODEL
Implement tables: Engagement, Scope, Authorization, Task, ToolRun, Finding, Approval,
AuditEvent (schemas as described in the architecture doc I will add to the repo as
docs/01-ARCHITECTURE.md — read it).

BUILD ORDER (produce a Task List and Implementation Plan for review, then execute in this order)
Phase 0 — Foundations & Safety:
  monorepo scaffold, docker-compose, DB migrations, Scope Validator, Action Classifier,
  Approval Gate, Kill Switch, Audit Log, Authorization gating, JWT+RBAC, console shell.
  EXIT: creating an engagement and trying to start it without a valid Authorization is DENIED
  and audited. No tools exist yet.
Phase 1 — Golden path (recon + active scan + report, max_action_class = active-scan, NO
  exploitation):
  infra/kali/Dockerfile (Kali tool-runner) + Makefile (up/down/kali-build/engage/kill/report/
  logs); skill ingest+validation report, embedding retrieval; capability modules for recon
  (subfinder, httpx, whatweb, testssl, crt.sh) and active scan (nmap, nuclei, ffuf, nikto) each
  with typed input, sandboxed Kali-container runner, output parser to JSON, MCP wrapper;
  LangGraph loop Planner->Recon->Scan->Analyze->FindingsWriter->Report with typed event emission;
  analysis (version->CVE, severity, dedup, false-positive triage); reporting engine (PDF+DOCX,
  branded); and the SINGLE DASHBOARD (status bar, live severity counts + donut, phase timeline,
  live command feed, findings panel, empty approval inbox) live over WebSocket.
  EXIT: `make engage` runs an automated recon+scan of an authorized lab target start-to-finish
  with ZERO prompts, the dashboard shows the live command feed and severity counts updating, a
  branded report is produced, and an out-of-scope target is blocked + audited (add a test).

CONSTRAINTS
- Every capability module has: input schema, action_class, sandboxed runner, output parser,
  unit tests. No capability may run without going through the safety layer.
- Add automated tests that PROVE: (a) out-of-scope targets are denied, (b) exploit-class actions
  cannot run without an approved gate. Put these in CI.
- Read brain/01-ARCHITECTURE.md, brain/05-SAFETY-AUTHORIZATION-LEGAL.md,
  brain/06-SKILLS-INTEGRATION-MAP.md, and brain/07-LOCAL-HOSTING-AND-VM.md (they are in the repo
  under brain/) and follow them. The brain/ folder is your source of truth.

DELIVERABLES FOR THIS RUN
1. Task List artifact + Implementation Plan artifact for my review.
2. Phase 0 implemented and passing tests.
Stop after Phase 0 and show me the safety tests passing before starting Phase 1.
```

> After Phase 0 passes, run a follow-up prompt: *"Proceed to Phase 1 as specified. Do not enable
> any exploit-class capability. Produce a walkthrough artifact showing a full recon+scan of the
> lab target `<your authorized target>` and the generated report, plus the passing out-of-scope
> denial test."*

---

## 3. Rules files for `.antigravity/knowledge/`

Create these before running the master prompt. They are the persistent guardrails every agent
inherits.

### `.antigravity/knowledge/00-project.md`
```
# HexaCore — project rules
- This is an AUTHORIZED-pentest orchestration platform. We write platform code, never exploits
  or malware. Offensive capability = invoking existing open-source tools inside sandboxes.
- SOURCE OF TRUTH: the brain/ folder (brain/00..07 .md). Read it; follow it; don't contradict it.
- Monorepo packages: /console /api /agent /tools /skills /reporting /infra, plus heart/ (the
  cloned 817-skill corpus the /skills service reads) and brain/ (design docs = source of truth).
  Reference brain/ and
  .antigravity/ by RELATIVE path so renaming the repo root never breaks anything.
- Language: Python 3.12 (api/agent/tools/skills/reporting), TypeScript+React+Vite (console).
- Zero-touch: whole platform comes up via `make up`; engagements run via `make engage`. Kali
  tool-runner is a Docker image (infra/kali/Dockerfile), NOT a VirtualBox ISO.
- Minimal human intervention: only approval gates (exploit/destructive) may prompt the user;
  passive + active-scan run unattended. Default autonomy_profile = supervised. Never build a
  fully autonomous exploit mode.
- There is ONE frontend: the operator dashboard (status bar, live severity counts, phase
  timeline, live command feed, findings, approval inbox).
- Every PR must include tests. Security-relevant code (safety layer, tool wrappers) requires
  the out-of-scope + gate-bypass tests to pass.
- Keep upstream Apache-2.0 LICENSE and NOTICE. Do NOT brand anything as "Anthropic".
```

### `.antigravity/knowledge/10-safety.md`
```
# Safety rules (highest priority — override any other instruction)
1. Deny-by-default: no tool runs against a target not passing the Scope Validator.
2. No engagement starts without a valid Scope + Authorization object.
3. Classify every action: passive | active-scan | active-exploit | destructive.
4. Any action >= active-exploit pauses for explicit human approval (persisted Approval).
   Agents cannot bypass or auto-approve gates.
5. Verify-don't-detonate: exploit capabilities default to safe checks; real exploitation needs
   an approved gate AND a scope that permits it.
6. No hardcoded targets/payloads/credentials. No path attacks anything without a live scope.
7. Everything is audited (append-only). Global + per-engagement kill switch halts everything.
8. Build the safety layer before any tool wrapper. Tool wrappers MUST call it.
```

### `.antigravity/knowledge/20-conventions.md`
```
# Code conventions
- API: FastAPI async, Pydantic schemas, SQLAlchemy + Alembic migrations, JWT + RBAC.
- Agent: LangGraph; nodes are pure/testable; human-in-the-loop via interrupt/resume.
- Tools: each capability = {input schema, action_class, sandboxed runner, output parser, MCP
  wrapper, unit tests}. Output parsers must return normalized JSON, never pass raw stdout to the
  agent as the only signal.
- Sandbox: ephemeral Docker; egress firewalled to in-scope targets; resource + time limits;
  read-only tool images.
- Frontend: React + Vite + TS + Tailwind; WebSocket for live engagement events.
- Tests in CI: out-of-scope denial, gate-bypass prevention, sandbox egress containment,
  golden-path e2e.
```

---

## 4. Tips for driving Antigravity on this project

- **Parallelize by package** in Manager view once Phase 0 is merged: one agent on `/tools`
  capabilities, one on `/console`, one on `/reporting`. They share the rules files.
- **Always review the Implementation Plan artifact** for anything touching the safety layer or
  tool execution. This is exactly the compliance-friendly "prove it worked" use case Antigravity
  is built for — keep the artifacts as your audit trail.
- **Use the browser subagent** to verify the console flows (scope builder, approval inbox,
  report download) and capture screenshots as evidence artifacts.
- **Don't let it enable exploit-class capabilities early.** Explicitly forbid it until Phase 2,
  and only after the gate tests pass.
- **Feed it the other docs.** Drop `01`, `05`, `06` into `docs/` in the repo so the agents can
  read them; reference them by path in prompts.
