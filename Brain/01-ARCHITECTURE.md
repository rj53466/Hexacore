# 01 — System Architecture

Codename **HexaCore** · AI-orchestrated, authorization-gated offensive-security platform.
Lifecycle covered: **Recon → Scanning → Analysis → Verification/Exploitation → Reporting.**

> **Spec–code parity rule (binding).** Every node, backend, model profile, or capability
> advertised in a docstring, README, or Brain spec MUST exist in code, and vice versa. Do not
> advertise unimplemented seams as "designed features." When a feature is deleted, delete its
> spec/docstring references in the *same* change. A phantom advertisement is a bug.

---

## 1. Design principles

1. **Skills are the brain, tools are the hands, scope is the conscience.** Never conflate them.
2. **Deny by default.** Every tool call is validated against an engagement scope allowlist before
   it runs. No scope object → nothing runs.
3. **Safety is a layer, not a feature flag.** Action classification and approval gates are
   architectural, cross-cutting, and cannot be bypassed by the agent.
4. **Everything is evidence.** Every tool run, decision, and finding is logged, timestamped,
   and attributable — for the client report *and* for your own legal protection.
5. **Model optionality.** The reasoning model is swappable via a local Ollama endpoint. The agent
   *selects and parameterizes typed tool capabilities*; it does not author raw exploit code.
6. **Progressive disclosure.** Scan 817 skill frontmatters cheaply (~30 tokens each), load only
   the 1–3 relevant full playbooks per step. Never dump the whole corpus into context.

---

## 2. High-level component diagram

```
                          ┌─────────────────────────────────────────────┐
                          │                 CONSOLE (React/Vite)         │
                          │  Scope builder · Engagement dashboard ·      │
                          │  Live activity · Approval gates · Findings · │
                          │  Report download                             │
                          └───────────────────────┬─────────────────────┘
                                                   │ REST / WebSocket
                          ┌───────────────────────▼─────────────────────┐
                          │              API / ORCHESTRATION (FastAPI)   │
                          │  Engagement lifecycle · AuthN/AuthZ (RBAC) · │
                          │  Job queue · WebSocket event stream          │
                          └───────┬───────────────────────────┬─────────┘
                                  │                           │
              ┌───────────────────▼──────────┐   ┌────────────▼───────────────────┐
              │      AGENT ORCHESTRATOR       │   │      SAFETY / AUTHZ LAYER       │
              │  (LangGraph state machine)    │◄─►│  (cross-cutting, in-path)       │
              │  planner → execute →          │   │  Scope validator · Action       │
              │  scan_setup / verify_setup    │   │  classifier · Approval gate ·   │
              │  gate+parse inside executor   │   │  Kill switch · Audit log        │
              └───┬───────────────┬───────────┘   └─────────────────────────────────┘
                  │               │
      ┌───────────▼──────┐  ┌─────▼────────────────────────────┐
      │  SKILL KNOWLEDGE │  │        TOOL EXECUTION LAYER        │
      │     SERVICE       │  │   (sandboxed capability runners)  │
      │  ingest +         │  │  Recon · Scan · WebApp · Cloud ·  │
      │  validation       │  │  AD/Identity · Exploit(gated) ·   │
      │  → JSON index of  │  │  Post-ex(gated)                   │
      │  valid skills     │  │  Each = Docker + MCP/subprocess   │
      └───────────────────┘  └───────────────┬──────────────────┘
                                              │ structured JSON output
                          ┌───────────────────▼─────────────────┐
                          │   EVIDENCE & FINDINGS STORE          │
                          │  Postgres (findings, engagements) +  │
                          │  MinIO/S3 (raw output, screenshots,  │
                          │  PoC, pcaps) — EU-hostable           │
                          └───────────────────┬─────────────────┘
                                              │
                          ┌───────────────────▼─────────────────┐
                          │        REPORTING ENGINE              │
                          │  Jinja2 templates → PDF/DOCX/HTML ·  │
                          │  CVSS · CWE · ATT&CK · remediation   │
                          └──────────────────────────────────────┘
```

---

## 3. Components in detail

### 3.1 Console (frontend) — the single dashboard

**Yes, there is one web frontend** — a single-pane operator dashboard. Stack: React + Vite +
TypeScript + Tailwind (your existing stack), Recharts for charts, WebSocket for live data.

The dashboard is what you watch while the agent works largely unattended. It has to answer, at a
glance: *what phase are we in, what command is running right now, what have we found, and how bad
is it.* Layout:

```
┌───────────────────────────────────────────────────────────────────────────┐
│  ENGAGEMENT: acme-staging   ● RUNNING   Phase 3/5: SCANNING   ⏱ 00:14:22    │  ← status bar
│  Scope: *.acme-staging.com, 10.20.30.0/24   Ceiling: active-scan  [KILL ■]  │
├──────────────────────────────┬────────────────────────────────────────────┤
│  SEVERITY SUMMARY            │   PHASE TIMELINE                            │
│  ┌──────┐  Critical   2      │   ✔ Recon      ✔ Scan(▸)  ○ Analyze         │
│  │donut │  High       5      │   ○ Verify     ○ Report                     │
│  └──────┘  Medium     11     │                                            │
│    Total   Low        8      │   AGENT STATUS: running nuclei on           │
│     34     Info       8      │   portal.acme-staging.com                   │
├──────────────────────────────┴────────────────────────────────────────────┤
│  LIVE COMMAND FEED (streaming)                                             │
│  12:04:19  scan.ports      nmap -sV -sS -Pn 10.20.30.11        exit 0  ✔   │
│  12:04:47  scan.web_nuclei nuclei -u https://portal... -severity ...  ▸    │
│  12:05:02  [SCOPE-DENY]     ffuf → prod.acme.com  BLOCKED (out of scope) ✖ │
├───────────────────────────────────────────────────────────────────────────┤
│  FINDINGS (live, severity-sorted)      │   APPROVAL INBOX (0 pending)      │
│  🔴 SQLi param `id` — portal /search   │   (empty — nothing needs you)     │
│  🟠 Outdated OpenSSH 7.2 — 10.20.30.11 │                                   │
│  ...                                    │                                   │
└───────────────────────────────────────────────────────────────────────────┘
```

**Widgets (all live via WebSocket):**
- **Status bar** — engagement name, run state, current phase (N/5), elapsed time, scope summary,
  action-class ceiling, and a always-visible **KILL** button.
- **Severity summary** — the counts you asked for: **Critical / High / Medium / Low / Info** +
  total, shown as a donut chart *and* numeric tiles. Updates as findings land.
- **Phase timeline** — Recon → Scan → Analyze → Verify → Report, with the active phase marked and
  a one-line "what the agent is doing right now."
- **Live command feed** — a terminal-style stream of every tool invocation: timestamp,
  capability, the actual command line, target, exit code, and status (running ▸ / ok ✔ / fail ✖).
  Scope denials show up here in red so you can *see* the guardrail working.
- **Findings panel** — severity-sorted list; click a finding → evidence (PoC req/resp,
  screenshot, raw output), CVSS, CWE, ATT&CK, remediation.
- **Approval inbox** — the **only** place you're asked to act. Empty most of the time (passive +
  active-scan run unattended). When the agent wants an exploit/destructive action it appears here
  with full context (target, capability, skill, expected impact, evidence-so-far) and one-click
  **Approve / Deny / Approve-with-limit / Abort**.

**Other screens:** Engagement list/history · Scope Builder (domains/CIDRs/deny, RoE, window,
ceiling) · Authorization upload/click-sign · Report preview & download.

**Data plumbing for the live view:** the agent orchestrator emits typed events
(`phase.changed`, `command.started`, `command.finished`, `scope.denied`, `finding.created`,
`gate.requested`, `gate.resolved`) onto Redis pub/sub → API relays over WebSocket → dashboard.
The severity counters are derived client-side from `finding.created`/`finding.updated` events, so
the numbers move in real time as the scan progresses.

### 3.2 API / Orchestration (backend)
- **Stack:** Python **FastAPI** (async), Postgres, Redis (queue + pub/sub), Celery or RQ workers.
  *Why Python:* the entire offensive-tooling + agent ecosystem is Python-native; one language
  for backend + agent + tool wrappers reduces friction.
- **Responsibilities:** engagement CRUD; user auth (JWT) + RBAC (owner / operator / viewer);
  enqueue engagement runs; stream events to console; enforce that no engagement transitions to
  `running` without a valid `Authorization` + `Scope`.

### 3.3 Agent Orchestrator (the runtime brain)
- **Framework:** **LangGraph** — a stateful graph is the right shape because the lifecycle has
  explicit phases, conditional branches, and human-in-the-loop interrupts (gates).
- **Graph nodes (as built):** the implemented LangGraph (`agent/hexacore_agent/graph.py`) has
  **four** nodes — `planner` → `execute` → `scan_setup` / `verify_setup` (loop back to `execute`).
  `execute` runs one queued capability per step through CapabilityExecutor (safety layer first);
  the setup nodes build the next phase's queue. Safety classification/gating, output parsing, and
  finding normalization happen *inside* CapabilityExecutor + the stores — not as separate graph
  nodes. The originally-envisioned Skill-Retriever / Tool-Selector / Verifier / Findings-Writer
  nodes were **not built** as nodes; the retriever in particular is **deleted, not deferred** (see
  §3.4). This list reflects the real graph per the Spec–code parity rule above.
- **Model router (as built):** `ModelRouter` (`agent/hexacore_agent/graph.py`) has two profiles —
  `deterministic` (fixed phase plan, FIFO, no model) and `local`/`ollama` (a local Ollama model
  reprioritises the task queue; permutation-only, falls back to FIFO on any error). No hosted-model
  path exists. The agent calls **functions/tools**, never emits raw payloads.
- **State:** persisted per engagement so a run can pause at a gate for hours and resume.

### 3.4 Skill Knowledge Service
- **Ingest + validate (BUILT):** load the corpus at `heart/skills/**/SKILL.md`; parse frontmatter;
  **validate & normalize** (flag malformed descriptions like the leaked `">-"`, truncated
  descriptions, missing fields, folder/name mismatch, duplicate names); emit a validation report +
  a compact JSON index of the valid skills. This is all `skills/skillsvc/ingest.py`.
- **Semantic retrieval — DELETED (2026-07-10), not deferred.** The embedding/RAG pipeline
  (sentence-transformers, cosine-similarity retriever, `.npy`/index artifacts) was built but never
  wired into the agent flow — nothing consumed it. It has been removed. If skill-context lookup is
  ever actually needed, add it then as a *fresh* item (a keyword/substring match over the JSON
  index is a few lines — do NOT reintroduce the torch pipeline). Serving/progressive-disclosure was
  never built either.
- **Curation layer:** an overlay file (`skill-overrides.yaml`) where *you* correct tool flags,
  add capability bindings, or disable a skill. Your overrides win over upstream content.

### 3.5 Tool Execution Layer (the hands)
- **Model:** each tool group is a **capability module** with a typed input schema, a sandboxed
  runner, and an **output parser** that returns structured JSON (never raw text to the agent
  as the sole signal).
- **Sandbox:** each capability runs in an ephemeral Docker container (or gVisor/Firecracker
  for stronger isolation later) with: no host network mount, egress restricted to the
  in-scope targets, CPU/mem/time limits, and read-only tool images.
- **Exposure to agent:** wrap capabilities as **MCP servers** (clean, model-agnostic, matches
  the agent ecosystem) *or* as direct typed function tools. MCP is preferred for portability.
- **Capability groups (MVP → later):**

  | Group | MVP tools | Class | Later |
  |---|---|---|---|
  | Recon (passive) | subfinder, amass (passive), crt.sh, httpx, whois/DNS | `passive` | SpiderFoot, theHarvester |
  | Recon (active) | nmap (SYN/service/scripts), masscan | `active-scan` | — |
  | Web scanning | nuclei, Nikto, ffuf/gobuster, whatweb, zap-baseline | `active-scan` | ZAP full, arjun |
  | Vuln analysis | nuclei templates, version→CVE lookup, testssl.sh | `active-scan` | Nessus/InsightVM connectors |
  | Web exploit (gated) | sqlmap (`--batch`, read-only first), SSRF/IDOR verifiers | `active-exploit` | authenticated flows |
  | Network exploit (gated) | Metasploit RPC (*check* modules first) | `active-exploit`/`destructive` | full exploitation |
  | AD / Identity (gated) | BloodHound-CE collectors, Certipy (find), NetExec (enum) | `active-scan`→`exploit` | Kerberoast, relay |
  | Cloud (gated) | ScoutSuite, CloudFox (read), Pacu (dry) | `active-scan`→`exploit` | full Pacu modules |

- **"Verify-don't-detonate" rule:** for any exploit-class capability, the default first action is
  a **safe check** (e.g. Metasploit `check`, sqlmap detection-only, ADCS `find` not `abuse`).
  Actual exploitation requires an approved gate *and* a scope that explicitly permits it.

### 3.6 Evidence & Findings Store
- **Postgres:** engagements, scopes, authorizations, tasks, tool-runs, findings, approvals,
  audit log.
- **Object store (MinIO / S3, EU-hostable):** raw tool stdout/stderr, parsed JSON, screenshots,
  PoC request/response pairs, pcaps, BloodHound zips. Referenced by findings.
- **Immutability:** audit log and raw evidence are append-only / write-once where possible.

### 3.7 Reporting Engine
- **Input:** normalized findings + engagement metadata + scope + timeline.
- **Templates:** Jinja2 → HTML → PDF (WeasyPrint) and DOCX (python-docx) — reuse the report
  templates that ship in relevant skills' `assets/`.
- **Sections:** Executive summary · Scope & authorization statement · Methodology (phases run) ·
  Findings (severity, CVSS vector, affected assets, evidence, ATT&CK/CWE, remediation) ·
  Retest checklist · Appendices (tool versions, raw evidence index).
- **Client-facing polish:** your existing brochure/branding pipeline plugs in here (Sahasrakshi
  branding, cover page, logo).

### 3.8 Safety / Authorization Layer (cross-cutting)
Fully specified in **doc `05`**. In-path components:
- **Scope Validator** — resolves a target (host/URL/IP) and returns allow/deny against the
  engagement allowlist (domain suffixes + CIDR ranges); wildcard and out-of-scope guards.
- **Action Classifier** — labels every intended action `passive | active-scan | active-exploit
  | destructive` from the capability + parameters.
- **Approval Gate** — interrupts the LangGraph run for human decision on `active-exploit`+.
- **Kill Switch** — global + per-engagement; immediately halts workers and containers.
- **Audit Log** — who/what/when/against-what/result, for every action and decision.

---

## 4. Core data model (essential tables)

```
Engagement
  id, name, client, status[draft|scoped|running|paused|reporting|done|aborted],
  created_by, created_at, model_profile

Scope
  id, engagement_id,
  allow_domains[],          -- e.g. ["*.acme-test.com"]
  allow_cidrs[],            -- e.g. ["10.20.0.0/24"]
  deny_list[],              -- explicit exclusions (always win)
  max_action_class,         -- passive | active-scan | active-exploit | destructive
  rules_of_engagement,      -- text: windows, rate limits, off-limits actions
  window_start, window_end  -- allowed testing window

Authorization
  id, engagement_id,
  authorizer_name, authorizer_email, signed_at,
  document_ref (object-store key of signed permission),
  method[click-sign|uploaded-doc|contract-ref], verified_by

Task            -- one lifecycle step
  id, engagement_id, phase[recon|scan|analyze|verify|exploit|report],
  objective, status, skill_refs[], started_at, ended_at

ToolRun
  id, task_id, capability, target, params, action_class,
  gate_status[not-required|pending|approved|denied],
  started_at, ended_at, exit_code, raw_evidence_ref, parsed_output_ref

Finding
  id, engagement_id, title, severity, cvss_vector, cwe, cve[],
  attack_techniques[], affected_assets[], evidence_refs[],
  status[open|confirmed|false-positive|fixed], remediation

Approval
  id, tool_run_id, requested_at, decided_at, decided_by, decision, limits

AuditEvent
  id, engagement_id, actor[agent|user], type, payload, at
```

---

## 5. End-to-end runtime flow (one engagement)

1. **Scope & authorize.** Human creates engagement, defines Scope (domains/CIDRs, RoE, window,
   `max_action_class`), and attaches Authorization. API refuses to start otherwise.
2. **Plan.** Planner produces a phase plan artifact → human reviews/approves the plan.
3. **Recon (passive).** Planner queues the passive recon capabilities (subfinder, crt.sh,
   httpx). No gate. Findings: asset inventory, tech stack, exposure surface.
4. **Scan (active).** Active recon + scanning skills → nmap/nuclei/ffuf/nikto. Scope validated
   per target. Findings: open ports, services, versions, web issues, misconfigs.
5. **Analyze.** Version→CVE correlation, severity scoring, dedup, false-positive triage
   (skills: `performing-web-application-vulnerability-triage`, etc.). Produces prioritized list.
6. **Verify / exploit (gated).** For each candidate: load the relevant exploit skill, run the
   **safe check** capability first. If confirmed and scope permits exploitation, **gate** →
   human approves → run the exploit capability with blast-radius limits. Capture PoC evidence.
7. **Report.** Reporting Engine compiles everything into a client-ready document with framework
   mappings and remediation, plus a retest checklist.
8. **Close.** Engagement archived; evidence retained per policy; audit log sealed.

---

## 6. Deployment topology

- **Dev / self-host (start here):** docker-compose — console, api, worker(s), agent, postgres,
  redis, minio, and the tool-runner images. Runs on one beefy box or your Kali-lab host.
- **Isolation:** tool runners on a segmented Docker network with egress firewalled to in-scope
  targets only; the agent/api never share a network namespace with tool containers.
- **Later / SaaS:** per-tenant worker pools, EU region for evidence store (you already scoped EU
  hosting), queue-based autoscaling of tool runners, SSO, and a hardened secrets manager.

---

## 7. What NOT to build (guardrails on your own scope)

- ❌ No "auto-exploit everything" mode. Ever. Exploitation is always scope-permitted + gated.
- ❌ No storing of client credentials/loot beyond what the report needs, unencrypted.
- ❌ No shipping raw upstream skills unvalidated — curate first.
- ❌ No hardcoded target lists or payloads that can fire without a live, validated scope.
- ❌ No marketing the product as affiliated with Anthropic.
