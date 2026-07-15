# 03 — Task Breakdown (ticket-ready backlog)

Each task is scoped to be an Antigravity mission or a single PR. IDs are stable so you can track
them. `[GATE]` = touches the safety layer; review with extra care.

---

## EPIC A — Foundations & Safety (Phase 0)

- **A1** Scaffold monorepo (`/console /api /agent /tools /skills /reporting /infra`), root
  README, licenses (keep upstream Apache-2.0 `LICENSE` + `NOTICE`), pre-commit, CI lint/test.
- **A2** `docker-compose.dev.yml`: postgres, redis, minio, api, console, mailhog.
- **A3** DB migrations for all core tables (Engagement, Scope, Authorization, Task, ToolRun,
  Finding, Approval, AuditEvent). Seed script.
- **A4** `[GATE]` **Scope Validator** service: resolve host/URL/IP → allow/deny vs
  `allow_domains` (suffix + wildcard), `allow_cidrs`, `deny_list` (deny always wins). Unit tests
  incl. IDN/punycode, IPv6, DNS-rebind guard.
- **A5** `[GATE]` **Action Classifier**: map (capability, params) → `passive | active-scan |
  active-exploit | destructive`. Table-driven + tests.
- **A6** `[GATE]` **Approval Gate** interface + persistence (Approval table) + resume token.
- **A7** `[GATE]` **Kill Switch**: global + per-engagement flag; middleware that aborts runs and
  stops containers; console button + API.
- **A8** `[GATE]` **Audit Log** writer + append-only guarantee; every safety decision logged.
- **A9** Authorization object: click-sign + file-upload flows; block engagement `start` unless a
  valid Authorization + Scope exist. Tests for the refusal path.
- **A10** AuthN (JWT) + RBAC (owner/operator/viewer) on all endpoints.
- **A11** Console shell: login, engagement list, create-engagement wizard (empty).

**Epic A exit test:** create engagement, add scope, try to start without authorization → denied
+ audited; add authorization → allowed to plan (no tools yet).

---

## EPIC B — Skill Knowledge Service

- **B1** Skill ingester: walk `heart/skills/**/SKILL.md`, parse YAML frontmatter + body sections.
- **B2** Frontmatter validator + normalizer; emit `skills-validation-report.md` listing
  malformed entries (e.g. leaked `">-"` descriptions, truncated descriptions, missing fields).
- **B3** `skill-overrides.yaml` overlay loader (your corrections + capability bindings win).
- ~~**B4** Embedding index over `description + tags`.~~ **DELETED 2026-07-10** — built but never
  wired into the agent; removed, not deferred. Reintroduce only as fresh keyword lookup if needed.
- ~~**B5** Retrieval API: `retrieve(objective, phase, k)`.~~ **DELETED 2026-07-10** (see B4).
- ~~**B6** Skill serving API (progressive disclosure).~~ **NOT BUILT** — depended on retrieval;
  dropped with it.
- ~~**B7** Capability-binding map (`skill → capability`).~~ **NOT BUILT** — capabilities are driven
  by the fixed phase plan, not skill bindings.

---

## EPIC C — Tool Execution Layer (capabilities)

*Each capability = typed input schema + sandboxed runner + output parser (→ structured JSON) +
action-class tag + MCP wrapper. One ticket per capability.*

**C-recon (passive):**
- **C1** `recon.subdomains` (subfinder)
- **C2** `recon.dns` (dnsx / zone-transfer attempt)
- **C3** `recon.http_probe` (httpx)
- **C4** `recon.tech` (whatweb)
- **C5** `recon.tls` (testssl.sh)
- **C6** `recon.ct_logs` (crt.sh)

**C-scan (active-scan):**
- **C7** `scan.ports` (nmap SYN + `-sV` + safe `--script`)  `[GATE]` active
- **C8** `scan.web_nuclei` (nuclei, curated templates)  `[GATE]` active
- **C9** `scan.web_dir` (ffuf/gobuster)  `[GATE]` active
- **C10** `scan.web_nikto` (nikto)  `[GATE]` active

**C-verify/exploit (Phase 2, gated):**
- **C11** `[GATE]` `verify.web_sqli` (sqlmap detection-only default; exploitation only post-gate)
- **C12** `[GATE]` `verify.msf_check` (Metasploit RPC `check` only default)
- **C13** `[GATE]` `verify.idor` / `verify.ssrf` (evidence-capturing verifiers)
- **C14** `[GATE]` `enum.netexec` (enumeration only)
- **C15** `[GATE]` `verify.adcs_find` (Certipy find)

**Cross-cutting:**
- **C16** Sandbox runner: ephemeral Docker, egress firewalled to in-scope targets, resource +
  time limits, read-only images.
- **C17** Output-parser framework (raw → normalized JSON + evidence upload to MinIO).
- **C18** MCP server(s) exposing capabilities to the agent; capability registry.
- **C19** `[GATE]` Egress-to-scope enforcement test harness (prove a container can't hit an
  out-of-scope host).

---

## EPIC D — Agent Orchestrator

- **D1** LangGraph skeleton — **as built**: nodes `planner`, `execute`, `scan_setup`,
  `verify_setup` (loop); persisted state. Safety-gate/parse/normalize happen inside
  CapabilityExecutor, not as separate nodes.
- **D2** **Planner** node → ordered per-phase capability queue (fixed phase plan).
- ~~**D3** Skill-Retriever node → calls Epic B retrieval.~~ **DELETED 2026-07-10** — retrieval
  removed (see Epic B4/B5); no such node exists.
- ~~**D4** Tool-Selector node → skill procedure → capability via binding map.~~ **NOT BUILT** —
  capabilities come straight from the fixed phase plan.
- **D5** Safety gating (classify + scope-validate + approval interrupt/resume) — **not a separate
  node**; it runs *inside* `CapabilityExecutor` before every tool call.
- **D6** **`execute` node** → invoke the queued capability via CapabilityExecutor; capture evidence.
- ~~**D7** Verifier node.~~ **NOT a node** — dedup + host-discovery follow-up happens inline in the
  `execute` node + `FindingStore`.
- ~~**D8** Findings-Writer node.~~ **NOT a node** — adapters parse to the Finding schema; the store
  normalizes/maps.
- **D9** Phase routing (advance/loop/end) — a conditional **edge** (`route()`), not a node;
  `scan_setup`/`verify_setup` build each phase's queue.
- **D10** **Model router** (`ModelRouter`): `deterministic` vs `local`/`ollama` (task reprioritise).
  No hosted path. Per-engagement `model_profile`; function/tool-calling only (no raw payloads).
- **D11** Event emitter → WebSocket (live console activity + phase timeline).

---

## EPIC E — Analysis & Findings

- **E1** Version→CVE correlation (service/tech versions → CVE list) + source caching.
- **E2** Severity + CVSS vector builder; normalize scanner severities.
- **E3** Dedup + false-positive triage (drive with triage skills).
- **E4** Framework mapper: CWE + MITRE ATT&CK technique from finding type; store on Finding.
- **E5** Follow-up planner: finding → candidate next skills (chaining).

---

## EPIC F — Reporting

- **F1** Jinja2 report templates (exec summary, scope+authorization statement, methodology,
  findings, remediation, retest checklist, appendices).
- **F2** PDF (WeasyPrint) + DOCX (python-docx) renderers.
- **F3** Branding pack (Sahasrakshi cover/logo/colors) + configurable theme.
- **F4** Evidence appendix generator (screenshots, PoC req/resp, tool versions).
- **F5** Report download + history in console.

---

## EPIC G — Console (single dashboard, frontend)

- **G1** Scope Builder (domains/CIDRs/deny, RoE, window, `max_action_class`, `autonomy_profile`).
- **G2** Authorization upload/click-sign UI.
- **G3** Dashboard shell + WebSocket client (subscribes to engagement event stream).
- **G3a** Status bar widget (engagement, run state, current phase N/5, elapsed timer, scope
  summary, ceiling, always-visible KILL button).
- **G3b** Severity summary widget: live Critical/High/Medium/Low/Info counts + total, donut chart
  (Recharts) + numeric tiles; derives from `finding.created`/`finding.updated` events.
- **G3c** Phase timeline widget (Recon→Scan→Analyze→Verify→Report, active phase + "doing now").
- **G3d** Live command feed widget: terminal-style stream (timestamp, capability, command line,
  target, exit code, status); scope denials rendered in red.
- **G4** `[GATE]` Approval Inbox (target, tool, skill, expected impact, evidence-so-far; Approve /
  Deny / Approve-with-limit / Abort). Empty under `scan-only`.
- **G5** Findings panel (severity sort, click→evidence: PoC req/resp, screenshot, raw output,
  CVSS, CWE, ATT&CK, remediation; status edit).
- **G6** Report preview + download.
- **G7** Kill-switch button (global + per-engagement) with confirm.

## EPIC I — Zero-touch environment & lifecycle

- **I1** `infra/kali/Dockerfile` — Kali tool-runner image with all Phase-1 tools; `make kali-build`.
- **I2** `docker-compose.yml` for full platform; `docker-compose.kali.yml` for the tool runner.
- **I3** `Makefile`: `up`, `down`, `kali-build`, `engage SCOPE=…`, `kill ENG=…`, `report ENG=…`,
  `logs`.
- **I4** Engagement-from-scope-file loader (`engagements/*.yaml` → Engagement+Scope+Authorization),
  so `make engage` runs unattended.
- **I5** `autonomy_profile` implementation (scan-only | supervised | assisted) wired to the gate
  logic; default `supervised`; `scan-only` runs with zero prompts.
- **I6** `[GATE]` Agent event emitter → Redis pub/sub (`phase.changed`, `command.started`,
  `command.finished`, `scope.denied`, `finding.created`, `gate.requested`, `gate.resolved`);
  API WebSocket relay.
- **I7** (Optional) `infra/vm/Vagrantfile` for the prebuilt-Kali-box VM path (no ISO installer).

---

## EPIC H — Testing, Safety Validation, Ops

- **H1** `[GATE]` Out-of-scope red-team test suite (must deny + audit) — run in CI.
- **H2** `[GATE]` Gate-bypass test suite (agent cannot execute exploit-class without approval).
- **H3** Sandbox escape / egress test (container can't reach out-of-scope or host).
- **H4** End-to-end golden-path test on a known-vulnerable lab target.
- **H5** Load/limits: concurrent engagements, tool timeouts, retries.
- **H6** Observability: structured logs, per-engagement traces, metrics.

---

## Suggested first 10 tickets (in order)

`A1 → A4 → A5 → A6 → A7 → A8 → A9 → B1 → B2 → A11`

Ship the *conscience* before the *hands*. You should be able to demo "it refuses to touch
anything it isn't authorized and scoped for" before a single packet is ever sent.
