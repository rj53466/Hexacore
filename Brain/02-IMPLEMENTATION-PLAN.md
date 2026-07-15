# 02 — Implementation Plan

Codename **HexaCore**. Phased so you always have a shippable, *safe* artifact at each milestone.
Timeboxes assume you solo + Antigravity doing heavy lifting; scale up if you add help.

---

## 1. Recommended stack (locked-in choices)

| Layer | Choice | Why |
|---|---|---|
| Frontend | React + Vite + TS + Tailwind + Recharts | Your existing stack; Recharts for the live severity donut/charts on the dashboard. |
| Tool env | Kali Docker image (`kalilinux/kali-rolling`) | Zero-touch, scriptable, ephemeral per run — see `07`. (Avoid VirtualBox ISO: interactive installer.) |
| API | FastAPI (Python 3.12, async) | Same language as agent + tools; great DX; native async. |
| Agent | LangGraph | Stateful graph = phases + human-in-the-loop interrupts. |
| Models | Ollama (local) via `ModelRouter` (deterministic / local-ollama profiles) | Offensive reasoning stays local; refusal-resistant. (No hosted-model path — not built.) |
| Tool exposure | MCP servers per capability group | Model-agnostic, portable, matches ecosystem. |
| Sandbox | Docker (→ gVisor/Firecracker later) | Cheap, ubiquitous isolation; harden later. |
| Queue/bus | Redis + Celery (or RQ) | Long tool runs, retries, pub/sub for live UI. |
| DB | PostgreSQL | Relational fit for the data model; JSONB for parsed output. |
| Object store | MinIO (S3 API), EU region | Self-host now, EU-hostable evidence you already scoped. |
| Reporting | Jinja2 + xhtml2pdf (PDF) + python-docx | Client-ready, template-driven (WeasyPrint dropped — needs native GTK). |
| ~~Embeddings~~ | ~~local sentence-transformer~~ | **DELETED 2026-07-10** — semantic skill retrieval was never wired in; removed, not deferred. |
| Auth | JWT + RBAC | Owner / operator / viewer roles. |

> Keep it **one repo, monorepo layout** (`/console`, `/api`, `/agent`, `/tools`, `/skills`,
> `/reporting`, `/infra`). Antigravity 2.0 handles multi-package repos well.

---

## 2. Phase 0 — Foundations (Week 1)

**Goal:** skeleton that runs, with the safety layer stubbed *first* so nothing offensive can
ever run un-gated even during development.

- Monorepo scaffold + docker-compose (postgres, redis, minio, api, console).
- Data model migrations (Engagement, Scope, Authorization, Task, ToolRun, Finding, Approval,
  AuditEvent).
- **Safety Layer stubs implemented before any tool:** Scope Validator (deny-by-default),
  Action Classifier, Approval Gate interface, Kill Switch, Audit Log writer.
- Skill ingest v1: parse `heart/skills/**/SKILL.md`, validate frontmatter, build a JSON index of
  valid skills; produce a **validation report** listing malformed skills to fix. (No embedding
  index — semantic retrieval deleted 2026-07-10.)
- Console shell: auth, engagement list, empty dashboard.

**Exit criteria:** you can create an engagement, define a scope, and the system *refuses* to do
anything without an Authorization. No tools yet.

---

## 3. Phase 1 — MVP "Golden Path": Recon + Scan + Report (Weeks 2–4)

**Goal:** the first sellable, *legally safe* deliverable — a fully automated **passive+active
recon and vulnerability scan** of an in-scope web app + CIDR, ending in a client-ready report.
**No live exploitation in this phase.** `max_action_class = active-scan`.

- Tool capabilities (passive + active-scan only), each MCP-wrapped + output-parsed:
  - `recon.subdomains` (subfinder), `recon.dns`, `recon.http_probe` (httpx), `recon.tech`
    (whatweb), `recon.tls` (testssl.sh).
  - `scan.ports` (nmap SYN + service + safe scripts), `scan.web_nuclei` (nuclei),
    `scan.web_dir` (ffuf/gobuster), `scan.web_nikto` (nikto).
- Agent graph: planner → execute → scan_setup → verify_setup (loop). Analyze + report run after
  the graph. (Skill retrieval deleted 2026-07-10 — capabilities are driven by the fixed phase
  plan, not skill lookup.)
- Analyze node: version→CVE correlation + severity + dedup + false-positive triage.
- Reporting Engine v1: PDF + DOCX with your branding, findings, framework mappings.
- Console: live engagement view (phase timeline + streaming activity), findings board, report
  download.
- Scope enforcement verified with a red-team test: attempt an out-of-scope target → must be
  denied + audited.

**Exit criteria:** point it at a lab target (your Kali/VMware range or an authorized test app),
get a clean, branded report with real findings, and prove out-of-scope targets are blocked.
**This is your first demo/sellable artifact.**

---

## 4. Phase 2 — Gated Verification & Safe Exploitation (Weeks 5–7)

**Goal:** add the "exploit" step — but as **verify-don't-detonate** with approval gates.
`max_action_class` can now be raised to `active-exploit` per engagement.

- Approval Gate fully wired into the graph as a human-in-the-loop interrupt (LangGraph
  `interrupt` → console Approval Inbox → resume).
- Exploit-class capabilities, safe-check-first:
  - `verify.web_sqli` (sqlmap detection-only → gated exploitation),
  - `verify.msf_check` (Metasploit RPC `check` modules only by default),
  - `verify.idor` / `verify.ssrf` (evidence-capturing verifiers),
  - `verify.adcs_find` (Certipy find), `enum.netexec` (enumeration only).
- Blast-radius limits: rate caps, single-target confirmation, no mass/`destructive` class in v2.
- Evidence capture upgraded: PoC request/response pairs, screenshots, minimal reproduction.
- Report gains a "Confirmed / Exploited" evidence section and CVSS with exploited-in-context.

**Exit criteria:** on an authorized vulnerable target, the agent detects → gates → (you approve)
→ safely confirms a vuln with captured PoC, and the report reflects confirmed exploitation.

---

## 5. Phase 3 — Depth, coverage & post-exploitation (Weeks 8–12)

**Goal:** widen skill/tool coverage and add carefully-gated post-exploitation.

- More capability groups: AD/Identity (BloodHound-CE, Kerberoast *gated*, ADCS abuse *gated*),
  Cloud (ScoutSuite, CloudFox, Pacu modules *gated*), API security (GraphQL/REST fuzzing).
- Post-exploitation phase (highly gated, `destructive` still off by default): lateral-movement
  *enumeration*, privilege-path analysis — evidence, not damage.
- Chaining logic: findings feed follow-on skill selection (e.g. valid creds → scoped auth'd
  scans).
- Skill corpus curation pass 2: fix all flagged skills, add capability bindings across domains.

**Exit criteria:** multi-phase engagement across web + network + one identity/cloud path, fully
gated, with a comprehensive report.

---

## 6. Phase 4 — Productization & SaaS hardening (Weeks 12+)

- Multi-tenant + org management, SSO, per-tenant isolation, EU evidence region.
- Autoscaling tool-runner pools; stronger sandbox (gVisor/Firecracker).
- Scheduling/recurring assessments (attack-surface monitoring product line).
- Client portal (read-only findings + report history), retest workflows.
- Compliance packaging: SOC2-friendly audit trails, data-retention controls, ToS/RoE templates.
- Pricing/packaging: per-engagement, per-asset continuous monitoring, or seat-based.

---

## 7. Milestones & "definition of done"

| Milestone | When | DoD |
|---|---|---|
| M0 Foundations | End W1 | Engagement + scope + authorization gating works; skill index built; validation report produced. |
| M1 MVP report | End W4 | Automated recon+scan → branded report on a lab target; out-of-scope blocked & audited. |
| M2 Safe exploit | End W7 | Gated verify-don't-detonate confirms a vuln with PoC evidence. |
| M3 Coverage | End W12 | Multi-domain gated engagement (web+net+identity/cloud). |
| M4 SaaS | W12+ | Multi-tenant, scheduled, EU-hosted, compliance-ready. |

---

## 8. Where Antigravity fits into building this

- Use **Manager view** to spawn parallel agents per package: one on `/api`, one on `/agent`,
  one on `/console`, one on `/tools`. Antigravity 2.0's multi-repo/multi-package support handles
  the monorepo.
- Review the **Implementation Plan artifact** Antigravity generates *before* proceeding — set
  artifact review to require approval (don't let it "Always Proceed" on security code).
- Use the **browser subagent** to verify the console UI (scope builder, approval inbox).
- Store project conventions + the **safety rules** (doc `04`) in `.antigravity/knowledge/` so
  every agent inherits the deny-by-default posture.
- The build prompt is in **doc `04`**.

---

## 9. Practical order of operations (do this literally)

1. Read doc `05` (safety) end-to-end. Build the safety layer **first**.
2. Phase 0 skeleton + skill ingest + validation report.
3. Curate the worst skills flagged in the validation report (doc `06` §Curation).
4. Phase 1 golden path → get a real report out of a lab target.
5. Only then Phase 2 gated exploitation.
6. Everything else is expansion.
