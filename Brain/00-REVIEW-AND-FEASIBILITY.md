# 00 — Review, Reality Check & Feasibility Verdict

> _Historical record — do not edit as spec. Some designs changed since; notably semantic skill
> retrieval was removed (2026-07-10). See Brain/01 for current architecture._

> **Product name:** `HexaCore`. Also referred to as **the Platform** below.

---

## 1. What you were handed, and what was wrong with it

The ChatGPT output pointed you at the **`mukul975/Anthropic-Cybersecurity-Skills`** repo
(817 skills, 29 domains, 6 framework mappings) and — reading between the lines of your
frustration — implied you could bolt these "skills" onto an agent and get an end-to-end
"scan → exploit → report" product almost for free. Two load-bearing facts were skipped:

### 1.1 The skills are **knowledge**, not **executables**

Every skill is a `SKILL.md` file: YAML frontmatter (name, description, tags, ATT&CK/D3FEND/
NIST mappings) plus a Markdown body with `When to Use`, `Prerequisites`, `Workflow`,
`Verification`. That's it. Example from the library:

```
skills/performing-web-application-penetration-test/
├── SKILL.md          ← playbook text (what to do, which tool, which flags)
├── references/       ← standards + deep procedure
├── scripts/          ← optional helper scripts
└── assets/           ← report templates
```

They are **decision-making playbooks for an LLM**. They do not open a socket, send a packet,
or run an exploit. The value is real — they turn a generic model into something that *reasons
like a senior analyst* — but they are the **cortex**, not the **hands**. Your product still has
to supply the hands: nmap, subfinder, httpx, nuclei, ffuf, sqlmap, Nikto, Metasploit RPC,
BloodHound/Certipy, cloud enum tools, etc., running in a controlled sandbox.

**This is the single most important correction.** Any plan that treats the skills as the
execution engine is broken on day one.

### 1.2 It is **not** an Anthropic product

The repo's own README, first line under the title:

> *"Community Project — This is an independent, community-created project. Not affiliated with
> Anthropic PBC."*

Author is **Mahipal Jangra (`mukul975`)**, license **Apache-2.0**. You *can* use it commercially
and you *can* fork it — Apache-2.0 permits that — but:
- Do **not** brand or market your product as "Anthropic" anything.
- Keep the `LICENSE`, `NOTICE`, and attribution in your repo.
- Treat the skill content as a **starting corpus you curate and harden**, not gospel. Some
  descriptions in `index.json` are visibly malformed (e.g. a `">-"` leaked as a description,
  truncated descriptions). You'll need a validation/cleanup pass — covered in the task list.

### 1.3 Antigravity's role was probably muddled

You said "a prompt for my antigravity." **Google Antigravity is the agentic IDE you'll use to
*build* the Platform** — it is not the thing that runs the pentest. Keep these separate in your
head:

| | Builds the code | Runs the pentest at runtime |
|---|---|---|
| **Antigravity** (Gemini/Claude agents, artifacts, browser verify) | ✅ yes | ❌ no |
| **The Platform's own runtime agent** (your LangGraph loop + tools) | ❌ no | ✅ yes |

The prompt in doc `04` is a **build spec for Antigravity**. The runtime agent it builds is
specified in docs `01`, `02`, `06`.

---

## 2. Feasibility verdict

**Verdict: BUILDABLE and commercially sensible — with three non-negotiable constraints.**

| Dimension | Verdict | Notes |
|---|---|---|
| Technical feasibility | ✅ High | All components are proven tech. The novel part is orchestration + safety, not any single piece. |
| Fit to your skills | ✅ Very high | You already run VulnClaw, Ollama (Qwen), a Kali lab, and ship React products. This is a productization of things you do by hand. |
| Legal / liability | ⚠️ Gated | Autonomous *exploitation* is a real pentest, not a demo. Without an authorization + rules-of-engagement layer it's a liability, not a product. Doc `05` makes this a core feature. |
| LLM cooperation | ⚠️ Manage it | Many hosted models refuse offensive tasks. Your architecture must support **model optionality** (local Ollama for offensive reasoning, hosted for reporting/analysis) and structured tool-calling so the model *orchestrates* rather than *authors* exploits. |
| Timeline to first sellable version | ✅ Realistic | A scoped MVP (recon + scan + report, no live exploitation) is ~6–8 focused weeks solo with Antigravity doing the grunt work. Full lifecycle is a phased roadmap (doc `02`). |

### The three non-negotiables

1. **Safety-by-default execution.** Passive/active/exploit/destructive actions are classified;
   anything beyond active scanning is **gated behind human approval** and a validated scope.
   Default mode is *dry-run*. (Doc `05`.)
2. **Authorization is a data object, not a checkbox.** No engagement runs without a stored
   scope allowlist (domains/CIDRs) + a signed authorization record + rules of engagement.
   The scope validator sits *in front of every tool call*. (Doc `05`.)
3. **Scoped MVP, then expand.** Do not try to ship all 817 skills and full post-exploitation at
   once. Ship the **golden path** first (doc `02`, Phase 1), prove it, then widen.

---

## 3. What the product actually is (one paragraph)

> **The Platform is an authorization-gated, AI-orchestrated offensive-security engine.** A human
> defines and *proves* scope for an engagement. A planner agent decomposes it into lifecycle
> phases (recon → scanning → analysis → verification/exploitation → reporting). For each step the
> agent retrieves the matching playbook(s) from the curated skills corpus, picks a **real tool
> capability**, validates the target against the scope allowlist, runs the tool inside a sandbox,
> parses the output into structured findings, and moves on — pausing for human approval before
> any active-exploit or destructive action. At the end it compiles a client-ready report mapped
> to CVE/CWE/CVSS and MITRE ATT&CK. The 817 skills are the agent's playbook library; the sandboxed
> tools are its hands; the scope + RoE layer is its conscience.

---

## 4. Honest risks & how the design answers them

| Risk | Reality | Design answer |
|---|---|---|
| Model refuses / degrades on offensive steps | Common with hosted models | Model router: local model for offensive reasoning, hosted for parse/report; the model *selects* pre-built tool capabilities, never writes raw exploits. |
| Agent scans/attacks out-of-scope asset | Catastrophic legally | Scope validator wraps *every* tool invocation; deny-by-default; hard kill switch. |
| Destructive exploit runs unattended | Real risk of damage | Action classifier + approval gates + blast-radius limits + "verify-don't-detonate" default. |
| Skill corpus has errors / stale tool flags | Confirmed (malformed entries in index.json) | Ingest pipeline validates + normalizes + lets you override; skills are advisory to a typed tool layer, not executed verbatim. |
| Scope creep kills the project | Very likely given 817 skills | Phased roadmap; MVP = one web target + one CIDR, recon+scan+report only. |
| Legal exposure to your company | High for a pentest SaaS | Written authorization object, audit log of every action, EU-hostable evidence store, ToS + RoE templates. |

---

## 5. Deliverables in this package

| File | Purpose |
|---|---|
| `00-REVIEW-AND-FEASIBILITY.md` | This document — the reality check and go/no-go. |
| `01-ARCHITECTURE.md` | Full system architecture, components, data model, agent loop. |
| `02-IMPLEMENTATION-PLAN.md` | Phased roadmap, milestones, tech stack, MVP definition. |
| `03-TASK-BREAKDOWN.md` | Granular, ticket-ready backlog per phase. |
| `04-ANTIGRAVITY-PROMPT.md` | Copy-paste build prompt(s) + `.antigravity` rules for the IDE. |
| `05-SAFETY-AUTHORIZATION-LEGAL.md` | Scope, RoE, action gating, kill switch, legal scaffolding. |
| `06-SKILLS-INTEGRATION-MAP.md` | How to wire the 817 skills into the scan→exploit→report pipeline. |

Read them in order. `05` is not optional reading — it is where the product either becomes real
or becomes a lawsuit.
