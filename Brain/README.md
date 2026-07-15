# HexaCore — Product Build Package

AI-orchestrated, authorization-gated **offensive-security platform**: recon → scanning →
analysis → gated verification/exploitation → reporting, powered by a curated cybersecurity
skills corpus as the agent's playbook library and real sandboxed tools as its hands.

> **Product name: `HexaCore`** (chosen from the gray-hat shortlist in
> [`10-PRODUCT-NAMES.md`](10-PRODUCT-NAMES.md)). Built for
> **authorized penetration testing only**.
>
> **Anatomy:** `brain/` = these design docs (reasoning + source of truth). `heart/` = the
> 817-skill corpus (the knowledge that powers decisions). Keep both folder names as-is; they're
> the anatomy, not the brand.

## Read in this order

| # | Document | What it gives you |
|---|---|---|
| 00 | [`00-REVIEW-AND-FEASIBILITY.md`](00-REVIEW-AND-FEASIBILITY.md) | Honest review of the ChatGPT idea, what was wrong, and the go/no-go verdict. **Start here.** |
| 01 | [`01-ARCHITECTURE.md`](01-ARCHITECTURE.md) | Full system architecture, components, data model, runtime flow. |
| 02 | [`02-IMPLEMENTATION-PLAN.md`](02-IMPLEMENTATION-PLAN.md) | Locked-in stack, phased roadmap, MVP definition, milestones. |
| 03 | [`03-TASK-BREAKDOWN.md`](03-TASK-BREAKDOWN.md) | Ticket-ready backlog (epics A–H), first-10-tickets order. |
| 04 | [`04-ANTIGRAVITY-PROMPT.md`](04-ANTIGRAVITY-PROMPT.md) | Copy-paste build prompt + `.antigravity/knowledge/` rules. |
| 05 | [`05-SAFETY-AUTHORIZATION-LEGAL.md`](05-SAFETY-AUTHORIZATION-LEGAL.md) | Scope, authorization, action gating, kill switch, legal scaffolding. **Not optional.** |
| 06 | [`06-SKILLS-INTEGRATION-MAP.md`](06-SKILLS-INTEGRATION-MAP.md) | How to wire the 817 skills into the pipeline; curation; Phase-1 shortlist. |
| 07 | [`07-LOCAL-HOSTING-AND-VM.md`](07-LOCAL-HOSTING-AND-VM.md) | Run it locally on Kali; one-folder layout; **zero-touch** Kali (Docker vs VirtualBox); `make up`/`make engage`. |
| 08 | [`08-TOOL-INTEGRATION.md`](08-TOOL-INTEGRATION.md) | Full tool inventory (nmap, nuclei, nikto, ZAP, **Burp** 3 ways, sqlmap, MSF, AD/cloud); how the Platform drives each; adapter contract. |
| 09 | [`09-TIMELINE-ESTIMATE.md`](09-TIMELINE-ESTIMATE.md) | Weeks-to-build with calendar dates (start 7 Jul 2026), full-time vs part-time. |
| 10 | [`10-PRODUCT-NAMES.md`](10-PRODUCT-NAMES.md) | Gray-hat product-name brainstorm — the shortlist `HexaCore` was chosen from. |

**There is one frontend** — a single live operator **dashboard** (status bar, live severity
counts Critical/High/Medium/Low/Info, phase timeline, live command feed, findings, approval
inbox). Spec is in `01-ARCHITECTURE.md §3.1`; it's built by the Antigravity prompt in `04`.

**Tools & Burp:** Kali Docker ships nothing preinstalled — the `infra/kali/Dockerfile` installs
exactly what's driven (`08`). Web DAST is **OWASP ZAP** (automation-native); **Burp** is included
three ways (DAST API / Pro API / Community as a manual station), because Burp Community can't be
automated — details in `08 §4`.

**Timeline:** first sellable recon-scan-report MVP ≈ **3–4 weeks full-time** from a 7 Jul 2026
start; full lifecycle ≈ 3 months. See `09`.

## The three things that make or break this

1. **Skills are the brain, tools are the hands, scope is the conscience** — never conflate them.
2. **Build the safety layer before any tool** — deny-by-default scope + gated exploitation.
3. **Ship the golden path first** (recon + scan + report, no exploitation), then expand.

## First actions

1. Read `00`, then `05`, then `07`.
2. Put this whole `brain/` folder at the root of your repo (it's the source of truth).
3. Clone the skills corpus into `heart/` (see `07 §2`) — that's **the heart**.
4. Create the `.antigravity/knowledge/` rules from `04`.
5. Paste the master prompt from `04` into Antigravity Manager view.
6. Ship Phase 0 (safety) → prove out-of-scope is denied → then Phase 1 (recon+scan+report +
   dashboard).
7. Run it: `make up` then `make engage SCOPE=./engagements/<name>.yaml` → watch the dashboard.

## The environment in one line

Kali **Docker** tool-runner (`make kali-build`) + `make up` + `make engage` = **zero-touch**. The
only human moment is approving an exploit at a gate. Skip the VirtualBox ISO — its installer is
interactive and breaks the "no intervention" goal (see `07 §3`).

## Attribution & licensing note

The skills corpus (`mukul975/Anthropic-Cybersecurity-Skills`) is a **community project, not
affiliated with Anthropic**, licensed Apache-2.0. Keep its `LICENSE`/`NOTICE`, attribute it, and
**do not** brand your product as "Anthropic" anything.
