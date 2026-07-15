# 09 — Timeline & Effort Estimate

Straight answer to "how many weeks, if we start tomorrow." **Start date assumed: Tue 7 Jul 2026.**
Ranges, not false precision — the honest drivers of variance are in §4.

---

## 1. Two scenarios (solo, with Antigravity doing the heavy lifting)

Antigravity accelerates scaffolding, boilerplate, UI, and glue a lot. It does **not** remove the
hard 20%: the safety layer's correctness, per-tool output parsers (each tool is its own edge-case
zoo), agent-loop reliability, and integration debugging. So the estimate splits by *your*
availability.

| Milestone | Phase | Full-time (~40 h/wk) | Part-time (~12 h/wk) |
|---|---|---|---|
| **M0** Foundations + safety layer works (out-of-scope denied) | 0 | ~1 wk → **~13 Jul** | ~3 wk → **~28 Jul** |
| **M1** MVP: recon+scan+report + live dashboard (no exploitation) — *first sellable/demoable* | 1 | ~3–4 wk → **~1 Aug** | ~9–10 wk → **~15 Sep** |
| **M2** Gated safe exploitation (verify-don't-detonate w/ PoC) | 2 | ~6–7 wk → **~24 Aug** | ~15–17 wk → **~27 Oct** |
| **M3** Depth: web+network+identity/cloud, post-ex enum | 3 | ~11–12 wk → **~28 Sep** | ~27–30 wk → **~Jan 2027** |
| **M4** SaaS hardening (multi-tenant, EU hosting, scheduling) | 4 | ~16+ wk → **~Nov 2026** | ~40+ wk → **mid 2027** |

**Headline numbers:**
- **First real, sellable version (M1): ~3–4 weeks full-time, or ~9–10 weeks part-time.**
- **Full-lifecycle product you'd put your company's name on (through M3): ~3 months full-time.**

---

## 2. What "start tomorrow" week 1 looks like (full-time)

| Day | Focus |
|---|---|
| Tue 7 Jul | Repo scaffold, docker-compose, `brain/` + `.antigravity/knowledge/` in place, Antigravity master prompt (Phase 0). |
| Wed 8 Jul | DB migrations; Scope Validator + Action Classifier (the conscience). |
| Thu 9 Jul | Approval Gate + Kill Switch + Audit Log; Authorization gating. |
| Fri 10 Jul | Skill ingest + validation report; console shell + auth. |
| Mon 13 Jul | **M0 exit test:** engagement can't start without scope+authorization; out-of-scope denied + audited. |

If M0 slips a few days, that's normal — the safety layer is the part you do *not* rush.

---

## 3. Why M1 is the milestone that matters

M1 (recon + scan + report + dashboard, no exploitation) is:
- **Legally safe** to run on authorized targets (no exploitation).
- **Demoable** to prospects and usable on real engagements immediately.
- The point where the dashboard shows live commands + severity counts you asked for.

Everything after M1 (gated exploitation, breadth, SaaS) is expansion you can sell *toward* while
already using M1. Don't wait for M4 to show anyone.

---

## 4. What moves these dates (honest variance drivers)

**Slower if:**
- Your availability is spiky (day job: SOC + pentest + existing products) — part-time column is
  the realistic one unless you block dedicated time.
- Tool output parsers fight you — nmap XML, nuclei JSONL, sqlmap dirs, ZAP API each have quirks;
  budget real time here.
- The agent loop is flaky at first (wrong skill picked, loops, bad params) — reliability tuning
  is iterative.
- Model refusals on offensive reasoning — mitigated by the local-model router, but setup time.
- You widen scope early (chasing all 817 skills / Burp DAST licensing) instead of the Phase-1
  shortlist.

**Faster if:**
- You block focused full-time weeks for Phase 0–1.
- You stick to the **9-skill / ~6-capability Phase-1 shortlist** (`06 §7`) and ZAP-only web DAST.
- You reuse your existing VulnClaw/Ollama/Kali work for the model + tool plumbing.
- You let Antigravity parallelize `/console`, `/tools`, `/reporting` once Phase 0 is merged.

---

## 5. Recommended commitment to hit "~4 weeks to MVP"

To land **M1 by early August**, you realistically need **~3 focused full-time weeks** (or
equivalent — e.g. 2 full days/week for ~9 weeks). Concretely:
- Weeks 1: Phase 0 (safety) — full attention, no shortcuts.
- Weeks 2–3: Phase 1 capabilities + agent loop + dashboard + reporting.
- Buffer: ~4–5 days for parser edge cases and the golden-path e2e test on your Kali lab target.

---

## 6. One-line answer

**Full-time, starting tomorrow: a real, sellable recon-scan-report product with the live
dashboard in ~3–4 weeks (early August 2026); safe gated exploitation ~7 weeks; a full-lifecycle
product ~3 months. Part-time, roughly 2.5–3× those.** The safety layer in week 1 is the one thing
worth doing slowly.
