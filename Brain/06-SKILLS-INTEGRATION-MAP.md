# 06 — Skills Integration Map

> **STATUS (2026-07-10): DESIGN INTENT, not current architecture.** Semantic skill **retrieval is
> deleted** and the capability-**binding map was never built**. What exists today: `skillsvc.ingest`
> validates the corpus and emits a JSON index of valid skills (see Brain/01 §3.4). The agent drives
> capabilities from a **fixed phase plan**, not from skill lookup. This doc is retained as the
> intended future integration design; do NOT reintroduce the torch/embeddings pipeline to build it.

How the 817-skill corpus *would* plug into the **scan → exploit → report** pipeline. The key
idea again: **a skill tells the agent *what to do and how to interpret it*; a capability *does
it*.** This doc defines the intended binding between them.

---

## 1. The binding model

```
Objective (from Planner)
      │  [DESIGN INTENT] select relevant skills — retrieval was deleted; a keyword match
      │  over the JSON index is the lazy way to build this if ever needed
      ▼
SKILL.md  ── "Workflow" says: enumerate subdomains, probe HTTP, then scan web vulns
      │  binding map: skill → capability(ies)
      ▼
Capability  ── recon.subdomains → recon.http_probe → scan.web_nuclei
      │  (each: typed input · action_class · sandbox · parser)
      ▼
Structured findings ── "Verification" section of the skill confirms/interprets results
```

Two artifacts you maintain:

1. **`skill-overrides.yaml`** — your corrections to upstream skill content (fix flags, mark
   deprecated, adjust for your tool versions).
2. **`capability-bindings.yaml`** — maps each usable skill to one or more platform capabilities +
   the action class the binding is allowed to reach.

Example binding entry:

```yaml
performing-subdomain-enumeration-with-subfinder:
  phase: recon
  capabilities: [recon.subdomains]
  max_action_class: passive

scanning-network-with-nmap-advanced:
  phase: scan
  capabilities: [scan.ports]
  max_action_class: active-scan

exploiting-sql-injection-with-sqlmap:
  phase: verify
  capabilities: [verify.web_sqli]
  max_action_class: active-exploit     # => always gated
  default_mode: detection-only          # verify-don't-detonate
```

**Rule:** a skill can never cause an action above its binding's `max_action_class`, and the
engagement's `max_action_class` caps everything. Both must permit an action for it to run.

---

## 2. Phase → skills → capabilities (concrete, from the real corpus)

### Phase: RECON (passive) — no gate
| Representative skills (real names in corpus) | Capabilities |
|---|---|
| `conducting-external-reconnaissance-with-osint`, `performing-osint-with-spiderfoot`, `building-threat-actor-profile-from-osint` | `recon.osint` |
| `performing-subdomain-enumeration-with-subfinder`, `performing-dns-enumeration-and-zone-transfer` | `recon.subdomains`, `recon.dns` |
| `analyzing-tls-certificate-transparency-logs`, `auditing-tls-certificate-transparency-logs` | `recon.ct_logs`, `recon.tls` |
| `performing-ai-driven-osint-correlation` | agent-side correlation (no tool) |

### Phase: SCAN (active-scan) — audited, capped by engagement ceiling
| Representative skills | Capabilities |
|---|---|
| `scanning-network-with-nmap-advanced` | `scan.ports` |
| `building-vulnerability-scanning-workflow`, `performing-agentless-vulnerability-scanning` | `scan.web_nuclei` (+ later Nessus/InsightVM connectors) |
| `performing-web-application-scanning-with-nikto` | `scan.web_nikto` |
| `performing-vulnerability-scanning-with-nessus`, `implementing-rapid7-insightvm-for-scanning` | connectors (Phase 3) |
| `performing-ot-vulnerability-scanning-safely` | OT-safe profile (Phase 3, extra caution) |

### Phase: ANALYZE — agent-side, no tool actions
| Representative skills | Use |
|---|---|
| `performing-web-application-vulnerability-triage` | dedup, severity, false-positive triage |
| (version→CVE correlation) | drives follow-up skill selection |

### Phase: VERIFY / EXPLOIT (active-exploit) — **always gated + verify-first**
| Representative skills | Capabilities | Notes |
|---|---|---|
| `exploiting-sql-injection-with-sqlmap`, `exploiting-sql-injection-vulnerabilities` | `verify.web_sqli` | detection-only default; exploitation post-gate |
| `exploiting-idor-vulnerabilities` | `verify.idor` | evidence capture, no data exfil |
| `exploiting-insecure-deserialization`, `exploiting-nosql-injection-vulnerabilities`, `exploiting-api-injection-vulnerabilities` | web verifiers | Phase 2/3, gated |
| `exploiting-ms17-010-eternalblue-vulnerability`, `exploiting-smb-vulnerabilities-with-metasploit`, `exploiting-vulnerabilities-with-metasploit-framework` | `verify.msf_check` | **`check` module only** by default; exploit = destructive-risk, extra gate |
| `conducting-internal-reconnaissance-with-bloodhound-ce`, `analyzing-active-directory-acl-abuse` | `enum.bloodhound` | enumeration (Phase 3) |
| `exploiting-adcs-with-certipy`, `abusing-shadow-credentials-for-privesc` | `verify.adcs_find` → gated abuse | find-first (Phase 3) |
| `exploiting-aws-with-pacu`, `performing-cloud-penetration-testing-with-pacu`, `enumerating-cloud-with-cloudfox` | cloud verifiers | read/enum first (Phase 3) |

### Phase: REPORT
| Representative skills | Use |
|---|---|
| `generating-threat-intelligence-reports` | report structure/templates |
| `building-vulnerability-dashboard-with-defectdojo`, `building-vulnerability-aging-and-sla-tracking` | optional findings-mgmt integration (Phase 4) |

> The corpus is defense-heavy (lots of `detecting-*`, `hunting-*`, `implementing-*` skills). For
> an **offensive** product you'll primarily bind the `performing-*`, `exploiting-*`, `scanning-*`,
> `conducting-*`, `enumerating-*` skills. The defensive skills are still useful for the
> **remediation** sections of reports (map each finding to its detection/hardening skill).

---

## 3. Curation pipeline (do this in Phase 0/1)

The upstream corpus has quality issues you must handle:

1. **Ingest + validate** every `SKILL.md` under `heart/skills/` ; flag entries with:
   - malformed descriptions (e.g. a literal `">-"` leaked as the description — seen in
     `achieving-cmmc-level-2-compliance`),
   - truncated descriptions (several entries cut mid-sentence),
   - missing/invalid frontmatter fields.
2. **Produce `skills-validation-report.md`** — the punch list to fix.
3. **Curate the offensive subset first** (the ~150–200 skills you'll actually bind for scan/
   exploit/report). Don't try to fix all 817 up front.
4. **Write `skill-overrides.yaml`** for corrections; your overrides win at load time.
5. **Write `capability-bindings.yaml`** for the curated subset; unbound skills are advisory-only
   (agent may read them for reasoning but cannot trigger tools through them).
6. **Version-pin** the upstream repo commit you curated against, so upstream churn doesn't
   silently change agent behavior. Re-curate deliberately.

---

## 4. Retrieval & progressive disclosure — DELETED (2026-07-10), design intent only

The semantic-retrieval subsystem (embeddings, top-k cosine, re-rank, progressive body loading) was
built but never wired into the agent and has been removed — deps, artifacts, and `retrieve.py` are
gone. What survives is `skillsvc.ingest`: it emits a JSON index of valid skills
(`name + description + tags + subdomain + sections`). If skill-context lookup is ever actually
needed, add a **keyword/substring match over that JSON index** (a few lines) — do NOT reintroduce
the torch/sentence-transformers pipeline.

---

## 5. Framework mappings → report value

Each skill carries ATT&CK / D3FEND / NIST / (F3) mappings in frontmatter. Propagate them onto
findings so the report can show, per finding:
- **ATT&CK technique** (what the attacker did),
- **CWE / CVE** (the weakness),
- **D3FEND / detection skill** (how the client detects it next time),
- **remediation** (hardening skill).

This cross-framework mapping is the corpus's genuine differentiator — surface it in the report;
it's a real selling point over a plain nuclei scan.

---

## 6. Chaining example (how findings drive next skills)

```
scan.ports → 445/tcp open, SMB, Windows
   → Analyze: candidate MS17-010
   → retrieve skill `exploiting-ms17-010-eternalblue-vulnerability`
   → binding: verify.msf_check (check module ONLY)  [active-scan-safe check]
   → confirmed vulnerable? → GATE (active-exploit/destructive) → human approves? 
        → run exploit with blast-radius limit → capture PoC
        → Finding: severity Critical, ATT&CK T1210, CVE-2017-0144, remediation = patch + SMBv1 disable
```

Every arrow crossing into exploit/destructive passes through scope validation + classification +
the approval gate. That's the whole design in one trace.

---

## 7. What to bind first (Phase 1 shortlist)

Bind exactly these to ship the golden path (all ≤ active-scan, no gates needed):

```
recon:  conducting-external-reconnaissance-with-osint,
        performing-subdomain-enumeration-with-subfinder,
        performing-dns-enumeration-and-zone-transfer,
        analyzing-tls-certificate-transparency-logs
scan:   scanning-network-with-nmap-advanced,
        building-vulnerability-scanning-workflow,
        performing-web-application-scanning-with-nikto
analyze:performing-web-application-vulnerability-triage
report: generating-threat-intelligence-reports
```

Nine skills, ~six capabilities, one report template. That's your entire MVP surface — small,
safe, sellable. Everything else is Phase 2+.
