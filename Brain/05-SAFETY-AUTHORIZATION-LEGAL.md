# 05 — Safety, Authorization & Legal Layer

**Read this before writing any tool code.** This is the layer that turns "a script that attacks
things" into "a product a company can sell." It is architectural, not a setting.

> Not legal advice. You run a security company (Sahasrakshi) — have your own counsel review the
> authorization templates, ToS, and data-retention terms before commercial use. This doc gives
> you the engineering + process scaffolding.

---

## 1. The core principle

An autonomous system that scans and exploits is **only lawful against systems the operator owns
or has explicit written permission to test.** The Platform must make it *structurally impossible*
to act outside that boundary, and must produce evidence that it stayed inside it.

Three objects enforce this, and all three are required before anything runs:

1. **Scope** — the technical boundary (what may be touched).
2. **Authorization** — the legal boundary (proof you're allowed to touch it).
3. **Rules of Engagement (RoE)** — the behavioral boundary (how, when, how hard).

---

## 2. Scope object

```
Scope {
  allow_domains:   ["*.acme-staging.com", "portal.acme-test.com"]
  allow_cidrs:     ["10.20.30.0/24", "203.0.113.0/28"]
  deny_list:       ["10.20.30.5", "prod.acme.com"]   # deny ALWAYS wins
  max_action_class: active-scan                       # ceiling for this engagement
  window_start / window_end                           # allowed testing window
  rate_limits:      { requests_per_sec, concurrency }
  off_limits:       ["DoS", "social-engineering", "data-destruction"]
}
```

### Scope Validator (in-path, wraps every tool call)
- Resolve the intended target (URL→host→IP; CIDR membership; domain suffix match with explicit
  wildcard handling).
- **Deny by default.** Allow only if it matches an `allow_*` entry AND is not in `deny_list`.
- Guard against: DNS rebinding (re-resolve at execution, not just at plan time), IP/host mismatch,
  redirects to out-of-scope hosts, IPv6 bypass, punycode/IDN tricks, link-local/metadata IPs
  (169.254.169.254 etc. off-limits unless explicitly in scope).
- Enforced **twice**: at planning (reject the task) and at execution (final check before the
  packet leaves the sandbox). Egress firewall on the container is the third line.

---

## 3. Authorization object

```
Authorization {
  authorizer_name, authorizer_email, authorizer_title
  method:  click-sign | uploaded-document | contract-reference
  document_ref:  <object-store key of signed permission / SoW>
  signed_at, verified_by
  scope_hash:  <hash of the Scope at time of signing>   # scope can't silently change
}
```

- **No Authorization → engagement cannot leave `scoped` state.** The API enforces this; it is not
  a UI nicety.
- If Scope changes after authorization (hash mismatch), the engagement is **frozen** until
  re-authorized. This prevents "authorized for the test box, quietly expanded to prod."
- Store the signed document (SoW, penetration-testing authorization letter, or click-through
  attestation) in the evidence store, referenced from the engagement.

### Minimum authorization letter fields (template you ship)
Client legal entity · authorized signatory + title · exact in-scope assets (domains/IPs) ·
explicit exclusions · permitted action classes (scan-only vs exploitation) · testing window ·
emergency contact + stop procedure · liability/indemnity clause · data-handling terms · date +
signature.

---

## 4. Action classification & gating

Every intended tool action is classified before it runs:

| Class | Examples | Gate |
|---|---|---|
| `passive` | OSINT, CT logs, WHOIS, passive DNS | none |
| `active-scan` | port scan, service detection, web vuln scan (nuclei/nikto), directory brute | none *if* within `max_action_class`; audited |
| `active-exploit` | sqlmap exploitation, MSF exploit module, ADCS abuse, IDOR/SSRF confirmation with impact | **human approval required** + scope must permit |
| `destructive` | anything that modifies/deletes data, DoS, account lockout risk, mass exploitation | **default OFF**; requires explicit scope opt-in + per-action approval + limits |

### Approval Gate (human-in-the-loop)
- Implemented as a LangGraph **interrupt**: the run pauses, an Approval record is created, the
  console Approval Inbox shows the operator: **target, capability, skill invoked, parameters,
  expected impact, evidence-so-far**.
- Operator options: **Approve**, **Deny**, **Approve-with-limit** (e.g. single target, read-only,
  rate cap), **Abort engagement**.
- The agent **cannot** self-approve or route around the gate — it's a control-flow interrupt, not
  a prompt the model can talk its way past.
- Approvals are time-boxed and logged with who/when/what-limits.

### Verify-don't-detonate default
For exploit-class capabilities the first action is always a **safe check**:
- Metasploit: `check` module before `exploit`.
- sqlmap: detection/enumeration flags before data extraction.
- ADCS: `find` before `abuse`; AD: enumerate before Kerberoast/relay.
Exploitation proceeds only after (a) the check confirms, (b) scope permits it, (c) a gate is
approved.

---

## 4b. Autonomy profiles (how "hands-off" a run is)

You want minimal human intervention — give a command, walk away, only get pulled in when it truly
matters. That's exactly what the gates give you: **everything up to and including active scanning
runs unattended; only exploit/destructive actions pause for you.** An engagement picks an
autonomy profile:

| Profile | Runs unattended | Pauses for approval | Use when |
|---|---|---|---|
| `scan-only` | passive + active-scan (the whole run) | never (ceiling is active-scan) | recon+scan+report engagements — **fully zero-touch** |
| `supervised` *(recommended)* | passive + active-scan | active-exploit **and** destructive | you want exploitation but a human okays each one |
| `assisted` | passive + active-scan + confirmed low-risk verifies | destructive only | experienced operator, tighter loop, more gates auto-approved within preset limits |
| `autonomous-exploit` | *(discouraged)* | destructive only | **not recommended commercially** — see below |

**Do not offer or run `autonomous-exploit` for client work.** Fully unattended exploitation
removes the human judgment that both the law and your professional liability assume is present. A
gate that fires a few times per engagement and takes one click is a feature, not friction — it's
what makes the run defensible. Keep `supervised` as the default; use `scan-only` for the truly
walk-away engagements.

The dashboard's **Approval Inbox is the single human-intervention surface.** Under `scan-only`
it stays empty the entire run. Under `supervised` it lights up only at exploit/destructive steps.
Everything else — recon, scanning, analysis, reporting — happens without you.

---

## 5. Rules of Engagement (RoE)

Stored on the Scope, enforced by the agent + tool layer:
- Testing window (no actions outside `window_start..window_end`).
- Rate limits and concurrency caps (avoid taking prod down).
- Off-limits techniques (DoS, social engineering, physical, data destruction) unless explicitly
  authorized.
- Emergency stop procedure + client emergency contact.
- Handling of discovered sensitive data (PII, secrets) — capture *minimum necessary* proof,
  never exfiltrate real data, redact in reports.

---

## 6. Kill switch

- **Global** (stop all engagements) and **per-engagement** flags.
- Effect: signal workers to stop, terminate running tool containers, mark engagement `paused`,
  audit the event.
- Reachable from console (big red button, confirm dialog) and API.
- Must work even mid-tool-run (container termination), not just between steps.

---

## 7. Sandbox & egress containment

- Each tool runs in an **ephemeral container** with:
  - No mount of host filesystem/network namespace.
  - **Egress firewall allowing only in-scope targets** (belt-and-suspenders with Scope Validator).
  - CPU/mem/time limits; killed on timeout.
  - Read-only tool image; writable scratch only.
- CI test (`H3`): prove a container cannot reach an out-of-scope host or host-metadata endpoint.

---

## 8. Audit & evidence (protects the client *and* you)

- **Append-only AuditEvent** for every: scope decision, classification, gate request/decision,
  tool run (target, params, exit code), kill-switch event.
- Evidence store retains raw output, PoC req/resp, screenshots — referenced from findings.
- Retention policy configurable; support client-requested deletion; encrypt at rest;
  EU-hostable region (you scoped this).
- This audit trail is your defense if a client ever disputes what was touched. Antigravity's own
  build artifacts double as a dev-time audit trail for how the safety code was built.

---

## 9. Data handling

- Treat all findings and captured evidence as **client-confidential**.
- Never store real exfiltrated data — capture *proof of access*, not the data itself, and redact.
- Secrets discovered (API keys, creds) → flagged, redacted in reports, secure-deleted after
  engagement per policy.
- Access to an engagement's data limited by RBAC to that engagement's team.

---

## 10. Model behavior safeguards

- The agent **selects and parameterizes typed capabilities**; it never emits freeform exploit
  code that gets executed. This bounds what "the AI decided to do."
- Offensive-reasoning steps can use a local model (Ollama) to avoid hosted-model refusals, but
  the *actions* are still constrained to the typed, gated capability set — the model can't invent
  a new attack path outside the capabilities you shipped.
- Prompt-injection defense: content pulled from targets (web pages, banners) is treated as
  untrusted data, never as instructions to the agent. The planner ignores instructions embedded
  in scanned content.

---

## 11. Legal/commercial checklist (with your counsel)

- [ ] Penetration-testing authorization letter template.
- [ ] Statement of Work template (scope, exclusions, window, deliverables).
- [ ] Terms of Service + acceptable-use policy for the platform.
- [ ] Liability / indemnification clauses.
- [ ] Data-processing agreement (esp. for EU clients / GDPR).
- [ ] Incident/emergency-stop clause + contacts.
- [ ] Insurance (professional liability / E&O for security testing).
- [ ] Clear "authorized use only" gating in-product (attestation at engagement creation).

---

## 12. One-line summary

**No Scope + no Authorization → nothing runs. Anything beyond active scanning → a human approves
it first. Everything that happens → is logged as evidence. Default is verify, not detonate.**
