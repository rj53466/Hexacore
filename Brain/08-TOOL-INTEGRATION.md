# 08 — Tool Inventory & Platform Integration

How the security tools live inside the Kali Docker environment, and exactly how the Platform
drives them. This is the "hands" layer from `01`, documented tool-by-tool.

---

## 1. Does the Kali Docker image come with tools? — No, and that's good

`kalilinux/kali-rolling` is a **minimal base image** — it ships almost nothing. You install what
you need with `apt`. This is deliberate and better for us: we install *only* the tools the
Platform actually drives, keeping the image small, auditable, and fast to rebuild. (The giant
`kali-linux-everything` metapackage is multi-GB and full of GUI apps we don't want in an
automation container.)

So: **the tools are installed by our `infra/kali/Dockerfile`, not "already there."** The full
list is in §5, and the Dockerfile is in `07`.

---

## 2. The core idea: every tool is a "capability adapter"

The Platform never lets the LLM type raw shell at a target. Each tool is wrapped in a **capability
adapter** with a fixed contract:

```
CapabilityAdapter
  action_class     : passive | active-scan | active-exploit | destructive
  input_schema     : typed params (target, options) — validated
  build_command()  : params -> exact argv (or API call)   [target must pass Scope Validator]
  run(sandbox)     : execute in ephemeral Kali container / call the tool's API
  parse(raw)       : tool-specific -> normalized JSON (NEVER hand raw text to the agent alone)
  normalize()      : -> Finding schema (severity, cvss, cwe, cve, attack, evidence)
```

The agent selects an adapter and fills its typed params. The adapter does the rest. This is what
"my tool reacts with this" means concretely: **the agent picks *which* capability and *what*
target/params; the adapter builds the command, the sandbox runs it, the parser turns output into
structured findings.** The model orchestrates; it never authors exploit strings.

### Two execution patterns
1. **CLI tools** → run in an **ephemeral container** (`docker run --rm` from the Kali image) per
   invocation, with egress firewalled to the in-scope target. Capture stdout + output files,
   parse, tear down. This is 90% of the tools.
2. **Daemon / API tools** (OWASP ZAP, Metasploit RPC, Burp Suite DAST/Pro) → run as a
   **long-lived service**; the Platform holds a client and calls the tool's API (start scan →
   poll status → pull structured results). Better for stateful scanners.

Everything a tool emits is normalized into the same **Finding schema**, then **deduplicated
across tools** (e.g. nuclei and ZAP both flag a missing security header → one finding, two
sources).

---

## 3. Machine-readable output is the whole game

Adapters rely on each tool's structured-output mode, never screen-scraping human text:

| Tool | Structured output flag / mode |
|---|---|
| nmap | `-oX` (XML) → parse to ports/services/scripts |
| nuclei | `-jsonl` (one JSON finding per line) |
| httpx | `-json` |
| subfinder | `-oJ` / `-json` |
| whatweb | `--log-json` |
| testssl.sh | `--jsonfile` |
| nikto | `-Format json -output` |
| ffuf | `-of json` |
| feroxbuster | `--json` |
| sqlmap | `--batch --output-dir` (parse results dir / `-x` XML) |
| OWASP ZAP | REST API + `-r`/JSON/SARIF report from `zap-*.py` |
| Metasploit | msgrpc/JSON-RPC (`msfrpcd`) responses |
| netexec (nxc) | `--json` / SQLite results db |
| BloodHound collectors | JSON zip → ingested to Neo4j/BHCE |
| Certipy | JSON / text (parse) |
| ScoutSuite | JSON results file |
| CloudFox | JSON + loot files |

If a tool has no machine-readable mode, we don't put it in the auto-loop — we wrap it as a manual
station (see §6).

---

## 4. Web DAST: ZAP vs Burp — read this before choosing

Web application scanning is the "main chunk" you flagged. Here's the honest layout so it isn't
left aside:

| Option | Automatable? | Cost | Role in the Platform |
|---|---|---|---|
| **OWASP ZAP** | ✅ Built for it — headless daemon, REST API, Docker, Automation Framework (YAML), `zap-baseline/full/api.py`, JSON/HTML/SARIF | Free (open source) | **Default automated web DAST** in the pipeline. |
| **Burp Suite DAST** (ex-Enterprise) | ✅ GraphQL (preferred) + REST API, CI-native, scheduled scans | ~$9k+/yr, scoped quote | **Premium scanner capability** — same as ZAP adapter but calls Burp DAST API. Offer per-engagement/client. |
| **Burp Suite Professional** | ⚠️ Desktop-first; has REST API + headless mode but "not a drop-in CI scanner" (PortSwigger) | ~$449–499/user/yr | Optional — drive Burp's engine via its REST API if you already own Pro seats. More DIY. |
| **Burp Suite Community** | ❌ GUI only, no API, no scanner automation | Free | **Manual station only** (see §6) — human-in-the-loop for business-logic/IDOR/auth bugs DAST misses. |

**Recommendation:**
- **Automated web DAST = OWASP ZAP** (adapter = `scan.web_dast_zap`). Free, API-native, fits the
  daemon pattern perfectly.
- **Burp Suite DAST** = an *optional premium* `scan.web_dast_burp` adapter (GraphQL API) for
  clients who specifically want Burp's engine/false-positive profile. Same adapter contract,
  different backend.
- **Burp Community** = the **manual toolbox** for the human phase — the things no DAST catches
  (complex authorization, business logic, chained bugs). This is where Burp genuinely earns its
  keep in 2026; automation can't replace it, and pretending otherwise would be dishonest.

This way Burp is in the list three ways, and you're not trying to automate a GUI that can't be
automated.

---

## 5. Full tool inventory (what goes in the Kali image / as services)

Grouped by pipeline phase. `class` = default action class; **[G]** = gated (needs approval).

### Recon — passive (no gate)
| Capability | Tool(s) | Install | Drive |
|---|---|---|---|
| `recon.subdomains` | subfinder, amass (passive) | apt | CLI ephemeral |
| `recon.dns` | dnsx, host, dig | apt | CLI |
| `recon.http_probe` | httpx | apt | CLI |
| `recon.tech` | whatweb | apt | CLI |
| `recon.ct_logs` | crt.sh (curl) | — | HTTP |
| `recon.osint` | theHarvester, SpiderFoot (CLI) | apt/pipx | CLI |

### Scan — active (`active-scan`)
| Capability | Tool(s) | Install | Drive |
|---|---|---|---|
| `scan.ports` | nmap, masscan | apt | CLI |
| `scan.tls` | testssl.sh, sslscan | apt | CLI |
| `scan.web_nuclei` | nuclei (+ curated templates) | apt | CLI |
| `scan.web_nikto` | nikto | apt | CLI |
| `scan.web_dir` | ffuf, feroxbuster, gobuster | apt | CLI |
| `scan.web_dast_zap` | **OWASP ZAP** | Docker svc | **REST API / daemon** |
| `scan.web_dast_burp` *(optional)* | **Burp Suite DAST** | server + license | **GraphQL API** |
| `scan.smb_enum` | enum4linux-ng | apt | CLI |

### Verify / Exploit (`active-exploit`, all **[G]**, verify-first)
| Capability | Tool(s) | Install | Drive |
|---|---|---|---|
| `verify.web_sqli` **[G]** | sqlmap (detection-only default) | apt | CLI |
| `verify.msf_check` **[G]** | Metasploit (`check` modules) | apt | **msfrpcd RPC** |
| `verify.idor` / `verify.ssrf` **[G]** | custom evidence verifiers | — | CLI/HTTP |
| `verify.web_manual` **[G]** | **Burp Community** manual station | apt (GUI) | **human via VNC** (§6) |

### AD / Identity (`active-scan`→`exploit`, mostly **[G]**)
| Capability | Tool(s) | Install | Drive |
|---|---|---|---|
| `enum.bloodhound` | BloodHound-CE + bloodhound-python | apt/pipx | CLI → BHCE |
| `enum.netexec` **[G]** | netexec (nxc) | apt/pipx | CLI |
| `verify.adcs_find` **[G]** | Certipy (`find`) | pipx | CLI |

### Cloud (`active-scan`→`exploit`, **[G]** for write)
| Capability | Tool(s) | Install | Drive |
|---|---|---|---|
| `cloud.scout` | ScoutSuite | pipx | CLI |
| `cloud.enum` | CloudFox | binary | CLI |
| `cloud.exploit` **[G]** | Pacu (AWS) | pipx | CLI |

> All exploit-class capabilities default to **safe check** first (Metasploit `check`, sqlmap
> detection, Certipy `find`) — see `05`. Real exploitation needs an approved gate **and** a scope
> whose `max_action_class` permits it.

---

## 6. GUI tools & the manual station (Burp Community, browser)

Automation containers are **headless**. GUI tools can't and shouldn't live in the auto-loop.
For the human-in-the-loop manual phase, the Platform provides an **optional separate container**:

```
infra/manual-toolbox/   (kali-linux-headless + kali-desktop-xfce + Burp Community + Firefox
                         + a noVNC/websockify server)
```

- Launched **only** when the agent reaches a `verify.web_manual` step (or the operator requests
  it), scoped to that engagement, egress-firewalled to in-scope targets.
- The operator opens it in the browser (noVNC), does manual Burp testing (auth logic, IDOR/BOLA,
  chained bugs), then records confirmed findings back into the Platform (small importer or manual
  entry). These become normal Findings with evidence, feeding the same report.
- This is a **gated, human step** — it does not run unattended, by design. It's the honest place
  for Burp Community's strengths.

---

## 7. How a scan result becomes a finding (end-to-end, concrete)

```
agent: objective "scan web app portal.acme-staging.com for known vulns"
  -> planner: queues scan.web_nuclei  (params: target=https://portal.acme-staging.com)
  -> execute -> CapabilityExecutor safety check: class=active-scan, in scope? YES, ceiling? YES -> no approval
  -> runs: docker run --rm kali-tools nuclei -u https://portal... -jsonl -severity ...
  -> Parser: JSONL -> [{template, severity, matched, cwe, ...}, ...]
  -> Normalize: -> Finding{title, severity=High, cwe, evidence_ref=raw.jsonl, attack=Txxxx}
  -> Dedup: same issue also seen by scan.web_dast_zap? merge, keep both sources
  -> emit finding.created  -> dashboard severity tile (High +1) + findings panel
```

Every arrow that would cross into exploit/destructive passes through the approval gate first.
That single trace is the whole interaction contract between the Platform ("my tool") and the
security tools.

---

## 8. Adding a new tool later (the extension point)

To add any tool, implement one adapter:
1. Declare `action_class` + typed `input_schema`.
2. `build_command()` (CLI argv or API call) — target must go through Scope Validator.
3. Pick execution pattern: ephemeral CLI container **or** daemon/API service.
4. `parse()` its machine-readable output → Finding schema.
5. Register it as an MCP capability + add a `capability-bindings.yaml` entry (which skills use it).
6. Add a unit test (parse fixtures) + a scope-denial test.

No agent-loop changes needed — the adapter contract is the stable interface. That's how you grow
from the Phase-1 shortlist to full coverage without rewrites.
