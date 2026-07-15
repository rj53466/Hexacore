# 07 — Local Hosting, Folder Layout & Zero-Touch Kali Environment

How to run the whole thing locally with as little human intervention as possible. Read the
**honest note in §3 first** — it changes how you should set up the Kali environment.

---

## 1. The one-folder layout (your "brain in a folder" plan)

Everything lives under a single repo folder. The docs I gave you are the **brain**; the code
Antigravity generates sits alongside it; the Kali environment is provisioned from `infra/`.

```
HexaCore/                         ← repo root (name it whatever; keep it consistent)
├── brain/                       ← THESE DOCS (the brain: design + reasoning). Source of truth.
│   ├── README.md
│   ├── 00-REVIEW-AND-FEASIBILITY.md
│   ├── 01-ARCHITECTURE.md
│   ├── 02-IMPLEMENTATION-PLAN.md
│   ├── 03-TASK-BREAKDOWN.md
│   ├── 04-ANTIGRAVITY-PROMPT.md
│   ├── 05-SAFETY-AUTHORIZATION-LEGAL.md
│   ├── 06-SKILLS-INTEGRATION-MAP.md
│   ├── 07-LOCAL-HOSTING-AND-VM.md   ← this file
│   ├── 08-TOOL-INTEGRATION.md
│   ├── 09-TIMELINE-ESTIMATE.md
│   └── 10-PRODUCT-NAMES.md
│
├── heart/                       ← THE SKILLS CORPUS (the heart: 817 playbooks that give it
│                                   knowledge). Cloned from the community repo — see §2.
│
├── .antigravity/
│   └── knowledge/               ← the rules from brain/04 (agents inherit these)
│
├── console/                     ← React+Vite dashboard (the frontend)
├── api/                         ← FastAPI backend
├── agent/                       ← LangGraph orchestrator
├── tools/                       ← capability modules + MCP servers
├── skills/                      ← ingest + validation SERVICE (reads heart/, builds JSON index)
├── reporting/                   ← report engine + templates
│
├── infra/
│   ├── docker-compose.yml       ← brings up the whole platform
│   ├── docker-compose.kali.yml  ← the Kali tool-runner image (RECOMMENDED path)
│   ├── kali/
│   │   └── Dockerfile           ← Kali base + all offensive tools, scripted
│   └── vm/                      ← ONLY if you use the VirtualBox path (§4)
│       ├── Vagrantfile          ← zero-touch Kali box (preferred over ISO)
│       └── place-iso-here/      ← drop kali.iso here only if going the ISO route
│
├── .env.example
├── Makefile                     ← one-command lifecycle (make up / make engage / make down)
└── README.md
```

> **On your "keep the repo name hard / brain folder" point:** the only thing that must stay
> consistent is that the agents can find the docs at `brain/*.md` and the rules at
> `.antigravity/knowledge/`. Reference them by those **relative paths** everywhere so nothing
> breaks if you rename the repo root. Don't hardcode absolute paths.

---

## 2. Getting the skills corpus into `heart/`

```bash
cd <repo-root>
git clone https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git heart
# The ingest service (/skills, per brain/06) reads heart/skills/**/SKILL.md and builds the index.
# Keep heart/LICENSE and heart/NOTICE (Apache-2.0). Pin the commit you curated against.
```

`heart/` is **the heart** — the 817-skill knowledge that powers the brain's decisions. Keep it as
a submodule or pinned clone (not vendored-and-forgotten) so you can re-curate deliberately when
upstream changes.

---

## 3. HONEST NOTE — how to get true "zero human intervention"

You pictured: *ISO in the folder + install VirtualBox → done, no clicks.* That won't be
zero-touch, because a **raw Kali ISO boots an interactive installer** (keyboard, disk, user,
partitioning) and will sit waiting for you. To actually remove human intervention you have three
real options, best first:

| Option | Human clicks to provision | Fits the architecture? | Verdict |
|---|---|---|---|
| **A. Kali Docker image** (`kalilinux/kali-rolling` + a Dockerfile) | **0** | Perfectly — it *is* the sandbox tool-runner | ✅ **Recommended** |
| **B. Kali Vagrant box / prebuilt OVA** | ~0 (Vagrant pulls a ready box, no installer) | Good — VM appliance the platform talks to | ✅ Fine if you want a full VM |
| **C. ISO + preseed/autoinstall file** | 0 *after* you write the autoinstall file | Works, most fiddly | ⚠️ Only if you specifically need ISO |

**Recommendation:** use **Option A** (Kali Docker). It matches the sandboxed tool-execution layer
in `brain/01` exactly, needs zero clicks, is fully scriptable by Antigravity, and gives you the
per-engagement ephemeral isolation the safety model wants. Skip VirtualBox entirely unless you
have a specific reason to want a full VM.

---

## 4. Option A (recommended): Kali Docker tool-runner — fully zero-touch

`infra/kali/Dockerfile` (Antigravity generates the final version; this is the shape). The base
image ships almost nothing — we install exactly what the Platform drives (see `08` for the full
inventory + why):

```dockerfile
FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y --no-install-recommends \
      # recon
      subfinder amass dnsutils whatweb theharvester \
      # scan
      nmap masscan nuclei nikto ffuf feroxbuster gobuster testssl.sh sslscan \
      httpx-toolkit enum4linux-ng \
      # verify/exploit (CLI; run gated + safe-check-first by the platform)
      sqlmap metasploit-framework netexec \
      # supporting
      curl jq git python3 python3-pip pipx \
    && pipx install certipy-ad scoutsuite bloodhound \
    && rm -rf /var/lib/apt/lists/*
# NOTE:
#  - Tools run in EPHEMERAL containers per invocation, egress firewalled to in-scope targets.
#  - OWASP ZAP is NOT installed here — it runs as a separate DAEMON/API service
#    (image: zaproxy/zap-stable) that the platform calls over REST. See infra/docker-compose.yml.
#  - Burp Suite DAST (optional, licensed) also runs as a separate API service, not in this image.
#  - Burp Suite COMMUNITY is GUI-only -> lives in the separate manual-toolbox container
#    (infra/manual-toolbox, noVNC), used only for the gated human manual-testing step. See brain/08.
```

The web DAST engine (OWASP ZAP) and any daemon/API tools (Metasploit RPC, Burp DAST) run as
their own compose services the platform talks to over their APIs — they are not baked into this
CLI image.

Bring the whole platform up:

```bash
cp .env.example .env          # set model profile, secrets
make up                       # docker compose up: postgres, redis, minio, api, agent, console
make kali-build               # builds the Kali tool-runner image once
```

The platform then launches ephemeral Kali containers on demand — one per tool run — and tears
them down after. No VM, no installer, no clicks.

---

## 5. Option B (if you want a real VM): zero-touch Kali via Vagrant

If you prefer a dedicated Kali **VM** as the tool appliance (e.g. for stronger isolation than
Docker, or because you like the VM model), use a **prebuilt box** — not the ISO:

`infra/vm/Vagrantfile`:

```ruby
Vagrant.configure("2") do |config|
  config.vm.box = "kalilinux/rolling"     # prebuilt, no installer, no clicks
  config.vm.provider "virtualbox" do |vb|
    vb.memory = 4096
    vb.cpus   = 2
  end
  config.vm.network "private_network", ip: "192.168.56.20"
  config.vm.provision "shell", inline: <<-SH
    apt-get update && apt-get install -y nmap nuclei subfinder httpx-toolkit ffuf nikto \
      sqlmap metasploit-framework netexec testssl.sh jq
    # start an SSH-key or small API endpoint the platform uses to run scoped tool commands
  SH
end
```

```bash
# one-time: install VirtualBox + Vagrant (scriptable on Kali/Debian host)
sudo apt-get install -y virtualbox vagrant
cd infra/vm && vagrant up      # pulls the box, boots, provisions — no interaction
```

The platform's tool layer then executes scoped commands on this VM (over SSH/agent), still
guarded by the same Scope Validator + gates. **This is more moving parts than Option A** — only
take it if you need a full VM.

### If you truly must use the ISO (Option C)
Put `kali.iso` in `infra/vm/place-iso-here/` and add a **preseed/autoinstall** file so the
installer runs unattended (answers all prompts automatically). Antigravity can generate the
preseed. Without it, the install is interactive and your "no intervention" goal breaks. This is
the most fragile path — prefer A or B.

---

## 6. Running an engagement with minimal intervention

The whole point: you give a command, grant scope + authorization once, and walk away. Human
input is required **only at an approval gate** (exploit/destructive), which surfaces in the
dashboard's Approval Inbox.

```bash
# 1. bring up the platform
make up

# 2. create an engagement from a scope file (domains/CIDRs, ceiling, RoE, authorization)
make engage SCOPE=./engagements/acme-staging.yaml

# 3. open the dashboard
xdg-open http://localhost:5173
```

Then watch the dashboard: phase timeline advances, live command feed streams, severity counts
climb. If `max_action_class` is `active-scan`, it runs start-to-finish **with zero prompts** and
drops a report. If you allowed exploitation, the run pauses only at each gate for your one-click
approval — nothing else.

Example `engagements/acme-staging.yaml`:

```yaml
name: acme-staging
client: ACME Corp
scope:
  allow_domains: ["*.acme-staging.com"]
  allow_cidrs:   ["10.20.30.0/24"]
  deny_list:     ["10.20.30.5"]
  max_action_class: active-scan     # raise to active-exploit to enable gated exploitation
  window: { start: "2026-07-07T00:00Z", end: "2026-07-14T00:00Z" }
authorization:
  authorizer_name: "Jane Doe, CISO ACME"
  document_ref: ./auth/acme-signed-authorization.pdf
autonomy_profile: supervised         # see brain/05 — gates only for exploit/destructive
```

---

## 7. Minimum host requirements (Kali or any Linux host)

- Docker + docker-compose (Option A) **or** VirtualBox + Vagrant (Option B).
- 16 GB RAM comfortable (8 GB works for small engagements); 4+ CPU cores.
- Disk for tool images + evidence store (~20 GB to start).
- If running local models (Ollama) for offensive reasoning: a GPU helps but Qwen-class models run
  on CPU for small tasks; size to your box.
- Outbound network reachable to the in-scope targets only (the platform firewalls tool egress).

---

## 8. One-command lifecycle (`Makefile` targets Antigravity should create)

```
make up          # start platform (compose)
make kali-build  # build Kali tool-runner image (Option A)
make down         # stop everything
make engage SCOPE=…   # start an engagement from a scope file
make kill ENG=…       # trip the kill switch for an engagement
make report ENG=…     # (re)generate the report
make logs             # tail platform logs
```

Bottom line: **Option A (Kali Docker) + `make up` + `make engage` is your zero-touch path.** The
only human moment is approving an exploit at a gate — which is exactly where you *want* a human.
