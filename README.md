# HexaCore

**An authorized penetration-testing platform you run from one command.** Enter your targets in a
web console, and HexaCore runs real security tools against them, streams the results live, explains
each finding, and produces a report — all while a built-in safety layer makes sure it never touches
anything outside the scope you approved.

It runs entirely on your own machine (a Kali Linux box or VM). A local AI model and a library of 636
security "skills" help it decide what to check next and how to fix what it finds. No data leaves your
computer.

---

## ⚠️ Legal & safety — read this first

HexaCore is for **authorized security testing only** — systems you own, or have **explicit written
permission** to test.

- Scanning or attacking systems without permission is **illegal** in most countries.
- You are responsible for staying within your authorization.
- Only run it against a lab you control or an engagement you are contracted for.

HexaCore has guardrails (it refuses targets outside your defined scope and requires you to name an
authorizer before a scan can start), but **the guardrails do not make unauthorized testing legal.**
The responsibility is yours.

---

## What it does, in plain English

1. **You add targets** — an IP, a domain, a URL, or a range — in the web console.
2. **HexaCore scans them** in stages: find what's there (recon) → scan for weaknesses → dig deeper
   on interesting findings → verify. It uses well-known open-source tools (nmap, nuclei, sqlmap,
   and more).
3. **You watch it happen live.** A real-time feed shows every command and every finding as they
   come in.
4. **It explains the findings.** A local AI model, guided by a 636-skill security knowledge base,
   suggests how to fix each issue and what to safely check next.
5. **It writes a report** — HTML, PDF, or Word — you can hand to a client or a team.

Nothing runs against a target you didn't approve, and any high-risk action pauses for your explicit
approval.

---

## What you need

- A **Kali Linux** (or Debian-based) machine or VM — this is where the security tools live.
- **Root or sudo** access.
- About **8 GB RAM** (for the local AI model) and **~15 GB free disk**.
- **Internet access** the first time only (to download tools and the AI model). After that it runs
  fully offline.

Don't have Kali? Install it free in VirtualBox/VMware from https://www.kali.org/get-kali/.

---

## Install & run — one command

```bash
# 1. Get the project onto your Kali machine
git clone https://github.com/<your-username>/hexacore.git
cd hexacore

# 2. Run it. That's the whole install.
chmod +x hexacore.sh
./hexacore.sh
```

The first run installs everything for you — Python libraries, the security tools, the local AI model
(`qwen2.5:7b`), and it builds the web console — then starts the server. **This takes 15–30 minutes
the first time** (the AI model alone is ~4.7 GB).

**Every run after that is instant** — the same `./hexacore.sh` checks what's already installed and
goes straight to launching.

When it finishes, open the console in a browser:

```
http://localhost:8000
```

If Kali is a VM and you're on the host machine, use the VM's IP instead of `localhost`
(run `ip a` inside Kali to find it).

### Options

| Command | What it does |
|---|---|
| `./hexacore.sh` | Install anything missing, then launch. |
| `./hexacore.sh --no-llm` | Skip the AI model (scanner still works, just no AI suggestions). |
| `./hexacore.sh --check` | Verify the setup without launching. |

---

## First use — a 60-second walkthrough

1. **Change the default passwords.** Open the `.env` file the installer created and set the three
   `HEXACORE_*_PASSWORD` lines to your own values. Re-run `./hexacore.sh` (it keeps your settings and
   just relaunches).
2. **Log in** at `http://localhost:8000` as user `operator` with the password you just set.
3. **Create an engagement:** click *Add Target*, type your target(s), and **fill in the Authorizer
   name** — this is required; it's your confirmation that you're allowed to test these targets.
4. **Click "Live."** The scan starts and you watch the live feed. Findings appear on the *Findings*
   page; anything needing sign-off appears in the *Approvals* inbox.
5. **Download the report** from the engagement when it's done.

---

## The AI model & the skills — what they actually do

- **Local AI model (Ollama + `qwen2.5:7b`).** Runs on your machine, no internet. It prioritizes what
  to scan first and writes plain-English remediation advice for findings. If you skip it
  (`--no-llm`), the scanner still works — you just don't get the AI write-ups. The dashboard shows a
  small **LLM health** indicator (green = ready, red = the model isn't running).
- **The 636 skills (`Heart/`).** A library of security-technique write-ups (tagged with industry
  frameworks like MITRE ATT&CK). HexaCore matches each finding to the most relevant skill, uses it to
  guide the AI's advice, and — importantly — lets the skill **decide the next step**: which
  already-approved tool to run next. A skill can *choose* the next action, but it can **never** run
  an arbitrary command. Every action still goes through the safety layer.

---

## How it stays safe

Four rules are enforced in code, not just documented:

1. **Deny by default** — nothing runs against a target your scope doesn't explicitly allow.
2. **No scope, no start** — an engagement can't run without a defined scope *and* a named
   authorization bound to it.
3. **High-risk actions pause for you** — anything exploit-class waits for your explicit approval.
4. **Kill switch + audit log** — stop everything instantly; every action is recorded, append-only.

---

## Configuration (`.env`)

The installer writes a `.env` for you. The values worth knowing:

| Setting | Meaning |
|---|---|
| `HEXACORE_RUNNER_BACKEND` | `local` = run tools on this Kali host (default). Also `docker` / `vm`. |
| `HEXACORE_MODEL_PROFILE` | `ollama` = use the local AI. `deterministic` = no AI. |
| `HEXACORE_OLLAMA_MODEL` | Which AI model (default `qwen2.5:7b`). |
| `HEXACORE_*_PASSWORD` | Login passwords for owner / operator / viewer. **Change these.** |
| `HEXACORE_DB_URL` | Leave unset = fresh each restart. Set it to keep engagement history. |

Your `.env` is **never committed to git** (it's in `.gitignore`) — your passwords and secret key stay
on your machine.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| A tool won't install | Package names vary by Kali version (`httpx-toolkit`, `netexec`, `certipy-ad`). The installer warns and continues — install the missing one with `apt install <name>` and re-run. |
| "LLM · Ollama down" on the dashboard | Start it: `ollama serve &`, then `ollama pull qwen2.5:7b`. Or run with `--no-llm`. |
| Scan finds nothing | Make sure the tools are installed (`./hexacore.sh --check`) and your target is actually reachable and in scope. |
| Can't reach the console from my host | Use the Kali VM's IP, not `localhost`, and make sure the VM network allows it. |
| Not enough RAM for the AI | Use a smaller model: set `HEXACORE_OLLAMA_MODEL=llama3.2:3b` in `.env`, or run `--no-llm`. |

---

## Project layout

| Folder | What's inside |
|---|---|
| `api/` | The server + the safety layer (scope, gates, kill switch, audit). |
| `tools/` | The tool adapters and the sandboxed executor. |
| `agent/` | The scan runner, skill matching, and AI routing. |
| `console/` | The web dashboard (React). |
| `reporting/` | The report generator (HTML / PDF / Word). |
| `Heart/` | The 636-skill security knowledge base. |
| `Brain/` | Design documents (how and why it's built this way). |
| `hexacore.sh` | The one-command installer/runner. |

---

## For developers

```bash
python -m pytest -q                 # run the test suite (180 tests)
make serve                          # API + WebSocket on :8000
cd console && npm run dev           # console dev server on :5173
```

---

## License

Choose a license before publishing (e.g. Apache-2.0). The bundled skills corpus in `Heart/` is
Apache-2.0 — keep its `LICENSE`/`NOTICE` intact. Do not brand this as "Anthropic".
