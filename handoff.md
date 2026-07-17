# HexaCore — Handoff

_Last updated: 2026-07-17. For whoever (or whatever session) picks this up next._

## TL;DR

HexaCore is an authorization-gated pentest platform. **The local Kali build is feature-complete,
tested, and has been driven end-to-end in a real browser against real tools (nmap et al. — this
box already has them installed) — 175 tests pass, 3 skip (optional LangGraph engine).** Pushed to
GitHub, `main` is up to date with `origin/main` (`6786472`).
One command installs and runs the whole thing: `./hexacore.sh`.

Remaining work is **enterprise-only** (production SSO/OIDC, k8s deploy) and not needed for a local
lab. See "Open items" below.

## How to run

```bash
./hexacore.sh          # first run installs everything, then launches; later runs just launch
./hexacore.sh --no-llm # skip the local model
./hexacore.sh --check  # verify environment, don't launch
```
Console + API at `http://<host>:8000`. Login `operator` / the password in `.env`.
Dev loop: `make serve`, `cd console && npm run dev`, `python -m pytest -q`.

## Where things live

| Path | Role |
|---|---|
| `src/hexacore/app/` | FastAPI app (`main.py`), shared state + run orchestration (`state.py`), event bus (`bus.py`), auth. |
| `src/hexacore/safety/` | The safety layer — scope validator, action classifier, approval gate, kill switch, audit. |
| `src/hexacore/engagements/` | Engagement lifecycle + the start gate (no scope+auth = no run). |
| `src/hexacore_tools/` | Capability adapters (`adapters/`), executor, backends (dryrun/local/docker/vm) in `backends/backends.py`. |
| `src/hexacore_agent/` | Scan runner (`runner.py` — `SimpleEngagementRunner`, the deterministic recon→scan→enum→verify→analyze loop actually used in production), skills+LLM (`skill_advisor.py`), CVE enrichment (`analyzer.py`), optional LangGraph engine (`graph.py` — lazy-imports `langgraph`, not a hard dependency). |
| `console/src/` | React console — pages in `pages/`, API client `api.ts`, top bar / nav / toasts in `ui.tsx`. |
| `src/hexacore_reporting/` | HTML/PDF/DOCX report engine. |
| `Heart/` | 636-skill corpus. `skillsvc/ingest.py` builds `skills-index.json` from it. |
| `hexacore.sh` | The one-command installer/runner — builds `console/dist`, and `serve.py`'s FastAPI app serves it as static files on the same port as the API (`:8000`), so one process/one terminal covers both. |

## What changed most recently (this session)

Full browser-based QA pass (real Chromium via Playwright, real backend, real nmap/nikto/sqlmap —
already installed on this box) across every page, plus an owner-only kill switch for the whole
process. Found and root-caused 3 real bugs along the way:

- **Added `STOP` button** (top bar, owner role only) — `POST /system/shutdown` SIGTERMs the whole
  server process, not just an engagement. `console/src/ui.tsx`, `console/src/api.ts`,
  `src/hexacore/app/main.py`.
- **Fixed live-feed reconnect hang** — `run.complete`/`run.error` were published to the live
  WebSocket bus only, never persisted. A client reconnecting after the run already finished
  (refresh, dropped socket, React StrictMode's dev-only double-mount) replayed history but never
  saw the terminal event, so the modal hung on "connecting"/"live" forever. Fixed by routing every
  event — including the terminal ones — through one `AppState._record()` choke point
  (`src/hexacore/app/state.py`) instead of a bare `bus.publish()`.
- **Fixed silent CIDR-only no-op run** — the engagement form's own placeholder tells users to enter
  loopback as an exact `/32`, but `toScope()` in `console/src/pages/EngagementProject.tsx` only
  seeded a scannable host for bare-IP targets, not `/32` CIDR targets. Following the UI's own hint
  produced a scope with authorization but nothing to scan — a silent, findings-free "successful"
  run. A `/32` now seeds that one host too.
- **Fixed `pytest -q` / `make test` being completely broken** — `tests/test_langgraph_agent.py`
  eagerly imported the intentionally-optional `langgraph` package, aborting pytest's entire
  collection so *no* test in the repo ran. Now `pytest.importorskip("langgraph", ...)`.
- **Pushed to GitHub** — `main` is up to date with `origin/main` (see "Open items" below, the old
  push step is done).

Prior session's changes (kept for history):
- **Fixed two boot-blocking files** (`serve.py`, `state.py`) that had literal `` `r`n `` corruption.
- **Built the live-feed** — `LiveFeedModal` + "Live" button in `EngagementProject.tsx` (the WS
  backend existed but nothing consumed it).
- **Purged all frontend dummy data** — findings, approvals, dashboard now read real API data
  (**exception: `Operators` page is still explicitly client-seeded, empty by default** — no
  `/operators` backend endpoint exists; see "Open items").
- **`./hexacore.sh`** — idempotent one-command install/run.
- **Local LLM wired** — Ollama (`qwen2.5:7b`), profile `ollama`; `GET /llm/status` + `LlmPill` health
  on the dashboard.
- **Skills → LLM + skill-driven chaining** — `skill_advisor.py`: matches findings to skills
  (`skills-index.json`), the LLM drafts remediation, and matched skills **select the next gated
  capability** (`next_capabilities` + `CAP_SIGNALS`), emitting `skill.chain` events. Bounded to the
  21 vetted adapters — routing only, never arbitrary command execution.
- **`verify.idor` fix** — was HIGH on any 2xx; now unverified MEDIUM on object endpoints only.
- **Repo hygiene** — deleted ~80 MB junk, added `.gitignore`/`.dockerignore`, `LICENSE` (Apache-2.0),
  `SECURITY.md`, `.github/` templates, and a layman-friendly `README.md`.

## Key decisions / boundaries (don't undo these)

- **Skills route, they never inject.** A matched skill can only pick which *already-vetted, gated*
  capability runs next. Parsing/executing raw commands from skill markdown was explicitly refused —
  it would bypass scope/gate/kill-switch. Keep it that way.
- **Only 21 capabilities are real, gated adapters.** The other ~615 skills are knowledge, used for
  advice + routing, not execution.
- **`local` backend has no egress firewall** — only `docker` does. Scope validation still blocks
  out-of-scope targets before execution.
- **In-memory by default** — set `HEXACORE_DB_URL` to persist engagements across restarts.

## Open items

**Push to GitHub — done.** `main` is at `origin/main` (`6786472`), pushed this session.

**`apt` install + real tool execution — now actually verified**, not just reasoned through: this
session ran on a real Kali box with nmap/nuclei/subfinder/httpx/dnsx/whatweb/testssl/ffuf/
nikto/sqlmap/nxc/certipy-ad/msfconsole/curl all already present, and drove a full real engagement
(loopback target, `active-exploit` ceiling) through nmap → real findings → real approval gates →
approve/deny in the browser. Still watch for apt package-name drift on a fresh box
(`httpx-toolkit`, `netexec`, `certipy-ad`) — `hexacore.sh` warns and continues if one's missing.

**`Operators` page has no nav entry.** The route (`/operators`) works but the bottom nav
(`console/src/ui.tsx`, `NAV` array) doesn't list it — only reachable via the dashboard's "Active
Operators" card. Page is intentionally empty/client-seeded (no backend `/operators` endpoint) per
its own in-code comment, so this is a "decide and wire it up or leave it" call, not a bug to just
patch.

**Tools Library `INSTALL` buttons untested for real.** `POST /tools/{id}/install` genuinely shells
out to `apt-get install` — several map to multi-GB packages (`metasploit-framework` etc). QA this
session deliberately didn't click them to avoid mutating the box; worth a manual smoke test before
relying on it.

**Schedule/monitoring/trend REST endpoints have no console UI at all.** `POST
/engagements/{id}/schedule`, `GET /schedules`, `.../monitoring`, `.../trend` all work server-side
(tested), but nothing in `console/src/pages/` calls them. Pre-existing gap, not new.

**Enterprise (optional, ~3% to "overall 100%"):**
- Production SSO/OIDC (`main.py` endpoints are stubbed; needs a real IdP).
- k8s deploy (`k8s/` manifests exist, never exercised).

**Nice-to-have / tuning:**
- Skill-chaining is intentionally broad — on rich targets many caps get queued. Tighten the
  threshold in `skill_advisor.match_skill` / `next_capabilities` if you want it stricter (e.g. only
  chain on high/critical findings).
- `verify.idor` is a heuristic lead, not a confirmed finding — fine, just know it.
- Change the placeholder passwords in `.env` before any non-local use.
- Approving a gated `verify.*`/`enum.*` action in the Approval Inbox doesn't automatically re-run
  it — a human has to trigger the engagement again. Fine for now, just not fully automatic.

## Gotchas

- `.env` is gitignored — never commit it (JWT secret + passwords live there).
- `console/dist` must be built for the API to serve the UI (`hexacore.sh` does this).
- `skills-index.json` is gitignored and rebuilt by the installer; skill features no-op without it.
- If editing on Windows: don't edit these files through PowerShell string-escaping — that's what
  caused a past `` `r`n `` corruption incident. Use the editor/Bash. (This session was on Kali —
  not applicable here, kept as a warning for whoever's on Windows next.)
- `npm run dev` (`:5173`) runs under React StrictMode, which double-invokes effects in dev only —
  don't be surprised by two WebSocket connections in the server log for one "Live" click. Doesn't
  happen in the production build (`console/dist`, served by `serve.py` on `:8000`). See the
  live-feed reconnect fix above for why this used to actually matter functionally, not just look
  noisy.
- A `target` entered with explicit CIDR notation (e.g. `127.0.0.1/32`) authorizes that scope but
  historically didn't seed it for scanning unless typed as a bare IP — fixed this session for the
  `/32` case specifically. Broader CIDRs (e.g. `/24`) still authorize-only by design; there's no
  seed-side host discovery for a range, only for a single address.
