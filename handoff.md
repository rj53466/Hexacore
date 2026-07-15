# HexaCore — Handoff

_Last updated: 2026-07-15. For whoever (or whatever session) picks this up next._

## TL;DR

HexaCore is an authorization-gated pentest platform. **The local Kali build is feature-complete
(100%) and tested — 180 tests pass.** It's committed to git on `main` (not yet pushed to GitHub).
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
| `api/hexacore/app/` | FastAPI app (`main.py`), shared state + run orchestration (`state.py`), event bus, auth. |
| `api/hexacore/safety/` | The safety layer — scope validator, action classifier, approval gate, kill switch, audit. |
| `api/hexacore/engagements/` | Engagement lifecycle + the start gate (no scope+auth = no run). |
| `tools/hexacore_tools/` | Capability adapters (`adapters/`), executor (`runner.py`), backends (dryrun/local/docker/vm). |
| `agent/hexacore_agent/` | Scan runner (`runner.py`), skills+LLM (`skill_advisor.py`), CVE enrichment (`analyzer.py`), LangGraph engine (`graph.py`). |
| `console/src/` | React console — pages in `pages/`, API client `api.ts`. |
| `reporting/` | HTML/PDF/DOCX report engine. |
| `Heart/` | 636-skill corpus. `skills/skillsvc/ingest.py` builds `skills-index.json` from it. |
| `hexacore.sh` | The one-command installer/runner. |

## What changed most recently (this session)

- **Fixed two boot-blocking files** (`serve.py`, `state.py`) that had literal `` `r`n `` corruption.
- **Built the missing live-feed** — `LiveFeedModal` + "Live" button in `EngagementProject.tsx`
  (the WS backend existed but nothing consumed it).
- **Purged all frontend dummy data** — findings, approvals, dashboard now read real API data.
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

**Push to GitHub (immediate, human):** repo is committed on `main`; `gh` isn't installed in the dev
env, so push manually:
```bash
git remote add origin https://github.com/<user>/hexacore.git && git push -u origin main
```
Then replace `<your-username>` in the README clone URL. Recommend a **private** repo.

**Not verified from the dev box (Windows):** the actual `apt` install of tools and the Ollama model
pull have only been reasoned through, not run. First real run should be on a Kali VM — watch for apt
package-name drift (`httpx-toolkit`, `netexec`, `certipy-ad`); the script warns and continues.

**Enterprise (optional, ~3% to "overall 100%"):**
- Production SSO/OIDC (`main.py` endpoints are stubbed; needs a real IdP).
- k8s deploy (`k8s/` manifests exist, never exercised).

**Nice-to-have / tuning:**
- Skill-chaining is intentionally broad — on rich targets many caps get queued. Tighten the
  threshold in `skill_advisor.match_skill` / `next_capabilities` if you want it stricter (e.g. only
  chain on high/critical findings).
- `verify.idor` is a heuristic lead, not a confirmed finding — fine, just know it.
- Change the placeholder passwords in `.env` before any non-local use.

## Gotchas

- `.env` is gitignored — never commit it (JWT secret + passwords live there).
- `console/dist` must be built for the API to serve the UI (`hexacore.sh` does this).
- `skills-index.json` is gitignored and rebuilt by the installer; skill features no-op without it.
- Windows dev only: don't edit these files through PowerShell string-escaping — that's what caused
  the `` `r`n `` corruption. Use the editor/Bash.
