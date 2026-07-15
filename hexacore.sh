#!/usr/bin/env bash
# HexaCore — one command to install everything and run. Idempotent.
#
#   ./hexacore.sh          first run: install deps, tools, Ollama+model, build console, then launch.
#                          later runs: check what's present, skip what's done, launch.
#   ./hexacore.sh --no-llm run without installing/using a local LLM (scanner stays deterministic).
#   ./hexacore.sh --check  verify the environment and exit (install nothing, don't launch).
#
# Target: Kali / Debian-based Linux, run as root (or a sudo user). Safe to re-run any number of times.
set -euo pipefail

# ---- config (override via env) --------------------------------------------
MODEL="${HEXACORE_OLLAMA_MODEL:-qwen2.5:7b}"
PORT="${HEXACORE_PORT:-8000}"
HOST="${HEXACORE_HOST:-0.0.0.0}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$ROOT/.venv"
USE_LLM=1; CHECK_ONLY=0
for a in "$@"; do
  case "$a" in
    --no-llm) USE_LLM=0 ;;
    --check)  CHECK_ONLY=1 ;;
    *) echo "unknown option: $a"; exit 2 ;;
  esac
done

# ---- pretty logging -------------------------------------------------------
c(){ printf '\033[%sm%s\033[0m' "$1" "$2"; }
step(){ echo; echo "$(c '1;36' "▸ $1")"; }
ok(){   echo "  $(c '1;32' '✓') $1"; }
warn(){ echo "  $(c '1;33' '!') $1"; }
die(){  echo "  $(c '1;31' '✗') $1" >&2; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }

# sudo prefix only when not already root
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
apt_install(){ $SUDO apt-get install -y "$@" >/dev/null 2>&1; }

# ---- 1. preflight ---------------------------------------------------------
step "Preflight"
[ "$(uname -s)" = "Linux" ] || die "run this on your Kali/Linux host (found $(uname -s))."
have apt-get || die "apt-get not found — this installer targets Debian/Kali."
have python3 || { warn "python3 missing, installing"; $SUDO apt-get update -qq && apt_install python3 python3-venv python3-pip; }
ok "Linux + apt + python3 present"
APT_UPDATED=0
ensure_apt_updated(){ [ "$APT_UPDATED" -eq 0 ] && { $SUDO apt-get update -qq || true; APT_UPDATED=1; }; }

# ---- 2. python env + deps -------------------------------------------------
step "Python environment"
if [ ! -d "$VENV" ]; then python3 -m venv "$VENV"; ok "created .venv"; else ok ".venv present"; fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
REQ_HASH="$(sha256sum "$ROOT/requirements.txt" | cut -d' ' -f1)"
MARKER="$VENV/.deps-$REQ_HASH"
if [ ! -f "$MARKER" ]; then
  python -m pip install -q --upgrade pip
  python -m pip install -q -r "$ROOT/requirements.txt"
  rm -f "$VENV"/.deps-* ; touch "$MARKER"
  ok "installed Python dependencies"
else
  ok "Python dependencies up to date"
fi

# ---- 3. pentest tools -----------------------------------------------------
step "Pentest tools"
# binary -> apt package (bloodhound-python comes via pip; kept out of this map)
declare -A TOOL_PKG=(
  [nmap]=nmap [nuclei]=nuclei [subfinder]=subfinder [httpx]=httpx-toolkit [dnsx]=dnsx
  [whatweb]=whatweb [ffuf]=ffuf [nikto]=nikto [sqlmap]=sqlmap [curl]=curl
  [testssl.sh]=testssl.sh [nxc]=netexec [certipy]=certipy-ad [msfconsole]=metasploit-framework
)
missing=()
for bin in "${!TOOL_PKG[@]}"; do have "$bin" || missing+=("$bin"); done
if [ "${#missing[@]}" -eq 0 ]; then
  ok "all ${#TOOL_PKG[@]} tools present"
else
  warn "installing ${#missing[@]} missing: ${missing[*]}"
  ensure_apt_updated
  for bin in "${missing[@]}"; do
    if apt_install "${TOOL_PKG[$bin]}"; then ok "installed $bin"; else warn "could not install $bin (${TOOL_PKG[$bin]}) — install manually"; fi
  done
fi
have bloodhound-python || python -m pip install -q bloodhound >/dev/null 2>&1 || warn "bloodhound-python optional, skipped"

# ---- 4. console build -----------------------------------------------------
step "Console (web UI)"
if [ ! -d "$ROOT/console/dist" ]; then
  have npm || { warn "installing nodejs+npm"; ensure_apt_updated; apt_install nodejs npm; }
  ( cd "$ROOT/console" && npm install --silent && npm run build --silent )
  ok "built console/dist"
else
  ok "console already built (delete console/dist to rebuild)"
fi

# ---- 5. local LLM ---------------------------------------------------------
if [ "$USE_LLM" -eq 1 ]; then
  step "Local LLM (Ollama · $MODEL)"
  have ollama || { warn "installing Ollama"; curl -fsSL https://ollama.com/install.sh | sh; }
  # ensure the daemon is up
  if ! curl -fsS "http://localhost:11434/api/tags" >/dev/null 2>&1; then
    ( ollama serve >/tmp/ollama.log 2>&1 & )
    for _ in $(seq 1 20); do curl -fsS http://localhost:11434/api/tags >/dev/null 2>&1 && break; sleep 1; done
  fi
  if ollama list 2>/dev/null | grep -q "^${MODEL%%:*}"; then ok "$MODEL already pulled"
  else warn "pulling $MODEL (first time, a few GB)"; ollama pull "$MODEL" && ok "$MODEL ready"; fi
  LLM_PROFILE="ollama"
else
  step "Local LLM"; ok "skipped (--no-llm) — scanner stays deterministic"; LLM_PROFILE="deterministic"
fi

# ---- 6. skills index (for skill-guided enrichment) ------------------------
step "Skills index"
if [ ! -f "$ROOT/skills-index.json" ]; then
  ( cd "$ROOT" && PYTHONPATH="$ROOT/skills" python -m skillsvc.ingest --heart Heart --index skills-index.json --report /tmp/skills-report.md >/dev/null )
  ok "built skills-index.json"
else
  ok "skills-index.json present"
fi

# ---- 7. config ------------------------------------------------------------
step "Config (.env)"
if [ ! -f "$ROOT/.env" ]; then
  SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
  cat > "$ROOT/.env" <<EOF
HEXACORE_RUNNER_BACKEND=local
HEXACORE_JWT_SECRET=$SECRET
HEXACORE_MODEL_PROFILE=$LLM_PROFILE
HEXACORE_OLLAMA_MODEL=$MODEL
OLLAMA_HOST=http://localhost:11434
HEXACORE_OWNER_PASSWORD=change-me-owner
HEXACORE_OPERATOR_PASSWORD=change-me-operator
HEXACORE_VIEWER_PASSWORD=change-me-viewer
EOF
  ok "wrote .env (CHANGE THE PASSWORDS)"
else
  ok ".env present (kept as-is)"
fi

# ---- done / launch --------------------------------------------------------
if [ "$CHECK_ONLY" -eq 1 ]; then step "Check complete"; ok "environment ready — run ./hexacore.sh to launch"; exit 0; fi

step "Launch"
echo "  console + API → $(c '1;36' "http://$HOST:$PORT")   (Ctrl-C to stop)"
exec python "$ROOT/serve.py" --host "$HOST" --port "$PORT"
