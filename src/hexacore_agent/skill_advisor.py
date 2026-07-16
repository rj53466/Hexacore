"""Skill-guided finding enrichment — gives the 817-skill Heart/ corpus a real job.

For each finding, match the most relevant `Heart/skills/**/SKILL.md` (by MITRE ATT&CK technique and
tag/keyword overlap against the compact `skills-index.json`), then:

  * with a local LLM configured (HEXACORE_MODEL_PROFILE=ollama|local) — ask the model, grounded in
    that technique's write-up, for concise defender remediation + operator next-step hints;
  * offline — attach the matched skill reference + its description as guidance.

Either way the skill knowledge reaches the report. This never runs a tool, never touches scope, and
is wrapped so any failure (no index, model down, bad JSON) degrades to "no enrichment", never breaks
a run. Self-contained Ollama call (stdlib urllib) so importing this doesn't pull LangGraph.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from pathlib import Path
from typing import Callable, Optional

_ROOT = Path(__file__).resolve().parents[2]          # repo root
_WORD = re.compile(r"[a-z0-9]+")


def ollama_generate(prompt: str, *, host: str, model: str, timeout: float) -> str:
    """One-shot, non-streaming Ollama /api/generate call (stdlib urllib, no SDK)."""
    body = json.dumps({"model": model, "prompt": prompt, "stream": False,
                       "format": "json"}).encode()
    req = urllib.request.Request(host.rstrip("/") + "/api/generate", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read()).get("response", "")


def load_index(path: Optional[str | Path] = None) -> list[dict]:
    """Load the valid-skills list from skills-index.json. Missing/broken index -> [] (feature off)."""
    p = Path(path) if path else _ROOT / "skills-index.json"
    if not p.is_file():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8")).get("skills", [])
    except Exception:
        return []


def _tokens(s: str) -> set[str]:
    return set(_WORD.findall((s or "").lower()))


def match_skill(finding, index: list[dict]) -> Optional[dict]:
    """Pick the most relevant skill for a finding. Returns None below a confidence threshold."""
    if not index:
        return None
    f_attack = {t.upper() for t in (getattr(finding, "attack_techniques", None) or [])}
    f_attack_base = {a.split(".")[0] for a in f_attack}
    f_tok = _tokens(f"{finding.title} {finding.source} {finding.cwe or ''} {finding.description}")

    best, best_score = None, 0
    for sk in index:
        score = 0
        s_attack = {a.upper() for a in sk.get("mitre_attack", [])}
        if f_attack and s_attack:
            score += 5 * len(f_attack & s_attack)                       # exact technique match
            score += 3 * len(f_attack_base & {a.split(".")[0] for a in s_attack})  # base technique
        s_tok = _tokens(" ".join(sk.get("tags", [])) + " " + (sk.get("name") or "") + " "
                        + (sk.get("description") or ""))
        score += len(f_tok & s_tok)
        if score > best_score:
            best, best_score = sk, score
    return best if best_score >= 3 else None   # threshold avoids weak/coincidental matches


def _skill_context(sk: dict) -> str:
    """The matched skill's overview text (frontmatter stripped, bounded) to ground the model."""
    raw = sk.get("path", "")
    p = Path(raw) if Path(raw).is_absolute() else _ROOT / raw
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return sk.get("description", "") or ""
    body = re.sub(r"^\s*---.*?---\s*", "", text, count=1, flags=re.DOTALL)
    return body.strip()[:1600]


def default_generate() -> Optional[Callable[[str], str]]:
    """Return a one-shot Ollama generate fn iff a local LLM profile is configured, else None."""
    profile = os.getenv("HEXACORE_MODEL_PROFILE", "deterministic")
    if profile not in ("ollama", "local"):
        return None
    model = os.getenv("HEXACORE_OLLAMA_MODEL", "qwen2.5:7b")
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")

    timeout = float(os.getenv("HEXACORE_OLLAMA_TIMEOUT", "45"))

    def _gen(prompt: str) -> str:
        return ollama_generate(prompt, host=host, model=model, timeout=timeout)
    return _gen


def advise(finding, sk: dict, generate: Optional[Callable[[str], str]]) -> tuple[str, str]:
    """(remediation, next_steps) for a finding, grounded in skill `sk`. LLM if available, else fallback."""
    techniques = ", ".join(sk.get("mitre_attack", []) or ["n/a"])
    fallback = (f"Related technique: {sk.get('name')} ({techniques}). {sk.get('description', '')}", "")
    if generate is None:
        return fallback
    context = _skill_context(sk)
    prompt = (
        "You are a defensive security advisor summarizing for a penetration-test report. "
        "Given a finding and the relevant attack technique, respond with ONLY a JSON object "
        '{"remediation": "...", "next_steps": "..."} — no prose outside the JSON.\n'
        "remediation: 2-4 sentences of concrete defender fixes.\n"
        "next_steps: 1-2 sentences on how an operator would safely verify/confirm this.\n\n"
        f"FINDING: {finding.title}\nSEVERITY: {finding.severity.value}\n"
        f"ASSET: {finding.affected_asset}\nCWE: {finding.cwe or 'n/a'}\n"
        f"DETAIL: {(finding.description or '')[:400]}\n\n"
        f"TECHNIQUE ({techniques}) — {sk.get('name')}:\n{context}\n"
    )
    try:
        obj = json.loads(generate(prompt))
        rem = str(obj.get("remediation", "")).strip()
        nxt = str(obj.get("next_steps", "")).strip()
        return (rem or fallback[0], nxt)
    except Exception:
        return fallback


def enrich_with_skills(store, *, generate: Optional[Callable[[str], str]] = None,
                       index_path: Optional[str | Path] = None) -> int:
    """Attach skill-guided remediation/next-steps to each matched finding. Returns count enriched."""
    index = load_index(index_path)
    if not index:
        return 0
    if generate is None:
        generate = default_generate()
    enriched = 0
    for f in store.all():
        try:
            sk = match_skill(f, index)
            if not sk:
                continue
            rem, nxt = advise(f, sk, generate)
            if isinstance(f.evidence, dict):
                f.evidence.setdefault("skill_ref",
                                      {"name": sk.get("name"), "path": sk.get("path"),
                                       "mitre_attack": sk.get("mitre_attack", [])})
                if nxt:
                    f.evidence.setdefault("suggested_next_steps", nxt)
            if rem:
                prefix = "\n\n" if f.remediation else ""
                f.remediation = f"{f.remediation}{prefix}[Skill-guided] {rem}"
            enriched += 1
        except Exception:
            continue   # one bad finding never aborts the pass
    return enriched


# --- skill-driven chaining -------------------------------------------------
# Maps each VETTED, gated capability to the MITRE techniques + keywords that indicate a matched
# skill points at it. This is the ONLY bridge from skills to execution: a skill can select which
# already-safety-approved capability runs next — it can never inject a raw command. Every capability
# named here is a real adapter that still passes through scope + gate + kill switch.
CAP_SIGNALS: dict[str, dict] = {
    "enum.netexec": {"mitre": {"T1557", "T1021", "T1135", "T1110"},
                     "kw": ("smb", "netexec", "crackmapexec", "ntlm relay", "password spray", "445")},
    "enum.bloodhound": {"mitre": {"T1558", "T1069", "T1087", "T1482", "T1615"},
                        "kw": ("kerberoast", "as-rep", "asrep", "bloodhound", "active directory",
                               "ldap", "domain controller", "attack path")},
    "verify.adcs_find": {"mitre": {"T1649"},
                         "kw": ("adcs", "certipy", "esc1", "esc8", "certificate services", "certsrv",
                                "ad cs")},
    "verify.web_sqli": {"mitre": {"T1190"},
                        "kw": ("sql injection", "sqli", "sqlmap", "blind sql")},
    "verify.ssrf": {"mitre": {"T1090", "T1595"},
                    "kw": ("ssrf", "server-side request forgery", "metadata endpoint")},
    "verify.idor": {"mitre": {"T1078"},
                    "kw": ("idor", "broken access control", "insecure direct object")},
    "enum.linux_persistence": {"mitre": {"T1053", "T1543", "T1548", "T1078.003"},
                               "kw": ("linux privilege escalation", "linpeas", "suid", "sudo abuse",
                                      "linux persistence")},
    "enum.cloud.cloudfox": {"mitre": {"T1526", "T1580"},
                            "kw": ("cloudfox", "aws enumeration", "iam", "cloud attack surface")},
    "scan.cloud.scoutsuite": {"mitre": set(),
                              "kw": ("scoutsuite", "cloud posture", "azure", "gcp", "s3 bucket")},
    "scan.api.kiterunner": {"mitre": set(),
                            "kw": ("kiterunner", "api endpoint discovery", "swagger", "openapi",
                                   "route brute")},
}


def next_capabilities(store, index: list[dict], available: set[str]) -> dict[str, str]:
    """Decide which gated capabilities to queue next, driven by the skill matched to each finding.

    Returns {capability: skill_name_that_selected_it}, restricted to `available` (the vetted adapter
    set). This is advisory routing only — the returned capabilities are executed by the runner
    through the normal CapabilityExecutor + safety layer, exactly like any other step.
    """
    selected: dict[str, str] = {}
    if not index:
        return selected
    for f in store.all():
        try:
            sk = match_skill(f, index)
            if not sk:
                continue
            base = {a.split(".")[0].upper() for a in sk.get("mitre_attack", [])}
            blob = (" ".join(sk.get("tags", [])) + " " + (sk.get("name") or "") + " "
                    + (sk.get("description") or "")).lower()
            for cap, sig in CAP_SIGNALS.items():
                if cap not in available:
                    continue
                if (base & sig["mitre"]) or any(k in blob for k in sig["kw"]):
                    selected.setdefault(cap, sk.get("name") or sk.get("slug") or "skill")
        except Exception:
            continue
    return selected


if __name__ == "__main__":
    # Self-check: matching + offline advice work without any network or real index.
    class _F:
        title = "SMB signing not required"
        source = "scan.ports"
        cwe = "CWE-287"
        description = "Host exposes SMB (445/tcp); message signing disabled."
        severity = type("S", (), {"value": "high"})()
        affected_asset = "10.0.0.5"
        attack_techniques = ["T1557.001"]
        remediation = ""
        evidence: dict = {}
    idx = [{"name": "ntlm-relay", "mitre_attack": ["T1557.001"], "tags": ["smb", "relay"],
            "description": "Relay NTLM auth to gain access.", "path": "does/not/exist.md"}]
    assert match_skill(_F(), idx) is not None, "exact MITRE match should hit"
    rem, nxt = advise(_F(), idx[0], None)          # offline path
    assert "ntlm-relay" in rem and "T1557.001" in rem, rem
    store = type("St", (), {"all": lambda self: [_F()]})()
    assert enrich_with_skills(store, generate=None, index_path="does-not-exist.json") == 0
    # chaining: an NTLM-relay (T1557.001) skill should select the gated enum.netexec capability.
    nxt = next_capabilities(store, idx, available={"enum.netexec", "enum.bloodhound"})
    assert nxt.get("enum.netexec") == "ntlm-relay", nxt
    assert "verify.web_sqli" not in nxt, "must not select an unavailable/unrelated capability"
    print("skill_advisor self-check OK")
