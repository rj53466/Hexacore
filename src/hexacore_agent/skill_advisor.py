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
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
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
                       index_path: Optional[str | Path] = None, max_workers: int = 4) -> int:
    """Attach skill-guided remediation/next-steps to each matched finding. Returns count enriched.

    Findings that match the same skill and share a CWE/title (the same vuln found on N hosts) are
    grouped and advised ONCE — the remediation text is technique-specific, not host-specific, so
    N identical LLM calls bought nothing but N times the wait. The unique calls that remain are
    fanned out across a small thread pool: `ollama_generate` is a blocking `urllib` call, so threads
    (not asyncio) are what buys real concurrency here without an async rewrite of the whole module.
    """
    index = load_index(index_path)
    if not index:
        return 0
    if generate is None:
        generate = default_generate()

    # A slow/unresponsive Ollama times out per-finding (skill context prompts routinely exceed
    # HEXACORE_OLLAMA_TIMEOUT on CPU-only inference) with no early exit — on a real finding set this
    # serially burns minutes per finding before the run can reach later phases. Trip after a few
    # consecutive failures and fall back to offline (skill-reference-only) advice for the rest.
    # ponytail: flat trip count, no reset/half-open; good enough for a single enrichment pass.
    LLM_FAILURE_LIMIT = 3
    failures = 0
    lock = threading.Lock()

    def guarded_generate(prompt: str) -> str:
        nonlocal failures
        try:
            out = generate(prompt)
        except Exception:
            with lock:
                failures += 1
            raise
        with lock:
            failures = 0
        return out

    # Pass 1 (local, no network): match each unenriched finding to a skill and group by
    # (skill, cwe-or-title) — a resumed run already skips findings that carry skill_ref.
    groups: dict[tuple, dict] = {}
    for f in store.all():
        if isinstance(f.evidence, dict) and "skill_ref" in f.evidence:
            continue
        sk = match_skill(f, index)
        if not sk:
            continue
        key = (sk.get("name"), f.cwe or f.title)
        groups.setdefault(key, {"sk": sk, "findings": []})["findings"].append(f)

    # Pass 2 (network, parallel): one advise() call per unique group.
    # ponytail: the failure-count check races harmlessly under concurrency — a few extra in-flight
    # calls past LLM_FAILURE_LIMIT is an acceptable soft-breaker, not worth a stricter lock here.
    def _work(item):
        key, group = item
        active = guarded_generate if (generate and failures < LLM_FAILURE_LIMIT) else None
        return key, advise(group["findings"][0], group["sk"], active)

    results: dict[tuple, tuple[str, str]] = {}
    if groups:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            for key, result in pool.map(_work, groups.items()):
                results[key] = result

    # Pass 3: apply each group's (possibly shared) result to every finding in it.
    enriched = 0
    for key, group in groups.items():
        rem, nxt = results[key]
        sk = group["sk"]
        for f in group["findings"]:
            try:
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

    # Dedup + parallel fan-out: 3 findings, 2 sharing the same (skill, CWE) — same vuln on two
    # hosts plus one distinct finding — must cost 2 LLM calls, not 3, and all 3 still get enriched.
    def make(title, cwe, asset):
        f = _F()
        f.title, f.cwe, f.affected_asset, f.evidence, f.remediation = title, cwe, asset, {}, ""
        return f

    dup_a = make("SMB signing not required", "CWE-287", "10.0.0.5")
    dup_b = make("SMB signing not required", "CWE-287", "10.0.0.6")
    other = make("Kerberoasting exposed", "CWE-522", "10.0.0.7")
    call_count = {"n": 0}
    call_lock = threading.Lock()

    def counting_generate(prompt: str) -> str:
        with call_lock:
            call_count["n"] += 1
        return json.dumps({"remediation": "fix it", "next_steps": "verify it"})

    idx2 = idx + [{"name": "kerberoast", "mitre_attack": [], "tags": ["kerberoast"],
                   "description": "Request/crack service ticket hashes.", "path": "does/not/exist.md"}]
    multi_store = type("St", (), {"all": lambda self: [dup_a, dup_b, other]})()
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump({"skills": idx2}, tf)
        tmp_path = tf.name
    n = enrich_with_skills(multi_store, generate=counting_generate, index_path=tmp_path)
    assert n == 3, f"expected all 3 findings enriched, got {n}"
    assert call_count["n"] == 2, f"expected 2 LLM calls (deduped), got {call_count['n']}"
    assert "fix it" in dup_a.remediation and "fix it" in dup_b.remediation and "fix it" in other.remediation
    print("skill_advisor self-check OK")
