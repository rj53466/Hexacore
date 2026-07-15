"""More active-scan adapters (Brain/08 §5, all <= active-scan): scan.tls (testssl.sh),
scan.web_dir (ffuf), scan.web_nikto (nikto).
"""
from __future__ import annotations

import json

from ..base import CapabilityAdapter, Finding, Params, Severity
from hexacore.safety.actions import ActionClass

_TESTSSL_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW, "WARN": Severity.LOW, "INFO": Severity.INFO}


class TestsslAdapter(CapabilityAdapter):
    name = "scan.tls"
    action_class = ActionClass.ACTIVE_SCAN

    def build_command(self, target: str, params: Params) -> list[str]:
        return ["testssl.sh", "--jsonfile-pretty", "/dev/stdout", "--quiet", target]

    def parse(self, raw: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        try:
            rows = json.loads(raw) if raw.strip() else []
        except json.JSONDecodeError:
            return out
        if isinstance(rows, dict):
            rows = rows.get("scanResult") or []
        for r in rows if isinstance(rows, list) else []:
            sev = _TESTSSL_SEV.get(str(r.get("severity", "INFO")).upper())
            if sev is None or sev is Severity.INFO:
                continue  # skip OK/DEBUG/INFO noise
            out.append(Finding(
                title=f"TLS: {r.get('id', 'issue')}", severity=sev, source=self.name,
                affected_asset=r.get("ip") or target, description=str(r.get("finding", "")),
                cwe="CWE-327", attack_techniques=["T1040"], evidence={"id": r.get("id")}))
        return out


class FfufAdapter(CapabilityAdapter):
    name = "scan.web_dir"
    action_class = ActionClass.ACTIVE_SCAN

    def build_command(self, target: str, params: Params) -> list[str]:
        wordlist = str(params.get("wordlist", "/usr/share/wordlists/dirb/common.txt"))
        base = target.rstrip("/") + "/FUZZ"
        return ["ffuf", "-u", base, "-w", wordlist, "-of", "json", "-o", "/dev/stdout", "-s"]

    def parse(self, raw: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        try:
            data = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            return out
        for r in data.get("results", []):
            url = r.get("url") or target
            out.append(Finding(
                title=f"Path found: {url} ({r.get('status')})", severity=Severity.INFO,
                source=self.name, affected_asset=url,
                description=f"Directory/file brute-force hit, status {r.get('status')}.",
                attack_techniques=["T1595.003"], evidence={"status": r.get("status"),
                "length": r.get("length")}))
        return out


class NiktoAdapter(CapabilityAdapter):
    name = "scan.web_nikto"
    action_class = ActionClass.ACTIVE_SCAN

    def build_command(self, target: str, params: Params) -> list[str]:
        return ["nikto", "-h", target, "-Format", "json", "-output", "/dev/stdout"]

    def parse(self, raw: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        try:
            data = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            return out
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        for v in vulns:
            out.append(Finding(
                title=f"Nikto: {v.get('msg', v.get('id', 'issue'))}", severity=Severity.LOW,
                source=self.name, affected_asset=v.get("url") or target,
                description=str(v.get("msg", "")), attack_techniques=["T1595.002"],
                evidence={"id": v.get("id"), "method": v.get("method")}))
        return out
