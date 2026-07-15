"""verify.msf_check — Metasploit check module verification (Phase 2)."""
from __future__ import annotations

from ..base import CapabilityAdapter, Finding, Params, Severity
from hexacore.safety.actions import ActionClass


class MetasploitCheckAdapter(CapabilityAdapter):
    name = "verify.msf_check"
    action_class = ActionClass.ACTIVE_EXPLOIT

    def build_command(self, target: str, params: Params) -> list[str]:
        # Basic msfconsole wrapper
        # Requires module name and rhosts, e.g. msfconsole -q -x "use exploit/...; set RHOSTS <target>; check; exit"
        module = str(params.get("module", "auxiliary/scanner/http/http_version"))
        
        # Check if they want to exploit or just check
        action = str(params.get("action", "check")).lower()
        
        cmds = f"use {module}; set RHOSTS {target}; {action}; exit"
        argv = ["msfconsole", "-q", "-x", cmds]
        
        return argv

    def parse(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []

        findings: list[Finding] = []
        raw_lower = raw.lower()
        
        # Simple string-matching for msf check success
        if "is vulnerable" in raw_lower or "the target is vulnerable" in raw_lower:
            findings.append(Finding(
                title="Metasploit Vulnerability Found",
                severity=Severity.HIGH,
                source=self.name,
                affected_asset=target,
                description="Metasploit module confirmed a vulnerability.",
                attack_techniques=["T1190"],
                evidence={"raw": raw[:1000]}
            ))

        return findings
