"""verify.web_sqli — sqlmap adapter for SQL injection verification (Phase 2)."""
from __future__ import annotations

from ..base import CapabilityAdapter, Finding, Params, Severity
from hexacore.safety.actions import ActionClass


class SqlmapAdapter(CapabilityAdapter):
    name = "verify.web_sqli"
    action_class = ActionClass.ACTIVE_EXPLOIT

    def build_command(self, target: str, params: Params) -> list[str]:
        # sqlmap --batch -u <target>
        argv = ["sqlmap", "--batch", "-u", target]
        
        mode = str(params.get("mode", "detection")).lower()
        if mode in {"detection", "detect", "check"}:
            pass
        elif params.get("dump_all"):
            argv.append("--dump-all")
        elif params.get("os_shell"):
            argv.append("--os-shell")

        return argv

    def parse(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []

        # We do simple parsing for standard sqlmap output
        findings: list[Finding] = []
        
        raw_lower = raw.lower()
        if "is vulnerable" in raw_lower or "identified the following injection point" in raw_lower or "payload:" in raw_lower:
            findings.append(Finding(
                title="SQL Injection Vulnerability",
                severity=Severity.HIGH,
                source=self.name,
                affected_asset=target,
                description="sqlmap identified a potential SQL injection vulnerability.",
                attack_techniques=["T1190"],
                evidence={"raw": raw[:1000]},  # store a snippet of evidence
                cwe="CWE-89"
            ))

        return findings
