"""enum.linux_persistence — LinPEAS/Persistence check adapter (Phase 3).

Simulates checking for common Linux local privilege escalation vectors and 
persistence mechanisms.
"""
from __future__ import annotations

import re

from ..base import CapabilityAdapter, Finding, Params, Severity
from hexacore.safety.actions import ActionClass


class LinpeasAdapter(CapabilityAdapter):
    name = "enum.linux_persistence"
    action_class = ActionClass.ACTIVE_SCAN

    def build_command(self, target: str, params: Params) -> list[str]:
        # In a real scenario, this would likely be an SSH command to execute linpeas.sh
        # or a similar mechanism. For the adapter, we wrap a mock local check.
        argv = ["linpeas.sh"]
        
        if params.get("target"):
            argv.extend(["-t", str(params["target"])])
            
        return argv

    def parse(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []

        findings: list[Finding] = []

        # Look for simulated PEAS output (e.g. "RED/YELLOW" findings)
        # 🔴 🟡 
        vulns_found = re.findall(r"(?:RED/YELLOW|Vulnerable):\s*(.+)", raw, re.IGNORECASE)
        
        for vuln in vulns_found:
            findings.append(Finding(
                title=f"Potential LPE/Persistence: {vuln.strip()}",
                severity=Severity.HIGH,
                source=self.name,
                affected_asset=target,
                description=f"LinPEAS highlighted a potential vulnerability or persistence mechanism: {vuln.strip()}",
                attack_techniques=["T1548", "T1098"],
                remediation="Investigate the highlighted misconfiguration and apply least-privilege principles.",
            ))

        if not findings and "linpeas" in raw.lower():
            findings.append(Finding(
                title="LinPEAS Scan Completed",
                severity=Severity.INFO,
                source=self.name,
                affected_asset=target,
                description="LinPEAS ran but found no immediate RED/YELLOW critical vectors.",
                attack_techniques=["T1082"],
            ))

        return findings
