"""enum.netexec — NetExec (nxc) adapter for SMB/LDAP enumeration (Phase 3).

Runs netexec in enumeration-only mode.  No credential spraying or exploitation
unless explicitly parameterised and gated.
"""
from __future__ import annotations

import json

from ..base import CapabilityAdapter, Finding, Params, Severity
from hexacore.safety.actions import ActionClass


class NetexecAdapter(CapabilityAdapter):
    name = "enum.netexec"
    action_class = ActionClass.ACTIVE_EXPLOIT

    def build_command(self, target: str, params: Params) -> list[str]:
        protocol = str(params.get("protocol", "smb")).lower()
        argv = ["nxc", protocol, target]

        # Default: enumeration only (no creds → anonymous/guest)
        if params.get("username"):
            argv.extend(["-u", str(params["username"])])
        if params.get("password"):
            argv.extend(["-p", str(params["password"])])

        # Common enum flags
        if params.get("shares"):
            argv.append("--shares")
        if params.get("users"):
            argv.append("--users")
        if params.get("sessions"):
            argv.append("--sessions")
        if params.get("pass_pol"):
            argv.append("--pass-pol")

        return argv

    def parse(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []

        findings: list[Finding] = []

        # Parse netexec text output line by line
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue

            # SMB share enumeration
            if "READ" in line or "WRITE" in line:
                findings.append(Finding(
                    title=f"SMB Share Accessible: {line.split()[-1] if line.split() else 'unknown'}",
                    severity=Severity.MEDIUM if "WRITE" in line else Severity.LOW,
                    source=self.name,
                    affected_asset=target,
                    description=f"Network share discovered: {line}",
                    cwe="CWE-200",
                    attack_techniques=["T1135"],
                    evidence={"raw_line": line},
                ))

            # Signing not required
            if "signing" in line.lower() and "false" in line.lower():
                findings.append(Finding(
                    title="SMB Signing Not Required",
                    severity=Severity.MEDIUM,
                    source=self.name,
                    affected_asset=target,
                    description="SMB signing is not required, enabling relay attacks.",
                    cwe="CWE-294",
                    attack_techniques=["T1557.001"],
                    evidence={"raw_line": line},
                ))

        # If we got output but no specific findings, emit an info-level summary
        if not findings:
            findings.append(Finding(
                title=f"NetExec enumeration: {target}",
                severity=Severity.INFO,
                source=self.name,
                affected_asset=target,
                description="NetExec ran successfully; review raw output for details.",
                attack_techniques=["T1046"],
                evidence={"raw": raw[:1000]},
            ))

        return findings
