"""recon.subdomains — subfinder passive subdomain enumeration (Brain/08 §5). Parses JSON lines
(`-oJ`/`-json`), one host per line. Each discovered subdomain is an INFO finding (asset
inventory); the runner feeds in-scope discoveries into the scan phase.
"""
from __future__ import annotations

import json

from ..base import CapabilityAdapter, Finding, Params, Severity
from hexacore.safety.actions import ActionClass


class SubfinderAdapter(CapabilityAdapter):
    name = "recon.subdomains"
    action_class = ActionClass.PASSIVE

    def build_command(self, target: str, params: Params) -> list[str]:
        argv = ["subfinder", "-d", target, "-json", "-silent"]
        if params.get("all_sources"):
            argv.append("-all")
        return argv

    def parse(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            host = None
            if line.startswith("{"):
                try:
                    host = json.loads(line).get("host")
                except json.JSONDecodeError:
                    host = None
            else:
                host = line  # plain -silent output is one host per line
            if not host or host in seen:
                continue
            seen.add(host)
            findings.append(Finding(
                title=f"Subdomain discovered: {host}",
                severity=Severity.INFO,
                source=self.name,
                affected_asset=host,
                description=f"Passively enumerated subdomain of {target}.",
                attack_techniques=["T1595"],  # Active Scanning / recon
                evidence={"host": host, "root": target},
            ))
        return findings
