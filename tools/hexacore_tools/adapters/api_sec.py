"""api_sec — API Security scanning (Kiterunner, ZAP) (Phase 3).
"""
from __future__ import annotations

import json
from ..base import CapabilityAdapter, Finding, Params, Severity
from hexacore.safety.actions import ActionClass


class KiterunnerAdapter(CapabilityAdapter):
    name = "scan.api.kiterunner"
    action_class = ActionClass.ACTIVE_SCAN

    def build_command(self, target: str, params: Params) -> list[str]:
        # kr scan <target> -w routes.kite -o json
        wordlist = params.get("wordlist", "routes.kite")
        return ["kr", "scan", target, "-w", wordlist, "-o", "json"]

    def parse(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        findings = []
        for line in raw.splitlines():
            try:
                data = json.loads(line)
                url = data.get("url", target)
                status = data.get("status", 0)
                if status in (200, 201, 401, 403):
                    findings.append(Finding(
                        title=f"API Endpoint Discovered: {url} ({status})",
                        severity=Severity.INFO if status != 200 else Severity.LOW,
                        source=self.name,
                        affected_asset=target,
                        description=f"Kiterunner found an active API route. Method: {data.get('method', 'GET')}",
                        attack_techniques=["T1595.002"], # Active Scanning: Vulnerability Scanning
                        evidence=data
                    ))
            except json.JSONDecodeError:
                pass
        return findings
