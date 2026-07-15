"""scan.web_nuclei — nuclei template scan (Brain/08 §3). Parses JSONL (`-jsonl`), one finding
per line. Maps nuclei severities to the platform Severity and carries CWE/CVE/ATT&CK through to
the Finding for the report's framework mappings (Brain/06 §5).
"""
from __future__ import annotations

import json

from ..base import CapabilityAdapter, Finding, Params, Severity
from hexacore.safety.actions import ActionClass

_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


class NucleiAdapter(CapabilityAdapter):
    name = "scan.web_nuclei"
    action_class = ActionClass.ACTIVE_SCAN

    def build_command(self, target: str, params: Params) -> list[str]:
        argv = ["nuclei", "-u", target, "-jsonl", "-silent"]
        severities = params.get("severity")
        if severities:
            argv += ["-severity", str(severities)]
        tags = params.get("tags")
        if tags:
            argv += ["-tags", str(tags)]
        if params.get("rate_limit"):
            argv += ["-rate-limit", str(int(params["rate_limit"]))]
        return argv

    def parse(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info", {})
            classification = info.get("classification", {}) or {}
            sev = _SEV_MAP.get(str(info.get("severity", "info")).lower(), Severity.INFO)

            cwe = classification.get("cwe-id")
            if isinstance(cwe, list):
                cwe = cwe[0] if cwe else None
            cve = classification.get("cve-id") or []
            if isinstance(cve, str):
                cve = [cve]

            asset = obj.get("matched-at") or obj.get("host") or target
            title = info.get("name") or obj.get("template-id") or "nuclei finding"
            findings.append(Finding(
                title=title,
                severity=sev,
                source=self.name,
                affected_asset=asset,
                description=info.get("description", "") or "",
                cwe=cwe,
                cve=list(cve),
                cvss_vector=(classification.get("cvss-metrics") or None),
                remediation=info.get("remediation", "") or "",
                evidence={"template_id": obj.get("template-id"),
                          "matcher": obj.get("matcher-name"),
                          "type": obj.get("type")},
            ))
        return findings
