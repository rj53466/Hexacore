"""verify.adcs_find — Certipy `find` adapter for AD Certificate Services enumeration (Phase 3).

Runs Certipy in **find-only** mode to discover vulnerable certificate templates (ESC1–ESC8).
Never attempts abuse — that would require a separate, higher-gated adapter.
"""
from __future__ import annotations

import json

from ..base import CapabilityAdapter, Finding, Params, Severity
from hexacore.safety.actions import ActionClass


class CertipyFindAdapter(CapabilityAdapter):
    name = "verify.adcs_find"
    action_class = ActionClass.ACTIVE_EXPLOIT

    def build_command(self, target: str, params: Params) -> list[str]:
        argv = ["certipy", "find"]

        if params.get("username"):
            argv.extend(["-u", str(params["username"])])
        if params.get("password"):
            argv.extend(["-p", str(params["password"])])

        # target is the DC IP
        argv.extend(["-dc-ip", target])

        # Always request JSON output
        argv.append("-json")

        # Vulnerable-only filter
        if params.get("vulnerable_only", True):
            argv.append("-vulnerable")

        return argv

    def parse(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []

        findings: list[Finding] = []

        # Try JSON parse first
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # Fall back to text parsing
            return self._parse_text(raw, target)

        # Parse certificate templates from JSON
        templates = data if isinstance(data, list) else data.get("certificate_templates", [])
        if isinstance(data, dict) and not templates:
            # Some certipy versions nest differently
            for key, val in data.items():
                if isinstance(val, list):
                    templates = val
                    break

        for tmpl in templates:
            if not isinstance(tmpl, dict):
                continue
            name = tmpl.get("name", tmpl.get("template_name", "Unknown"))
            vuln = tmpl.get("vulnerabilities", tmpl.get("vulnerable_to", []))
            if isinstance(vuln, str):
                vuln = [vuln]

            sev = Severity.HIGH if vuln else Severity.INFO
            findings.append(Finding(
                title=f"ADCS Template: {name}" + (f" ({', '.join(vuln)})" if vuln else ""),
                severity=sev,
                source=self.name,
                affected_asset=target,
                description=(
                    f"Certificate template '{name}' "
                    + (f"is vulnerable to: {', '.join(vuln)}." if vuln else "enumerated (no known vulnerability).")
                ),
                cwe="CWE-295",
                attack_techniques=["T1649"],
                evidence={"template": tmpl},
            ))

        if not findings:
            findings.append(Finding(
                title=f"ADCS enumeration: {target}",
                severity=Severity.INFO,
                source=self.name,
                affected_asset=target,
                description="Certipy find completed; no vulnerable templates detected.",
                attack_techniques=["T1649"],
                evidence={"raw": raw[:1000]},
            ))

        return findings

    def _parse_text(self, raw: str, target: str) -> list[Finding]:
        """Fallback text parser for non-JSON output."""
        findings: list[Finding] = []
        raw_lower = raw.lower()

        esc_patterns = ["esc1", "esc2", "esc3", "esc4", "esc5", "esc6", "esc7", "esc8"]
        matched = [p.upper() for p in esc_patterns if p in raw_lower]

        if matched:
            findings.append(Finding(
                title=f"ADCS Vulnerable Templates Detected ({', '.join(matched)})",
                severity=Severity.HIGH,
                source=self.name,
                affected_asset=target,
                description=f"Certipy detected vulnerable escalation paths: {', '.join(matched)}.",
                cwe="CWE-295",
                attack_techniques=["T1649"],
                evidence={"escalation_paths": matched, "raw": raw[:1000]},
            ))
        else:
            findings.append(Finding(
                title=f"ADCS enumeration: {target}",
                severity=Severity.INFO,
                source=self.name,
                affected_asset=target,
                description="Certipy find completed (text output); review raw output.",
                attack_techniques=["T1649"],
                evidence={"raw": raw[:1000]},
            ))

        return findings
