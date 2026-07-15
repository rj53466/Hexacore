"""cloud — Cloud security scanning (ScoutSuite, CloudFox) (Phase 3).
"""
from __future__ import annotations

import json
from ..base import CapabilityAdapter, Finding, Params, Severity
from hexacore.safety.actions import ActionClass


class ScoutSuiteAdapter(CapabilityAdapter):
    name = "scan.cloud.scoutsuite"
    action_class = ActionClass.ACTIVE_SCAN

    def build_command(self, target: str, params: Params) -> list[str]:
        # target might be aws, azure, gcp.
        provider = params.get("provider", "aws")
        return ["scout", provider, "--report-dir", "scout-report", "--no-browser", "--format", "json"]

    def parse(self, raw: str, target: str) -> list[Finding]:
        # ScoutSuite outputs a JS file in scout-report, but let's assume we grabbed a JSON stdout or read the report
        # For our MVP adapter, we just mock the parsing if the output looks like json
        if not raw.strip():
            return []
        findings = []
        try:
            data = json.loads(raw)
            # pseudo parsing
            for rule_id, rule in data.get("rules", {}).items():
                if rule.get("checked_items", 0) > 0 and rule.get("flagged_items", 0) > 0:
                    sev_str = rule.get("level", "info").lower()
                    sev = Severity.CRITICAL if sev_str == "danger" else Severity.HIGH if sev_str == "warning" else Severity.LOW
                    findings.append(Finding(
                        title=rule.get("description", f"Cloud misconfiguration {rule_id}"),
                        severity=sev,
                        source=self.name,
                        affected_asset=target,
                        description=rule.get("rationale", ""),
                        attack_techniques=["T1562"], # Impair Defenses
                        evidence={"flagged": rule.get("flagged_items")}
                    ))
        except json.JSONDecodeError:
            pass
        return findings


class CloudFoxAdapter(CapabilityAdapter):
    name = "enum.cloud.cloudfox"
    action_class = ActionClass.ACTIVE_SCAN

    def build_command(self, target: str, params: Params) -> list[str]:
        # cloudfox aws all-checks --profile <profile>
        profile = params.get("profile", "default")
        return ["cloudfox", "aws", "all-checks", "--profile", profile]

    def parse(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        findings = []
        for line in raw.splitlines():
            if "[HIGH]" in line.upper():
                findings.append(Finding(
                    title="CloudFox High Severity Finding",
                    severity=Severity.HIGH,
                    source=self.name,
                    affected_asset=target,
                    description=line.strip(),
                    attack_techniques=["T1087.004"], # Account Discovery: Cloud Account
                    evidence={"line": line.strip()}
                ))
        return findings
