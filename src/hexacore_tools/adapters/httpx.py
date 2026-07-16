"""recon.http_probe — httpx HTTP probing (Brain/08 §5). Parses JSON lines (`-json`). Records
live web endpoints with status/title/tech as INFO findings; a detected server version is carried
in evidence for later version->CVE correlation (Epic E1).
"""
from __future__ import annotations

import json

from ..base import CapabilityAdapter, Finding, Params, Severity
from hexacore.safety.actions import ActionClass


class HttpxAdapter(CapabilityAdapter):
    name = "recon.http_probe"
    action_class = ActionClass.PASSIVE

    def build_command(self, target: str, params: Params) -> list[str]:
        argv = ["httpx", "-u", target, "-json", "-silent",
                "-status-code", "-title", "-tech-detect"]
        ports = params.get("ports")
        if ports:
            argv += ["-ports", str(ports)]
        return argv

    def parse(self, raw: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url") or obj.get("input") or target
            status = obj.get("status_code") or obj.get("status-code")
            title = obj.get("title") or ""
            tech = obj.get("tech") or obj.get("technologies") or []
            if isinstance(tech, str):
                tech = [tech]
            host = obj.get("host") or obj.get("input") or url
            desc = f"Live HTTP endpoint (status {status})"
            if title:
                desc += f' — "{title}"'
            findings.append(Finding(
                title=f"HTTP service: {url}",
                severity=Severity.INFO,
                source=self.name,
                affected_asset=host,
                description=desc,
                attack_techniques=["T1595.002"],
                evidence={"url": url, "status_code": status, "title": title,
                          "tech": tech, "webserver": obj.get("webserver")},
            ))
        return findings
