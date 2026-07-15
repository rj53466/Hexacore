"""More passive recon adapters (Brain/08 §5): recon.dns (dnsx), recon.tech (whatweb),
recon.ct_logs (crt.sh). Each builds argv + parses machine-readable output; nothing runs here.
"""
from __future__ import annotations

import json

from ..base import CapabilityAdapter, Finding, Params, Severity
from hexacore.safety.actions import ActionClass


class DnsxAdapter(CapabilityAdapter):
    name = "recon.dns"
    action_class = ActionClass.PASSIVE

    def build_command(self, target: str, params: Params) -> list[str]:
        return ["dnsx", "-json", "-a", "-resp", "-silent", "-d", target]

    def parse(self, raw: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                o = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = o.get("host") or target
            a = o.get("a") or []
            out.append(Finding(
                title=f"DNS record: {host}", severity=Severity.INFO, source=self.name,
                affected_asset=host, description=f"Resolved to {', '.join(a) or 'no A record'}.",
                attack_techniques=["T1590.002"], evidence={"a": a, "cname": o.get("cname")}))
        return out


class WhatwebAdapter(CapabilityAdapter):
    name = "recon.tech"
    action_class = ActionClass.PASSIVE

    def build_command(self, target: str, params: Params) -> list[str]:
        return ["whatweb", "--log-json=-", "--no-errors", target]

    def parse(self, raw: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        try:
            docs = json.loads(raw) if raw.strip().startswith("[") else \
                   [json.loads(l) for l in raw.splitlines() if l.strip().startswith("{")]
        except json.JSONDecodeError:
            return out
        for o in docs:
            if not isinstance(o, dict):
                continue
            tgt = o.get("target") or target
            tech = sorted((o.get("plugins") or {}).keys())
            out.append(Finding(
                title=f"Tech stack: {tgt}", severity=Severity.INFO, source=self.name,
                affected_asset=tgt, description=", ".join(tech) or "no plugins detected",
                attack_techniques=["T1592.002"], evidence={"tech": tech,
                "status": o.get("http_status")}))
        return out


class CrtShAdapter(CapabilityAdapter):
    name = "recon.ct_logs"
    action_class = ActionClass.PASSIVE

    def build_command(self, target: str, params: Params) -> list[str]:
        return ["curl", "-s", f"https://crt.sh/?q=%25.{target}&output=json"]

    def parse(self, raw: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        seen: set[str] = set()
        try:
            rows = json.loads(raw) if raw.strip() else []
        except json.JSONDecodeError:
            return out
        for row in rows:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lstrip("*.").lower()
                if not name or name in seen:
                    continue
                seen.add(name)
                out.append(Finding(
                    title=f"CT-log host: {name}", severity=Severity.INFO, source=self.name,
                    affected_asset=name, description=f"Seen in certificate transparency for {target}.",
                    attack_techniques=["T1596.001"], evidence={"host": name}))
        return out
