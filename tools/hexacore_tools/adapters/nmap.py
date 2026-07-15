"""scan.ports — nmap SYN + service detection (Brain/08 §5). Parses nmap XML (`-oX -`).

Open ports become INFO findings (asset inventory); a service with a detected version is annotated
so the analysis layer can do version->CVE correlation later (Epic E1). This adapter does not run
nmap; it only builds the argv and parses the XML.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from ..base import CapabilityAdapter, Finding, Params, Severity
from hexacore.safety.actions import ActionClass


class NmapPortsAdapter(CapabilityAdapter):
    name = "scan.ports"
    action_class = ActionClass.ACTIVE_SCAN

    def build_command(self, target: str, params: Params) -> list[str]:
        argv = ["nmap", "-sS", "-sV", "-Pn", "-oX", "-"]
        top_ports = params.get("top_ports")
        ports = params.get("ports")
        if ports:
            argv += ["-p", str(ports)]
        elif top_ports:
            argv += ["--top-ports", str(int(top_ports))]
        if params.get("safe_scripts", True):
            argv += ["--script", "default,safe"]
        argv.append(target)
        return argv

    def parse(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return []

        findings: list[Finding] = []
        for host in root.findall("host"):
            addr_el = host.find("address")
            address = addr_el.get("addr") if addr_el is not None else target
            for port in host.findall("./ports/port"):
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                portid = port.get("portid")
                proto = port.get("protocol", "tcp")
                svc = port.find("service")
                svc_name = svc.get("name") if svc is not None else "unknown"
                product = svc.get("product") if svc is not None else None
                version = svc.get("version") if svc is not None else None
                banner = " ".join(x for x in (product, version) if x)

                title = f"Open port {portid}/{proto} ({svc_name})"
                findings.append(Finding(
                    title=title,
                    severity=Severity.INFO,
                    source=self.name,
                    affected_asset=address,
                    description=(f"Service {svc_name}"
                                 + (f" — {banner}" if banner else "")).strip(),
                    attack_techniques=["T1046"],  # Network Service Discovery
                    evidence={"port": portid, "protocol": proto, "service": svc_name,
                              "product": product, "version": version},
                ))
        return findings
