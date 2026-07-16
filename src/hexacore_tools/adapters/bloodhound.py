"""enum.bloodhound — BloodHound-python collector adapter (Phase 3).

Runs the bloodhound-python ingestor to collect AD relationship data.  The output
is a ZIP of JSON files describing users, computers, groups, and domains.  This
adapter does NOT start BloodHound-CE or Neo4j — it just runs the collector and
reports what was gathered.
"""
from __future__ import annotations

import re

from ..base import CapabilityAdapter, Finding, Params, Severity
from hexacore.safety.actions import ActionClass


class BloodhoundCollectorAdapter(CapabilityAdapter):
    name = "enum.bloodhound"
    action_class = ActionClass.ACTIVE_SCAN

    def build_command(self, target: str, params: Params) -> list[str]:
        argv = ["bloodhound-python"]

        # Collection method (default: All)
        method = str(params.get("collection", "All"))
        argv.extend(["-c", method])

        # Domain
        if params.get("domain"):
            argv.extend(["-d", str(params["domain"])])

        # Domain controller / nameserver = target
        argv.extend(["-dc", target, "-ns", target])

        # Credentials
        if params.get("username"):
            argv.extend(["-u", str(params["username"])])
        if params.get("password"):
            argv.extend(["-p", str(params["password"])])

        # Output as zip
        argv.append("--zip")

        return argv

    def parse(self, raw: str, target: str) -> list[Finding]:
        if not raw.strip():
            return []

        findings: list[Finding] = []

        # Count collected items from the bloodhound-python output
        counts = {}
        for line in raw.splitlines():
            line = line.strip()
            # Typical output: "Done in 00m 02s, found 42 users, 15 computers, ..."
            for match in re.finditer(r"(\d+)\s+(users?|computers?|groups?|domains?|ous?|gpos?|containers?)", line.lower()):
                count = int(match.group(1))
                obj_type = match.group(2).rstrip("s")  # normalise plural
                counts[obj_type] = counts.get(obj_type, 0) + count

        if counts:
            summary_parts = [f"{v} {k}(s)" for k, v in sorted(counts.items())]
            findings.append(Finding(
                title=f"BloodHound Collection: {target}",
                severity=Severity.INFO,
                source=self.name,
                affected_asset=target,
                description=f"Collected AD data: {', '.join(summary_parts)}.",
                attack_techniques=["T1087"],
                evidence={"counts": counts, "raw": raw[:1000]},
            ))
        else:
            findings.append(Finding(
                title=f"BloodHound Collection: {target}",
                severity=Severity.INFO,
                source=self.name,
                affected_asset=target,
                description="BloodHound collector ran; review output for details.",
                attack_techniques=["T1087"],
                evidence={"raw": raw[:1000]},
            ))

        return findings
