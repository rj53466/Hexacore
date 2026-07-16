"""Analysis phase enrichment."""
from __future__ import annotations

import re
from hexacore.findings.store import FindingStore
from hexacore_tools.base import Severity

_VULN_DB = {
    r"nginx\s*/?\s*1\.18\.0": {
        "cve": "CVE-2021-23017",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": Severity.CRITICAL,
        "description_append": "\n\n[Enrichment] Known vulnerable version detected. CVE-2021-23017: 1-byte memory overwrite in resolver."
    },
    r"apache\s*/?\s*2\.4\.49": {
        "cve": "CVE-2021-41773",
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": Severity.CRITICAL,
        "description_append": "\n\n[Enrichment] Known vulnerable version detected. CVE-2021-41773: Path traversal and file disclosure."
    },
    r"openssh\s*/?\s*8\.3": {
         "cve": "CVE-2020-15778",
         "severity": Severity.MEDIUM,
         "description_append": "\n\n[Enrichment] OpenSSH 8.3 scp command injection."
    }
}

def enrich_findings(store: FindingStore) -> None:
    """Scan existing findings for tech stack versions and enrich with CVE data."""
    for finding in store.all():
        text_to_check = f"{finding.title} {finding.description} {finding.evidence}".lower()
        
        for pattern, data in _VULN_DB.items():
            if re.search(pattern, text_to_check):
                # Apply enrichment
                if data.get("cve") and data["cve"] not in finding.cve:
                    finding.cve.append(data["cve"])
                
                if data.get("cvss") and not finding.cvss_vector:
                    finding.cvss_vector = data["cvss"]
                
                if data.get("severity"):
                    # Only upgrade severity, never downgrade
                    current_sev = Severity.parse(finding.severity)
                    if data["severity"].rank > current_sev.rank:
                        finding.severity = data["severity"]
                        
                if data.get("description_append") and data["description_append"] not in finding.description:
                    finding.description += data["description_append"]

    # Skill-guided enrichment: match each finding to the Heart/ corpus and (if a local LLM is
    # configured) draft remediation + next-steps from the technique. No-ops without an index/model.
    try:
        from .skill_advisor import enrich_with_skills
        enrich_with_skills(store)
    except Exception:
        pass
