from hexacore_tools.adapters import NmapPortsAdapter, NucleiAdapter
from hexacore_tools import Severity

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.20.30.11" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.2p2"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NUCLEI_JSONL = (
    '{"template-id":"CVE-2021-1234","matched-at":"https://portal.acme-staging.com/x",'
    '"info":{"name":"Example RCE","severity":"critical",'
    '"classification":{"cwe-id":["CWE-78"],"cve-id":["CVE-2021-1234"]}}}\n'
    '{"template-id":"tech-detect","host":"portal.acme-staging.com",'
    '"info":{"name":"Nginx detected","severity":"info"}}\n'
    'not-json-garbage-line\n'
)


def test_nmap_build_command():
    argv = NmapPortsAdapter().build_command("10.20.30.11", {"top_ports": 100})
    assert argv[0] == "nmap" and "-oX" in argv and argv[-1] == "10.20.30.11"
    assert "--top-ports" in argv


def test_nmap_parses_only_open_ports():
    findings = NmapPortsAdapter().parse(NMAP_XML, "10.20.30.11")
    assert len(findings) == 2  # 443 is closed -> excluded
    titles = {f.title for f in findings}
    assert any("22/tcp" in t for t in titles)
    ssh = next(f for f in findings if "22/tcp" in f.title)
    assert ssh.severity is Severity.INFO
    assert ssh.evidence["version"] == "7.2p2"
    assert ssh.affected_asset == "10.20.30.11"


def test_nmap_handles_empty_and_bad_xml():
    assert NmapPortsAdapter().parse("", "x") == []
    assert NmapPortsAdapter().parse("<not-xml", "x") == []


def test_nuclei_build_command():
    argv = NucleiAdapter().build_command("https://portal.acme-staging.com",
                                         {"severity": "critical,high"})
    assert argv[:3] == ["nuclei", "-u", "https://portal.acme-staging.com"]
    assert "-jsonl" in argv and "-severity" in argv


def test_nuclei_parses_jsonl_and_maps_severity():
    findings = NucleiAdapter().parse(NUCLEI_JSONL, "portal.acme-staging.com")
    assert len(findings) == 2  # garbage line skipped
    crit = next(f for f in findings if f.severity is Severity.CRITICAL)
    assert crit.cwe == "CWE-78"
    assert crit.cve == ["CVE-2021-1234"]
    assert crit.title == "Example RCE"


def test_findings_dedup_key_stable_across_sources():
    a = NucleiAdapter().parse(NUCLEI_JSONL, "portal.acme-staging.com")[0]
    # Same asset + title + cwe -> same dedup key regardless of source label.
    from hexacore_tools import Finding
    b = Finding(title=a.title, severity=a.severity, source="scan.web_dast_zap",
                affected_asset=a.affected_asset, cwe=a.cwe)
    assert a.dedup_key == b.dedup_key
