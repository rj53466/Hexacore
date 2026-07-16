"""Tests for Phase 3 adapters (IDOR, SSRF, NetExec, Certipy, BloodHound) and chaining logic."""
import pytest
from hexacore_tools.adapters.idor_ssrf import IdorVerifier, SsrfVerifier
from hexacore_tools.adapters.netexec import NetexecAdapter
from hexacore_tools.adapters.certipy import CertipyFindAdapter
from hexacore_tools.adapters.bloodhound import BloodhoundCollectorAdapter
from hexacore_tools.base import Severity


# ─── IDOR Verifier ─────────────────────────────────────────────────

class TestIdorVerifier:
    def test_build_command(self):
        a = IdorVerifier()
        cmd = a.build_command("https://app.example.com/api/users/42", {})
        assert "curl" in cmd
        assert "https://app.example.com/api/users/42" in cmd

    def test_parse_object_endpoint_is_unverified_medium(self):
        # An object-addressing URL (/users/42) returning a real body is an UNVERIFIED lead — a real
        # IDOR needs a cross-identity comparison this single-target adapter can't do.
        a = IdorVerifier()
        raw = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
               "{\"id\": 42, \"email\": \"alice@example.com\"}\n200")
        findings = a.parse(raw, "https://app.example.com/api/users/42")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].cwe == "CWE-639"
        assert findings[0].evidence.get("unverified") is True

    def test_parse_no_object_reference_is_ignored(self):
        # A plain 2xx page with no id/UUID/id-param in the URL must NOT be flagged (no false flood).
        a = IdorVerifier()
        raw = "HTTP/1.1 200 OK\r\n\r\n<html>welcome home page body</html>\n200"
        assert a.parse(raw, "https://app.example.com/home") == []

    def test_parse_empty_body_is_ignored(self):
        a = IdorVerifier()
        raw = "HTTP/1.1 200 OK\r\n\r\n\n200"
        assert a.parse(raw, "https://app.example.com/api/users/42") == []

    def test_parse_403_no_finding(self):
        a = IdorVerifier()
        raw = "HTTP/1.1 403 Forbidden\r\n\r\nAccess Denied to this object\n403"
        findings = a.parse(raw, "https://app.example.com/api/users/42")
        assert findings == []

    def test_parse_empty(self):
        a = IdorVerifier()
        assert a.parse("", "x") == []


# ─── SSRF Verifier ─────────────────────────────────────────────────

class TestSsrfVerifier:
    def test_build_command(self):
        a = SsrfVerifier()
        cmd = a.build_command("https://app.example.com/proxy?url=http://169.254.169.254", {})
        assert "curl" in cmd

    def test_parse_aws_metadata_leak(self):
        a = SsrfVerifier()
        raw = '{"ami-id": "ami-12345678", "instance-id": "i-abcdef"}\n200'
        findings = a.parse(raw, "https://app.example.com/proxy")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].cwe == "CWE-918"
        assert "ami-id" in findings[0].evidence["canaries"]

    def test_parse_no_canary(self):
        a = SsrfVerifier()
        raw = "Normal page content\n200"
        findings = a.parse(raw, "https://app.example.com/proxy")
        assert findings == []

    def test_parse_etc_passwd_leak(self):
        a = SsrfVerifier()
        raw = "root:x:0:0:root:/root:/bin/bash\n200"
        findings = a.parse(raw, "http://target/file")
        assert len(findings) == 1
        assert "root:x:0:0" in findings[0].evidence["canaries"]


# ─── NetExec Adapter ───────────────────────────────────────────────

class TestNetexecAdapter:
    def test_build_command_defaults(self):
        a = NetexecAdapter()
        cmd = a.build_command("192.168.1.10", {})
        assert cmd == ["nxc", "smb", "192.168.1.10"]

    def test_build_command_with_creds_and_shares(self):
        a = NetexecAdapter()
        cmd = a.build_command("10.0.0.1", {"username": "admin", "password": "pass", "shares": True})
        assert "-u" in cmd and "admin" in cmd
        assert "--shares" in cmd

    def test_parse_shares(self):
        a = NetexecAdapter()
        raw = (
            "SMB  10.0.0.1  445  DC01  [*] Windows Server 2019\n"
            "SMB  10.0.0.1  445  DC01  ADMIN$  READ,WRITE\n"
            "SMB  10.0.0.1  445  DC01  C$      READ\n"
        )
        findings = a.parse(raw, "10.0.0.1")
        assert len(findings) == 2  # two share lines with READ/WRITE
        # WRITE share = MEDIUM, READ only = LOW
        sevs = sorted([f.severity for f in findings], key=lambda s: s.value)
        assert Severity.LOW in sevs or Severity.MEDIUM in sevs

    def test_parse_signing_disabled(self):
        a = NetexecAdapter()
        raw = "SMB  10.0.0.1  445  DC01  [*] signing: False\n"
        findings = a.parse(raw, "10.0.0.1")
        assert any("Signing" in f.title for f in findings)

    def test_parse_empty_output_info(self):
        a = NetexecAdapter()
        raw = "SMB  10.0.0.1  445  DC01  [*] Some generic info\n"
        findings = a.parse(raw, "10.0.0.1")
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO


# ─── Certipy Find Adapter ─────────────────────────────────────────

class TestCertipyFindAdapter:
    def test_build_command(self):
        a = CertipyFindAdapter()
        cmd = a.build_command("10.0.0.5", {"username": "user@domain", "password": "pass"})
        assert "certipy-ad" in cmd and "find" in cmd
        assert "-dc-ip" in cmd and "10.0.0.5" in cmd

    def test_parse_json_vulnerable(self):
        import json
        a = CertipyFindAdapter()
        data = {"certificate_templates": [
            {"name": "ESC1-Vuln", "vulnerabilities": ["ESC1"]},
            {"name": "Safe-Template", "vulnerabilities": []},
        ]}
        findings = a.parse(json.dumps(data), "10.0.0.5")
        assert len(findings) == 2
        vuln = [f for f in findings if f.severity == Severity.HIGH]
        assert len(vuln) == 1
        assert "ESC1" in vuln[0].title

    def test_parse_text_esc_detection(self):
        a = CertipyFindAdapter()
        raw = "[!] Template 'WebServer' is vulnerable to ESC1\n[!] Template 'User' is vulnerable to ESC4"
        findings = a.parse(raw, "10.0.0.5")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "ESC1" in findings[0].evidence["escalation_paths"]
        assert "ESC4" in findings[0].evidence["escalation_paths"]

    def test_parse_empty(self):
        a = CertipyFindAdapter()
        assert a.parse("", "x") == []


# ─── BloodHound Collector Adapter ─────────────────────────────────

class TestBloodhoundCollectorAdapter:
    def test_build_command(self):
        a = BloodhoundCollectorAdapter()
        cmd = a.build_command("10.0.0.5", {"domain": "corp.local", "username": "user", "password": "pass"})
        assert "bloodhound-python" in cmd
        assert "-c" in cmd and "All" in cmd
        assert "--zip" in cmd

    def test_parse_collection_output(self):
        a = BloodhoundCollectorAdapter()
        raw = (
            "INFO: Found AD domain: corp.local\n"
            "INFO: Done in 00m 05s, found 142 users, 38 computers, 12 groups, 1 domains\n"
        )
        findings = a.parse(raw, "10.0.0.5")
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert findings[0].evidence["counts"]["user"] == 142

    def test_parse_empty(self):
        a = BloodhoundCollectorAdapter()
        assert a.parse("", "x") == []


# ─── Chaining Logic ───────────────────────────────────────────────

class TestChainingLogic:
    def test_chain_smb_finding_triggers_netexec(self):
        from hexacore_tools.base import Finding, Severity
        from hexacore.findings.store import FindingStore
        from hexacore_agent.runner import _chain_capabilities

        store = FindingStore()
        store.add_many([Finding(
            title="Open port 445/tcp (microsoft-ds)",
            severity=Severity.INFO,
            source="scan.ports",
            affected_asset="10.0.0.1",
            description="SMB port open",
            evidence={"port": 445},
        )])
        chained = _chain_capabilities(store)
        assert "enum.netexec" in chained

    def test_chain_ldap_finding_triggers_bloodhound(self):
        from hexacore_tools.base import Finding, Severity
        from hexacore.findings.store import FindingStore
        from hexacore_agent.runner import _chain_capabilities

        store = FindingStore()
        store.add_many([Finding(
            title="Open port 389/tcp (LDAP)",
            severity=Severity.INFO,
            source="scan.ports",
            affected_asset="10.0.0.1",
            description="LDAP service detected",
            evidence={"port": 389},
        )])
        chained = _chain_capabilities(store)
        assert "enum.bloodhound" in chained

    def test_chain_adcs_finding_triggers_certipy(self):
        from hexacore_tools.base import Finding, Severity
        from hexacore.findings.store import FindingStore
        from hexacore_agent.runner import _chain_capabilities

        store = FindingStore()
        store.add_many([Finding(
            title="Active Directory Certificate Services (ADCS) endpoint",
            severity=Severity.INFO,
            source="scan.web_nuclei",
            affected_asset="10.0.0.5",
            description="certsrv endpoint found",
            evidence={},
        )])
        chained = _chain_capabilities(store)
        assert "verify.adcs_find" in chained

    def test_chain_no_match_returns_empty(self):
        from hexacore_tools.base import Finding, Severity
        from hexacore.findings.store import FindingStore
        from hexacore_agent.runner import _chain_capabilities

        store = FindingStore()
        store.add_many([Finding(
            title="HTTP 200 OK",
            severity=Severity.INFO,
            source="recon.http_probe",
            affected_asset="example.com",
            description="Web server running",
            evidence={},
        )])
        chained = _chain_capabilities(store)
        assert chained == set()
