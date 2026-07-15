from hexacore_tools import Severity
from hexacore_tools.adapters import HttpxAdapter, SubfinderAdapter, default_registry


def test_default_registry_has_phase1_shortlist():
    names = set(default_registry().names())
    assert {"recon.subdomains", "recon.http_probe", "scan.ports", "scan.web_nuclei"} <= names


def test_subfinder_build_and_parse_json():
    a = SubfinderAdapter()
    assert a.build_command("example.com", {})[:3] == ["subfinder", "-d", "example.com"]
    raw = ('{"host":"api.example.com"}\n'
           '{"host":"dev.example.com"}\n'
           '{"host":"api.example.com"}\n')  # dup
    findings = a.parse(raw, "example.com")
    hosts = {f.affected_asset for f in findings}
    assert hosts == {"api.example.com", "dev.example.com"}
    assert all(f.severity is Severity.INFO for f in findings)


def test_subfinder_parses_plain_lines():
    findings = SubfinderAdapter().parse("a.example.com\nb.example.com\n", "example.com")
    assert {f.evidence["host"] for f in findings} == {"a.example.com", "b.example.com"}


def test_httpx_parse_json():
    raw = ('{"url":"https://api.example.com","status_code":200,"title":"API",'
           '"tech":["nginx"],"host":"api.example.com","webserver":"nginx"}\n'
           'garbage\n')
    findings = HttpxAdapter().parse(raw, "api.example.com")
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["status_code"] == 200
    assert f.evidence["tech"] == ["nginx"]
    assert "API" in f.description
