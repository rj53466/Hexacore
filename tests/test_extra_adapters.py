from hexacore_tools import Severity
from hexacore_tools.adapters import (
    CrtShAdapter, DnsxAdapter, FfufAdapter, NiktoAdapter, TestsslAdapter, WhatwebAdapter,
    default_registry,
)


def test_registry_has_ten_phase1_capabilities():
    names = set(default_registry().names())
    assert names >= {"recon.subdomains", "recon.http_probe", "recon.dns", "recon.tech",
                     "recon.ct_logs", "scan.ports", "scan.web_nuclei", "scan.tls",
                     "scan.web_dir", "scan.web_nikto"}


def test_dnsx_parse():
    f = DnsxAdapter().parse('{"host":"api.x.test","a":["10.0.0.1"]}\ngarbage\n', "x.test")
    assert len(f) == 1 and f[0].affected_asset == "api.x.test" and f[0].evidence["a"] == ["10.0.0.1"]


def test_whatweb_parse_array_and_lines():
    arr = '[{"target":"http://x.test","http_status":200,"plugins":{"nginx":{},"jQuery":{}}}]'
    f = WhatwebAdapter().parse(arr, "x.test")
    assert f and "nginx" in f[0].evidence["tech"] and "jQuery" in f[0].evidence["tech"]


def test_crtsh_dedup_and_wildcard_strip():
    raw = '[{"name_value":"*.x.test\\napi.x.test"},{"name_value":"api.x.test"}]'
    f = CrtShAdapter().parse(raw, "x.test")
    assets = {x.affected_asset for x in f}
    assert assets == {"x.test", "api.x.test"}  # *. stripped, deduped


def test_testssl_maps_severity_skips_ok():
    raw = ('[{"id":"BREACH","severity":"HIGH","finding":"vulnerable","ip":"1.2.3.4"},'
           '{"id":"cipher","severity":"OK","finding":"fine"}]')
    f = TestsslAdapter().parse(raw, "x.test")
    assert len(f) == 1 and f[0].severity is Severity.HIGH


def test_ffuf_parse_results():
    raw = '{"results":[{"url":"http://x.test/admin","status":200,"length":10}]}'
    f = FfufAdapter().parse(raw, "http://x.test")
    assert f and "admin" in f[0].affected_asset and f[0].severity is Severity.INFO


def test_nikto_parse_vulns():
    raw = '{"vulnerabilities":[{"id":"1","url":"http://x.test/","msg":"Server leaks version"}]}'
    f = NiktoAdapter().parse(raw, "http://x.test")
    assert f and f[0].severity is Severity.LOW and "leaks" in f[0].description


def test_all_parsers_handle_empty():
    for A in (DnsxAdapter, WhatwebAdapter, CrtShAdapter, TestsslAdapter, FfufAdapter, NiktoAdapter):
        assert A().parse("", "x.test") == []
        assert A().parse("not-json", "x.test") == []
