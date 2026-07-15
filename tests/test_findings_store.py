from hexacore.findings import FindingStore
from hexacore_tools import Finding, Severity


def f(title, sev, source, asset, cwe=None):
    return Finding(title=title, severity=sev, source=source, affected_asset=asset, cwe=cwe)


def test_add_new_and_counts():
    store = FindingStore()
    store.add(f("SQLi", Severity.HIGH, "scan.web_nuclei", "a.test"))
    store.add(f("Open 22", Severity.INFO, "scan.ports", "a.test"))
    store.add(f("XSS", Severity.MEDIUM, "scan.web_nuclei", "a.test"))
    c = store.counts()
    assert (c.high, c.medium, c.info, c.total) == (1, 1, 1, 3)


def test_dedup_across_sources_keeps_one_and_remembers_sources():
    store = FindingStore()
    a = f("Missing HSTS header", Severity.LOW, "scan.web_nuclei", "a.test", cwe="CWE-693")
    b = f("Missing HSTS header", Severity.LOW, "scan.web_dast_zap", "a.test", cwe="CWE-693")
    assert store.add(a) is True
    assert store.add(b) is False           # merged
    assert len(store) == 1
    assert store.sources_for(a) == {"scan.web_nuclei", "scan.web_dast_zap"}


def test_dedup_keeps_higher_severity():
    store = FindingStore()
    store.add(f("Thing", Severity.LOW, "s1", "a.test", cwe="CWE-1"))
    store.add(f("Thing", Severity.CRITICAL, "s2", "a.test", cwe="CWE-1"))
    assert store.counts().critical == 1
    assert store.counts().low == 0


def test_all_sorted_most_severe_first():
    store = FindingStore()
    store.add(f("i", Severity.INFO, "s", "a.test"))
    store.add(f("c", Severity.CRITICAL, "s", "b.test"))
    store.add(f("m", Severity.MEDIUM, "s", "c.test"))
    severities = [x.severity for x in store.all()]
    assert severities == [Severity.CRITICAL, Severity.MEDIUM, Severity.INFO]
