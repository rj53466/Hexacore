import pytest

from hexacore.safety import ActionClass, ActionClassifier, UnknownCapability, requires_gate


def test_passive_recon_is_passive():
    c = ActionClassifier()
    assert c.classify("recon.subdomains") is ActionClass.PASSIVE


def test_active_scan_class():
    c = ActionClassifier()
    assert c.classify("scan.web_nuclei") is ActionClass.ACTIVE_SCAN


def test_unknown_capability_defaults_destructive():
    # Deny-by-default extends to classification: unknown => most dangerous => always gated.
    c = ActionClassifier()
    cls = c.classify("mystery.capability")
    assert cls is ActionClass.DESTRUCTIVE
    assert requires_gate(cls)


def test_unknown_capability_strict_raises():
    c = ActionClassifier(strict=True)
    with pytest.raises(UnknownCapability):
        c.classify("mystery.capability")


def test_sqlmap_detection_is_scan_but_extraction_is_exploit():
    c = ActionClassifier()
    assert c.classify("verify.web_sqli", {"mode": "detection"}) is ActionClass.ACTIVE_SCAN
    assert c.classify("verify.web_sqli", {"mode": "exploit"}) is ActionClass.ACTIVE_EXPLOIT
    assert c.classify("verify.web_sqli", {"os_shell": True}) is ActionClass.DESTRUCTIVE


def test_msf_check_is_scan_but_exploit_is_destructive():
    c = ActionClassifier()
    assert c.classify("verify.msf_check", {"action": "check"}) is ActionClass.ACTIVE_SCAN
    assert c.classify("verify.msf_check", {"action": "exploit"}) is ActionClass.DESTRUCTIVE


def test_verify_default_requires_gate():
    c = ActionClassifier()
    assert requires_gate(c.classify("verify.idor"))
