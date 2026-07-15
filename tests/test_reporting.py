"""Reporting engine: HTML/PDF/DOCX render from a fixture engagement + report."""
from hexacore.models import AuthMethod, Authorization, Engagement, EngagementStatus, hash_scope
from hexacore.safety import ActionClass, Scope
from hexacore_tools import Finding, Severity
from hexacore_agent.runner import EngagementReport, RunEvent
from hexacore.findings import SeverityCounts
from hexacore_reporting import build_docx, build_html, build_pdf


def _fixture():
    scope = Scope(allow_domains=["acme-staging.com"], allow_cidrs=["10.20.30.0/24"],
                  deny_list=["10.20.30.5"], max_action_class=ActionClass.ACTIVE_SCAN)
    auth = Authorization(authorizer_name="Jane Doe", authorizer_email="jane@acme.example",
                         method=AuthMethod.CLICK_SIGN, scope_hash=hash_scope(scope))
    eng = Engagement(name="acme-staging", client="ACME Corp", created_by="op",
                     status=EngagementStatus.DONE, scope=scope, authorization=auth,
                     autonomy_profile="scan-only")
    findings = [
        Finding(title="Example High", severity=Severity.HIGH, source="scan.web_nuclei",
                affected_asset="api.acme-staging.com", cwe="CWE-79", cve=["CVE-2021-1"],
                attack_techniques=["T1190"], remediation="Patch it."),
        Finding(title="Open port 443", severity=Severity.INFO, source="scan.ports",
                affected_asset="10.20.30.11"),
    ]
    report = EngagementReport(
        engagement_id=eng.id, name=eng.name,
        counts=SeverityCounts(high=1, info=1), findings=findings,
        events=[RunEvent("phase.changed", "recon", "Recon phase"),
                RunEvent("command.started", "scan", "scan.ports -> 10.20.30.11")],
        gated=[], denied_targets=["evil.example.com"])
    return eng, report


def test_html_has_sections_and_findings():
    eng, report = _fixture()
    html = build_html(eng, report)
    assert "ACME Corp" in html
    assert "Scope &amp; Authorization" in html
    assert "Example High" in html and "CWE-79" in html
    assert "evil.example.com" in html          # appendix: denied target
    assert "Jane Doe" in html


def test_pdf_is_a_pdf():
    eng, report = _fixture()
    pdf = build_pdf(eng, report)
    assert pdf[:4] == b"%PDF" and len(pdf) > 500


def test_docx_is_a_zip_with_content():
    eng, report = _fixture()
    docx = build_docx(eng, report)
    assert docx[:2] == b"PK" and len(docx) > 1000   # docx is a zip
