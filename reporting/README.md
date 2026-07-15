# reporting/ — report engine (Brain/01 §3.7)

`hexacore_reporting.render(engagement, report, fmt)` → HTML / PDF / DOCX. One inline Jinja2
template drives HTML; **xhtml2pdf** (pure-Python) turns it into PDF — WeasyPrint was dropped
because it needs native GTK/pango libs that don't ship on Windows. DOCX via python-docx.

Sections: title, scope + authorization statement, severity summary, methodology, findings
(CWE/CVE/ATT&CK/remediation), retest checklist, appendix (scope-denied targets).

Consumed by:
- `make engage` → writes `reports/<name>-report.{html,pdf,docx}` after a run.
- API `GET /engagements/{id}/report?format=html|pdf|docx`.
