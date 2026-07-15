"""Phase 5 — continuous attack-surface monitoring.

Diffs the findings of two runs of the same recurring engagement into new / fixed / persisting,
so the console can show run-over-run deltas and alert when a new exposure appears. Findings match
across runs by their stable ``dedup_key`` (asset|title|cwe). Pure functions over finding dicts —
no I/O — so they're trivially testable and reusable by the API, the report layer, and alerts.
"""
from __future__ import annotations

_ALERT_SEVERITIES = ("critical", "high")
_SEV_KEYS = ("critical", "high", "medium", "low", "info")


def diff_findings(previous: list[dict], current: list[dict]) -> dict:
    """Split findings into new (only in current), fixed (only in previous), persisting (both)."""
    prev = {f["dedup_key"]: f for f in previous}
    curr = {f["dedup_key"]: f for f in current}
    return {
        "new": [curr[k] for k in curr if k not in prev],
        "fixed": [prev[k] for k in prev if k not in curr],
        "persisting": [curr[k] for k in curr if k in prev],
    }


def _by_severity(findings: list[dict]) -> dict:
    out = {k: 0 for k in _SEV_KEYS}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        if sev in out:
            out[sev] += 1
    return out


def delta_summary(previous: list[dict], current: list[dict]) -> dict:
    """Run-over-run delta: counts, per-severity breakdown of new/fixed, and an alert flag that
    trips when a critical/high finding newly appears (the signal a monitoring product acts on)."""
    d = diff_findings(previous, current)
    new_by_sev = _by_severity(d["new"])
    newly_urgent = sum(new_by_sev[s] for s in _ALERT_SEVERITIES)
    return {
        "new": len(d["new"]),
        "fixed": len(d["fixed"]),
        "persisting": len(d["persisting"]),
        "new_by_severity": new_by_sev,
        "fixed_by_severity": _by_severity(d["fixed"]),
        "new_high_or_critical": newly_urgent,
        "alert": newly_urgent > 0,
        "findings": d,
    }


if __name__ == "__main__":  # ponytail: runnable self-check for the diff logic
    prev = [
        {"dedup_key": "a", "severity": "medium", "title": "Open port"},
        {"dedup_key": "b", "severity": "high", "title": "XSS"},
    ]
    curr = [
        {"dedup_key": "b", "severity": "high", "title": "XSS"},
        {"dedup_key": "c", "severity": "critical", "title": "SQLi"},
    ]
    s = delta_summary(prev, curr)
    assert s["new"] == 1 and s["fixed"] == 1 and s["persisting"] == 1, s
    assert s["new_by_severity"]["critical"] == 1 and s["alert"] is True, s
    # No previous run at all → everything is new; a clean re-run → no delta.
    assert delta_summary([], curr)["new"] == 2
    assert delta_summary(curr, curr) == delta_summary(curr, curr)
    assert delta_summary(curr, curr)["new"] == 0 and delta_summary(curr, curr)["alert"] is False
    print("monitoring self-check OK")
