"""Phase 5 monitoring: run-over-run finding diff (new / fixed / persisting) + alert flag."""
from hexacore.monitoring import diff_findings, delta_summary


def _f(key, sev="medium"):
    return {"dedup_key": key, "severity": sev, "title": key, "affected_asset": "10.0.0.1"}


def test_diff_splits_new_fixed_persisting():
    prev = [_f("a"), _f("b")]
    curr = [_f("b"), _f("c")]
    d = diff_findings(prev, curr)
    assert [x["dedup_key"] for x in d["new"]] == ["c"]
    assert [x["dedup_key"] for x in d["fixed"]] == ["a"]
    assert [x["dedup_key"] for x in d["persisting"]] == ["b"]


def test_delta_summary_alerts_on_new_high_or_critical():
    prev = [_f("a", "high")]                       # an existing high — not "new", must not alert
    curr = [_f("a", "high"), _f("b", "critical")]  # a newly-appeared critical — alert
    s = delta_summary(prev, curr)
    assert s["new"] == 1 and s["fixed"] == 0 and s["persisting"] == 1
    assert s["new_by_severity"]["critical"] == 1
    assert s["new_high_or_critical"] == 1 and s["alert"] is True


def test_no_new_urgent_findings_does_not_alert():
    base = [_f("a", "critical"), _f("b", "low")]
    # A clean re-run (identical findings) is not an alert, even with criticals present.
    assert delta_summary(base, base)["alert"] is False
    # A brand-new low-severity finding is a delta but not an alert.
    s = delta_summary(base, base + [_f("c", "low")])
    assert s["new"] == 1 and s["alert"] is False


def test_first_run_has_no_baseline():
    curr = [_f("a", "high"), _f("b", "info")]
    s = delta_summary([], curr)
    assert s["new"] == 2 and s["fixed"] == 0 and s["alert"] is True


def test_maybe_alert_fires_webhook_only_on_new_urgent(monkeypatch):
    from types import SimpleNamespace
    from hexacore.scheduler import maybe_alert

    # Stub state.monitoring so we test the alert branch in isolation.
    alerting = SimpleNamespace(monitoring=lambda sid, t: {"delta": {"alert": True, "new": 1}})
    calm = SimpleNamespace(monitoring=lambda sid, t: {"delta": {"alert": False, "new": 0}})
    sent = []

    monkeypatch.delenv("HEXACORE_ALERT_WEBHOOK", raising=False)
    assert maybe_alert(alerting, "s", "tenant-a", post=lambda u, p: sent.append(p)) is False  # no URL configured

    monkeypatch.setenv("HEXACORE_ALERT_WEBHOOK", "http://hook.test/x")
    assert maybe_alert(calm, "s", "tenant-a", post=lambda u, p: sent.append(p)) is False       # no new urgent finding
    assert sent == []
    assert maybe_alert(alerting, "s", "tenant-a", post=lambda u, p: sent.append(p)) is True     # fires
    assert len(sent) == 1 and sent[0]["event"] == "new_exposure"
