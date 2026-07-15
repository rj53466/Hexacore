"""API tests via FastAPI TestClient — REST flow + WebSocket live feed. Uses a fixture backend
so findings surface through HTTP without running real tools.
"""
import pytest
from fastapi.testclient import TestClient

from hexacore.app.main import create_app
from hexacore.app.state import AppState
from hexacore_tools.backends.contract import RunResult

NUCLEI_OUT = ('{"template-id":"CVE-2021-1","matched-at":"https://api.acme-staging.com",'
              '"info":{"name":"Example High","severity":"high",'
              '"classification":{"cwe-id":["CWE-79"]}}}\n')
SUBFINDER_OUT = '{"host":"api.acme-staging.com"}\n'


class FixtureBackend:
    def run(self, argv, *, timeout=None, allowed_egress=None, runtime=None):
        tool = argv[0]
        if tool == "subfinder":
            return RunResult(stdout=SUBFINDER_OUT)
        if tool == "nuclei":
            return RunResult(stdout=NUCLEI_OUT)
        return RunResult(stdout="")


def make_client(backend=None, role="operator", auth=True):
    state = AppState(backend=backend)
    c = TestClient(create_app(state))
    if auth:
        tok = c.post("/auth/login", json={"username": role, "password": f"{role}-dev"}).json()
        c.headers["Authorization"] = f"Bearer {tok['access_token']}"
        c.hexa_token = tok["access_token"]  # for WS query param
    return c


def scoped_body(with_auth=True):
    body = {
        "name": "acme-staging", "client": "ACME",
        "scope": {"allow_domains": ["acme-staging.com"], "max_action_class": "active-scan"},
        "autonomy_profile": "scan-only",
        "seeds": {"domains": ["acme-staging.com"]},
    }
    if with_auth:
        body["authorization"] = {"authorizer_name": "Jane", "authorizer_email": "j@acme.example",
                                 "method": "click-sign"}
    return body


def test_health():
    c = make_client()
    r = c.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_unauthenticated_is_401():
    c = make_client(auth=False)
    assert c.get("/engagements").status_code == 401
    assert c.post("/engagements", json=scoped_body()).status_code == 401


def test_bad_credentials():
    c = make_client(auth=False)
    assert c.post("/auth/login", json={"username": "operator", "password": "wrong"}).status_code == 401


def test_viewer_cannot_mutate_but_can_read():
    c = make_client(role="viewer")
    assert c.get("/engagements").status_code == 200            # read allowed
    assert c.post("/engagements", json=scoped_body()).status_code == 403  # write denied


def test_ws_rejects_bad_token():
    import pytest as _pytest
    from starlette.websockets import WebSocketDisconnect as _WSD
    c = make_client()
    eid = c.post("/engagements", json=scoped_body()).json()["id"]
    with _pytest.raises(_WSD):
        with c.websocket_connect(f"/engagements/{eid}/ws?token=garbage") as ws:
            ws.receive_json()


def test_create_and_get_engagement():
    c = make_client()
    r = c.post("/engagements", json=scoped_body())
    assert r.status_code == 201
    eid = r.json()["id"]
    assert r.json()["has_authorization"] is True
    assert r.json()["authorization_bound"] is True

    got = c.get(f"/engagements/{eid}")
    assert got.status_code == 200 and got.json()["name"] == "acme-staging"


def test_run_produces_findings_through_api():
    c = make_client(backend=FixtureBackend())
    eid = c.post("/engagements", json=scoped_body()).json()["id"]
    r = c.post(f"/engagements/{eid}/run")
    assert r.status_code == 200
    body = r.json()
    assert body["counts"]["high"] >= 1
    findings = c.get(f"/engagements/{eid}/findings").json()
    assert any("Example High" in f["title"] for f in findings["findings"])


def test_run_without_authorization_is_400():
    c = make_client()
    eid = c.post("/engagements", json=scoped_body(with_auth=False)).json()["id"]
    r = c.post(f"/engagements/{eid}/run")
    assert r.status_code == 400
    assert "authorization" in r.json()["detail"]


def test_kill_switch_blocks_run():
    c = make_client()
    eid = c.post("/engagements", json=scoped_body()).json()["id"]
    assert c.post("/kill", json={"engagement_id": eid}).status_code == 200
    r = c.post(f"/engagements/{eid}/run")
    assert r.status_code == 400 and "kill switch" in r.json()["detail"]


def test_websocket_streams_live_events():
    c = make_client(backend=FixtureBackend())
    eid = c.post("/engagements", json=scoped_body()).json()["id"]
    types = []
    with c.websocket_connect(f"/engagements/{eid}/ws?token={c.hexa_token}") as ws:
        # The WS triggers the run and streams until run.complete.
        while True:
            msg = ws.receive_json()
            types.append(msg["type"])
            if msg["type"] == "run.complete":
                break
    assert "phase.changed" in types
    assert "finding.created" in types
    assert types[-1] == "run.complete"


def test_report_endpoints():
    c = make_client(backend=FixtureBackend())
    eid = c.post("/engagements", json=scoped_body()).json()["id"]
    # 409 before a run.
    assert c.get(f"/engagements/{eid}/report").status_code == 409
    c.post(f"/engagements/{eid}/run")
    html = c.get(f"/engagements/{eid}/report")
    assert html.status_code == 200 and "Penetration Test Report" in html.text
    pdf = c.get(f"/engagements/{eid}/report", params={"format": "pdf"})
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    docx = c.get(f"/engagements/{eid}/report", params={"format": "docx"})
    assert docx.status_code == 200 and docx.content[:2] == b"PK"


def test_missing_engagement_404():
    c = make_client()
    assert c.get("/engagements/nope").status_code == 404
    assert c.post("/engagements/nope/run").status_code == 404


def test_schedules_crud_rbac_and_tenant_isolation(tmp_path):
    from hexacore.persistence import SqlScheduleRepository
    state = AppState(backend=FixtureBackend())
    # Isolated temp-file repo (a per-call :memory: sqlite wouldn't survive between Sessions).
    state._schedule_repo = SqlScheduleRepository(f"sqlite:///{tmp_path.as_posix()}/sched.db")
    c = TestClient(create_app(state))

    def bearer(username: str) -> dict:
        tok = c.post("/auth/login", json={"username": username, "password": f"{username}-dev"}).json()
        return {"Authorization": f"Bearer {tok['access_token']}"}

    op, vw, opb = bearer("operator"), bearer("viewer"), bearer("operator-b")
    eid = c.post("/engagements", json=scoped_body(), headers=op).json()["id"]

    r = c.post(f"/engagements/{eid}/schedule", json={"cron": "0 2 * * *"}, headers=op)
    assert r.status_code == 201 and r.json()["next_run"] and r.json()["enabled"] is True
    sid = r.json()["id"]

    assert c.post(f"/engagements/{eid}/schedule", json={"cron": "nope"}, headers=op).status_code == 400
    assert len(c.get("/schedules", headers=op).json()) == 1

    # viewer (Client View): read yes, mutate no
    assert c.get("/schedules", headers=vw).status_code == 200
    assert c.post(f"/engagements/{eid}/schedule", json={"cron": "0 3 * * *"}, headers=vw).status_code == 403
    assert c.post(f"/schedules/{sid}/disable", headers=vw).status_code == 403

    # cross-tenant: tenant-b sees none and can't touch tenant-a's schedule
    assert c.get("/schedules", headers=opb).json() == []
    assert c.post(f"/schedules/{sid}/disable", headers=opb).status_code == 404

    assert c.post(f"/schedules/{sid}/disable", headers=op).json()["enabled"] is False


def test_run_events_persist_when_durable(tmp_path):
    from hexacore.persistence import SqlEventRepository
    url = f"sqlite:///{tmp_path.as_posix()}/ev.db"
    state = AppState(backend=FixtureBackend())
    state.event_repo = SqlEventRepository(url)   # durable (as if HEXACORE_DB_URL were set)
    c = TestClient(create_app(state))
    tok = c.post("/auth/login", json={"username": "operator", "password": "operator-dev"}).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    eid = c.post("/engagements", json=scoped_body(), headers=h).json()["id"]
    c.post(f"/engagements/{eid}/run", headers=h)

    # A fresh repo on the same DB (a restarted server) still sees the RunEvent history.
    reloaded = SqlEventRepository(url).list(eid, "tenant-a")
    assert reloaded and any(e["type"] == "phase.changed" for e in reloaded)
    # Tenant isolation holds at the event layer too.
    assert SqlEventRepository(url).list(eid, "tenant-b") == []
    # The API reads back the same recorded stream.
    assert len(c.get(f"/engagements/{eid}/events", headers=h).json()["events"]) == len(reloaded)


def test_report_persists_and_reads_back_after_restart(tmp_path):
    """Regression: /findings and /report must read the durable report store, so a restarted
    server still serves the severity donut + report for a run it did not hold in memory."""
    from hexacore.persistence import (
        SqlEngagementRepository, SqlEventRepository, SqlReportRepository)
    url = f"sqlite:///{tmp_path.as_posix()}/rep.db"

    def durable_state():
        s = AppState(backend=FixtureBackend())
        s.service.repo = SqlEngagementRepository(url)
        s.event_repo = SqlEventRepository(url)
        s.report_repo = SqlReportRepository(url)
        return s

    c1 = TestClient(create_app(durable_state()))
    tok = c1.post("/auth/login", json={"username": "operator", "password": "operator-dev"}).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    eid = c1.post("/engagements", json=scoped_body(), headers=h).json()["id"]
    c1.post(f"/engagements/{eid}/run", headers=h)

    # Fresh server on the same DB: never held this report in memory.
    c2 = TestClient(create_app(durable_state()))
    findings = c2.get(f"/engagements/{eid}/findings", headers=h).json()
    assert findings["counts"] is not None and findings["counts"]["high"] == 1
    assert any(f["severity"] == "high" for f in findings["findings"])
    assert c2.get(f"/engagements/{eid}/report?format=html", headers=h).status_code == 200


def test_durable_engagement_create_keeps_scope_and_runs(tmp_path):
    """Regression: with a durable repo, create must persist scope/auth under the caller's tenant
    (a stale re-save used to clobber it back to a scope-less draft, so /run 400'd)."""
    from hexacore.persistence import SqlEngagementRepository, SqlEventRepository
    url = f"sqlite:///{tmp_path.as_posix()}/full.db"
    state = AppState(backend=FixtureBackend())
    state.service.repo = SqlEngagementRepository(url)   # durable engagements
    state.event_repo = SqlEventRepository(url)
    c = TestClient(create_app(state))
    tok = c.post("/auth/login", json={"username": "operator", "password": "operator-dev"}).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}

    j = c.post("/engagements", json=scoped_body(), headers=h).json()
    assert j["status"] == "scoped"                       # was "draft" before the fix
    assert j["scope"]["max_action_class"] == "active-scan"
    assert j["has_authorization"] and j["authorization_bound"]
    eid = j["id"]

    # Persisted under the caller's tenant (tenant-a), not the loader default.
    assert SqlEngagementRepository(url).get(eid, "tenant-a") is not None
    assert SqlEngagementRepository(url).get(eid, "default") is None

    assert c.post(f"/engagements/{eid}/run", headers=h).status_code == 200


def test_schedule_monitoring_diffs_last_two_runs(tmp_path):
    import datetime
    from types import SimpleNamespace
    from hexacore.persistence import SqlScheduleRepository
    from hexacore.models import Schedule
    from hexacore_tools.base import Finding, Severity

    state = AppState(backend=FixtureBackend())
    state._schedule_repo = SqlScheduleRepository(f"sqlite:///{tmp_path.as_posix()}/s.db")
    c = TestClient(create_app(state))
    tok = c.post("/auth/login", json={"username": "operator", "password": "operator-dev"}).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}

    sched = Schedule(cron="0 2 * * *", target_engagement_id="base", tenant_id="tenant-a")
    state.schedule_repository().save(sched)

    # Two runs of the schedule (scheduler stamps clone.schedule_id), oldest first.
    e_prev = state.service.create(name="run1", client="c", created_by="scheduler", tenant_id="tenant-a")
    e_curr = state.service.create(name="run2", client="c", created_by="scheduler", tenant_id="tenant-a")
    for e, day in ((e_prev, 1), (e_curr, 2)):
        e.schedule_id = sched.id
        e.created_at = datetime.datetime(2026, 1, day, tzinfo=datetime.timezone.utc)
        state.service.repo.save(e)

    def F(title, sev, asset="10.0.0.1"):
        return Finding(title=title, severity=sev, source="scan", affected_asset=asset)

    from hexacore.findings.store import SeverityCounts
    open_port, xss, sqli = F("Open port", Severity.MEDIUM), F("XSS", Severity.HIGH), F("SQLi", Severity.CRITICAL)
    state.reports[e_prev.id] = SimpleNamespace(findings=[open_port, xss], counts=SeverityCounts(high=1, medium=1))
    state.reports[e_curr.id] = SimpleNamespace(findings=[xss, sqli], counts=SeverityCounts(critical=1, high=1))

    r = c.get(f"/schedules/{sched.id}/monitoring", headers=h).json()
    assert r["runs"] == 2
    d = r["delta"]
    assert d["new"] == 1 and d["fixed"] == 1 and d["persisting"] == 1
    assert d["new_by_severity"]["critical"] == 1 and d["alert"] is True
    assert r["current_run"]["id"] == e_curr.id

    # Trend: severity counts per run, oldest first.
    trend = c.get(f"/schedules/{sched.id}/trend", headers=h).json()["points"]
    assert [p["id"] for p in trend] == [e_prev.id, e_curr.id]
    assert trend[0]["counts"]["total"] == 2 and trend[1]["counts"]["critical"] == 1

    # Unknown schedule 404s; a schedule with <2 runs reports a null delta.
    assert c.get("/schedules/nope/monitoring", headers=h).status_code == 404
    assert c.get("/schedules/nope/trend", headers=h).status_code == 404
    lonely = Schedule(cron="0 2 * * *", target_engagement_id="base", tenant_id="tenant-a")
    state.schedule_repository().save(lonely)
    assert c.get(f"/schedules/{lonely.id}/monitoring", headers=h).json()["delta"] is None
