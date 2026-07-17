"""FastAPI app: create/run engagements, stream the live feed, view findings, resolve gates.

Run: `uvicorn hexacore.app.main:app --reload` (from `api/`, or with `api/` on PYTHONPATH).
The tool-runner backend defaults to `dryrun` in the API unless HEXACORE_RUNNER_BACKEND is set,
so the server never executes real tools by accident.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect

from hexacore.engagements import EngagementError
from hexacore.loader import create_from_mapping
from hexacore.safety.approval import ApprovalState, GateError

from .auth import authenticate, create_token, decode_token, require_min_role, OIDC_DISCOVERY_URL, OIDC_CLIENT_ID
from .schemas import ApprovalResolve, EngagementCreate, KillRequest, LoginRequest, ScheduleCreate, TenantConfigModel
from .state import AppState


def _engagement_dict(eng) -> dict:
    return {
        "id": eng.id,
        "name": eng.name,
        "client": eng.client,
        "status": eng.status.value,
        "autonomy_profile": eng.autonomy_profile,
        "has_authorization": eng.authorization is not None,
        "authorization_bound": eng.authorization_matches_scope(),
        "scope": {
            "allow_domains": eng.scope.allow_domains if eng.scope else [],
            "allow_cidrs": eng.scope.allow_cidrs if eng.scope else [],
            "deny_list": eng.scope.deny_list if eng.scope else [],
            "max_action_class": eng.scope.max_action_class.value if eng.scope else None,
        },
    }


def _schedule_dict(s) -> dict:
    return {
        "id": s.id, "cron": s.cron, "target_engagement_id": s.target_engagement_id,
        "tenant_id": s.tenant_id, "enabled": s.enabled,
        "next_run": s.next_run.isoformat() if s.next_run else None,
    }


def _approval_dict(a) -> dict:
    return {
        "id": a.id, "tool_run_id": a.tool_run_id, "capability": a.capability,
        "target": a.target, "action_class": a.action_class, "state": a.state.value,
        "resume_token": a.resume_token, "requested_at": a.requested_at.isoformat(),
    }


def create_app(state: AppState | None = None) -> FastAPI:
    state = state or AppState()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        from hexacore.scheduler import Scheduler

        state.bus.bind_loop(asyncio.get_running_loop())

        scheduler = Scheduler(state, state.schedule_repository())
        scheduler.start()
        
        yield
        
        scheduler.stop()

    app = FastAPI(title="HexaCore API", version="0.1.0", lifespan=lifespan)
    app.state.hexa = state

    # ponytail: dev CORS for the local console. Tighten allow_origins for production.
    from fastapi.middleware.cors import CORSMiddleware
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
    )

    from pathlib import Path
    from fastapi import Request
    from fastapi.responses import FileResponse

    dist_dir = Path(__file__).resolve().parent.parent.parent.parent / "console" / "dist"

    # `GET /engagements` is both a React Router page and a JSON API route — a direct browser
    # navigation (refresh, bookmark, typed URL) has no way to reach the SPA catch-all below since
    # this exact path is already registered. `Sec-Fetch-Mode: navigate` is the browser-native,
    # non-spoofable-by-accident signal for "this is an address-bar/link page load" — it's `cors`
    # for our own console's fetch() calls, and absent entirely for curl/TestClient/API clients, so
    # non-browser callers still hit the real route and get a real 401 (see test_unauthenticated_is_401).
    @app.middleware("http")
    async def spa_route_collision_fallback(request: Request, call_next):
        if (request.method == "GET" and request.url.path == "/engagements"
                and request.headers.get("sec-fetch-mode") == "navigate"
                and (dist_dir / "index.html").exists()):
            return FileResponse(dist_dir / "index.html")
        return await call_next(request)

    # RBAC: reads need viewer, mutations need operator (owner outranks both) — enforced per-route
    # via Depends(require_min_role(...)) on each endpoint below.

    def require(engagement_id: str, tenant_id: str):
        eng = state.service.repo.get(engagement_id, tenant_id=tenant_id)
        if eng is None:
            raise HTTPException(status_code=404, detail="engagement not found")
        return eng

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "backend": state.settings.backend}

    @app.get("/llm/status")
    async def llm_status(user: dict = Depends(require_min_role("viewer"))) -> dict:
        """Local-LLM (Ollama) health for the dashboard: enabled? reachable? model pulled?"""
        import json as _json
        import os as _os
        import urllib.request as _url

        profile = _os.getenv("HEXACORE_MODEL_PROFILE", "deterministic")
        model = _os.getenv("HEXACORE_OLLAMA_MODEL", "qwen2.5:7b")
        host = _os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        if profile not in ("ollama", "local"):
            return {"profile": profile, "enabled": False, "reachable": False,
                    "model": model, "model_ready": False,
                    "detail": "deterministic mode — LLM off (scanner runs offline)"}

        def _probe() -> dict:
            try:
                with _url.urlopen(host + "/api/tags", timeout=2.0) as r:
                    names = [m.get("name", "") for m in _json.loads(r.read()).get("models", [])]
                ready = any(n == model or n.split(":")[0] == model.split(":")[0] for n in names)
                return {"profile": profile, "enabled": True, "reachable": True, "model": model,
                        "model_ready": ready, "host": host,
                        "detail": "model ready" if ready else f"{model} not pulled — run: ollama pull {model}"}
            except Exception as exc:
                return {"profile": profile, "enabled": True, "reachable": False, "model": model,
                        "model_ready": False, "host": host, "detail": f"Ollama unreachable: {exc}"}

        # Don't block the event loop on the socket probe.
        return await asyncio.get_running_loop().run_in_executor(None, _probe)

    @app.post("/auth/login")
    async def login(body: LoginRequest) -> dict:
        user = authenticate(body.username, body.password)
        if user is None:
            raise HTTPException(status_code=401, detail="bad credentials")
        return {"access_token": create_token(user["username"], user["role"], user["tenant_id"]),
                "token_type": "bearer", "role": user["role"]}

    @app.get("/auth/sso/login")
    async def sso_login():
        if not OIDC_DISCOVERY_URL:
            raise HTTPException(status_code=400, detail="SSO not configured")
        # In a real app, you'd fetch the authorization_endpoint from the OIDC discovery URL,
        # build the URL with client_id, redirect_uri, response_type=code, and state,
        # and return a 302 Redirect.
        # For MVP, we'll return the mock redirect URL.
        from fastapi.responses import RedirectResponse
        import httpx
        try:
            resp = httpx.get(OIDC_DISCOVERY_URL, timeout=5.0)
            resp.raise_for_status()
            auth_endpoint = resp.json().get("authorization_endpoint")
            return RedirectResponse(f"{auth_endpoint}?client_id={OIDC_CLIENT_ID}&response_type=code&redirect_uri=http://localhost:8000/auth/sso/callback")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to fetch OIDC configuration: {e}")

    @app.get("/auth/sso/callback")
    async def sso_callback(code: str):
        if not OIDC_DISCOVERY_URL:
            raise HTTPException(status_code=400, detail="SSO not configured")
        # In a real app, exchange code for tokens at the token_endpoint,
        # validate the ID token, and extract claims.
        # Here we mock the behavior for demonstration and return our internal token.
        # We would decode the ID token to get role and tenant_id.
        username = "sso-user"
        role = "operator"
        tenant_id = "tenant-a"
        internal_token = create_token(username, role, tenant_id)
        from fastapi.responses import RedirectResponse
        return RedirectResponse(f"http://localhost:5173/?token={internal_token}")

    @app.get("/tenant/config")
    async def get_tenant_config(user: dict = Depends(require_min_role("viewer"))) -> dict:
        from hexacore.persistence import TenantConfigRepository
        webhook = TenantConfigRepository().get_webhook(user["tenant_id"])
        return {"alert_webhook": webhook}

    @app.post("/tenant/config")
    async def set_tenant_config(body: TenantConfigModel, user: dict = Depends(require_min_role("owner"))) -> dict:
        from hexacore.persistence import TenantConfigRepository
        TenantConfigRepository().set_webhook(user["tenant_id"], body.alert_webhook or "")
        return {"alert_webhook": body.alert_webhook}

    # -- engagements ------------------------------------------------------
    @app.post("/engagements", status_code=201)
    async def create_engagement(body: EngagementCreate, user: dict = Depends(require_min_role("operator"))) -> dict:
        try:
            loaded = create_from_mapping(body.to_mapping(), state.service, actor="api",
                                         tenant_id=user["tenant_id"])
        except (ValueError, EngagementError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        state.seeds[loaded.engagement.id] = (loaded.seed_domains, loaded.seed_hosts)
        return _engagement_dict(loaded.engagement)

    @app.get("/engagements")
    async def list_engagements(user: dict = Depends(require_min_role("viewer"))) -> list[dict]:
        return [_engagement_dict(e) for e in state.service.repo.list(tenant_id=user["tenant_id"])]

    @app.get("/engagements/{engagement_id}")
    async def get_engagement(engagement_id: str, user: dict = Depends(require_min_role("viewer"))) -> dict:
        return _engagement_dict(require(engagement_id, user["tenant_id"]))

    @app.post("/engagements/{engagement_id}/run")
    async def run_engagement(engagement_id: str, user: dict = Depends(require_min_role("operator"))) -> dict:
        require(engagement_id, user["tenant_id"])
        domains, hosts = state.seeds.get(engagement_id, ([], []))
        try:
            report = await state.run_engagement(engagement_id, user["tenant_id"], seed_domains=domains,
                                                 seed_hosts=hosts)
        except EngagementError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {
            "engagement_id": engagement_id,
            "counts": report.counts.to_dict(),
            "findings": [f.to_dict() for f in report.findings],
            "denied_targets": sorted(set(report.denied_targets)),
            "gated": len(report.gated),
            "events": len(report.events),
        }

    @app.get("/engagements/{engagement_id}/findings")
    async def get_findings(engagement_id: str, user: dict = Depends(require_min_role("viewer"))) -> dict:
        require(engagement_id, user["tenant_id"])
        report = state.report_for(engagement_id, user["tenant_id"])
        if report is None:
            return {"findings": [], "counts": None}
        return {"findings": [f.to_dict() for f in report.findings],
                "counts": report.counts.to_dict()}

    @app.get("/engagements/{engagement_id}/events")
    async def get_events(engagement_id: str, user: dict = Depends(require_min_role("viewer"))) -> dict:
        require(engagement_id, user["tenant_id"])
        return {"events": state.events_for(engagement_id, user["tenant_id"])}

    @app.get("/engagements/{engagement_id}/report")
    async def get_report(engagement_id: str, format: str = "html", user: dict = Depends(require_min_role("viewer"))):
        from fastapi.responses import HTMLResponse, Response
        from hexacore_reporting import render
        eng = require(engagement_id, user["tenant_id"])
        report = state.report_for(engagement_id, user["tenant_id"])
        if report is None:
            raise HTTPException(status_code=409, detail="run the engagement before reporting")
        if format == "html":
            return HTMLResponse(render(eng, report, "html"))
        media = {"pdf": "application/pdf",
                 "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
        if format not in media:
            raise HTTPException(status_code=400, detail="format must be html|pdf|docx")
        data = render(eng, report, format)
        return Response(content=data, media_type=media[format], headers={
            "Content-Disposition": f'attachment; filename="{eng.name}-report.{format}"'})

    # -- schedules (recurring assessments) --------------------------------
    @app.post("/engagements/{engagement_id}/schedule", status_code=201)
    async def create_schedule(engagement_id: str, body: ScheduleCreate,
                              user: dict = Depends(require_min_role("operator"))) -> dict:
        from croniter import croniter
        from datetime import datetime, timezone
        from hexacore.models import Schedule
        require(engagement_id, user["tenant_id"])
        if not croniter.is_valid(body.cron):
            raise HTTPException(status_code=400, detail="invalid cron expression")
        now = datetime.now(timezone.utc)
        sched = Schedule(cron=body.cron, target_engagement_id=engagement_id,
                         tenant_id=user["tenant_id"], next_run=croniter(body.cron, now).get_next(datetime))
        state.schedule_repository().save(sched)
        state.audit.record("schedule.created", actor=f"user:{user['sub']}",
                           engagement_id=engagement_id, scope="tenant")
        return _schedule_dict(sched)

    @app.get("/schedules")
    async def list_schedules(user: dict = Depends(require_min_role("viewer"))) -> list[dict]:
        return [_schedule_dict(s) for s in state.schedule_repository().list(tenant_id=user["tenant_id"])]

    @app.get("/schedules/{schedule_id}/monitoring")
    async def schedule_monitoring(schedule_id: str, user: dict = Depends(require_min_role("viewer"))) -> dict:
        """Run-over-run delta (new/fixed/persisting) between this schedule's two latest runs."""
        if state.schedule_repository().get(schedule_id, tenant_id=user["tenant_id"]) is None:
            raise HTTPException(status_code=404, detail="schedule not found")
        return state.monitoring(schedule_id, user["tenant_id"])

    @app.get("/schedules/{schedule_id}/trend")
    async def schedule_trend(schedule_id: str, user: dict = Depends(require_min_role("viewer"))) -> dict:
        """Severity-count timeline across the schedule's runs (the exposure trend)."""
        if state.schedule_repository().get(schedule_id, tenant_id=user["tenant_id"]) is None:
            raise HTTPException(status_code=404, detail="schedule not found")
        return state.trend(schedule_id, user["tenant_id"])

    @app.post("/schedules/{schedule_id}/disable")
    async def disable_schedule(schedule_id: str, user: dict = Depends(require_min_role("operator"))) -> dict:
        repo = state.schedule_repository()
        sched = repo.get(schedule_id, tenant_id=user["tenant_id"])
        if sched is None:
            raise HTTPException(status_code=404, detail="schedule not found")
        sched.enabled = False
        repo.save(sched)
        return _schedule_dict(sched)

    # -- approvals (gates) ------------------------------------------------
    @app.get("/engagements/{engagement_id}/approvals")
    async def list_approvals(engagement_id: str, user: dict = Depends(require_min_role("viewer"))) -> list[dict]:
        require(engagement_id, user["tenant_id"])
        return [_approval_dict(a) for a in state.gate_for(engagement_id).pending()]

    @app.post("/approvals/{resume_token}")
    async def resolve_approval(resume_token: str, body: ApprovalResolve,
                               user: dict = Depends(require_min_role("operator"))) -> dict:
        decision = ApprovalState.APPROVED if body.decision == "approve" else ApprovalState.DENIED
        # decided_by is the authenticated human, not a client-supplied field (gate rejects "agent").
        for gate in state.gates.values():
            if resume_token in gate._by_token:  # noqa: SLF001
                try:
                    a = gate.resolve(resume_token, decision=decision,
                                     decided_by=f"user:{user['sub']}", limits=body.limits)
                except GateError as exc:
                    raise HTTPException(status_code=400, detail=str(exc))
                return _approval_dict(a)
        raise HTTPException(status_code=404, detail="approval not found")

    # -- tools management -------------------------------------------------
    import shutil
    import subprocess

    TOOL_METADATA = {
        "recon.subdomains": {"bin": "subfinder", "install": "apt-get install -y subfinder"},
        "recon.http_probe": {"bin": "httpx", "install": "apt-get install -y httpx-toolkit"},
        "recon.dns": {"bin": "dnsx", "install": "apt-get install -y dnsx"},
        "recon.tech": {"bin": "whatweb", "install": "apt-get install -y whatweb"},
        "recon.ct_logs": {"bin": "curl", "install": "apt-get install -y curl"},
        "scan.ports": {"bin": "nmap", "install": "apt-get install -y nmap"},
        "scan.web_nuclei": {"bin": "nuclei", "install": "apt-get install -y nuclei"},
        "scan.tls": {"bin": "testssl.sh", "install": "apt-get install -y testssl.sh"},
        "scan.web_dir": {"bin": "ffuf", "install": "apt-get install -y ffuf"},
        "scan.web_nikto": {"bin": "nikto", "install": "apt-get install -y nikto"},
        "verify.web_sqli": {"bin": "sqlmap", "install": "apt-get install -y sqlmap"},
        "verify.msf_check": {"bin": "msfconsole", "install": "apt-get install -y metasploit-framework"},
        "verify.idor": {"bin": "built-in", "install": ""},
        "verify.ssrf": {"bin": "built-in", "install": ""},
        "verify.adcs_find": {"bin": "certipy", "install": "apt-get install -y certipy-ad"},
        "enum.netexec": {"bin": "nxc", "install": "apt-get install -y netexec"},
        "enum.bloodhound": {"bin": "bloodhound-python", "install": "apt-get install -y bloodhound.py"},
        "enum.linux_persistence": {"bin": "linpeas.sh", "install": "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /usr/local/bin/linpeas.sh && chmod +x /usr/local/bin/linpeas.sh"},
        "scan.cloud.scoutsuite": {"bin": "scout", "install": "pip3 install scoutsuite"},
        "enum.cloud.cloudfox": {"bin": "cloudfox", "install": "apt-get install -y cloudfox"},
        "scan.api.kiterunner": {"bin": "kr", "install": "apt-get install -y kiterunner"},
    }

    @app.get("/tools/status")
    async def get_tools_status(user: dict = Depends(require_min_role("viewer"))) -> dict:
        status = {}
        for tool_id, meta in TOOL_METADATA.items():
            if meta["bin"] == "built-in":
                status[tool_id] = True
            else:
                status[tool_id] = shutil.which(meta["bin"]) is not None
        return status

    @app.post("/tools/{tool_id}/install")
    async def install_tool(tool_id: str, user: dict = Depends(require_min_role("operator"))) -> dict:
        if tool_id not in TOOL_METADATA:
            raise HTTPException(status_code=404, detail="Tool not found")
        
        meta = TOOL_METADATA[tool_id]
        if not meta["install"]:
            return {"status": "ok", "detail": "No installation required"}
            
        try:
            cmd = f"sudo -n {meta['install']}"
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if proc.returncode != 0:
                proc = subprocess.run(meta["install"], shell=True, capture_output=True, text=True)
                if proc.returncode != 0:
                    raise HTTPException(status_code=500, detail=f"Install failed: {proc.stderr}")
            return {"status": "ok"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


    # -- kill switch ------------------------------------------------------
    @app.post("/kill")
    async def kill(body: KillRequest, user: dict = Depends(require_min_role("operator"))) -> dict:
        if body.engagement_id:
            require(body.engagement_id, user["tenant_id"])
            state.kill_switch.trip(body.engagement_id)
        else:
            # For a global kill, we'd need to kill all engagements in the tenant.
            # But the kill switch is currently a simple set. Let's just forbid global kill for now.
            raise HTTPException(status_code=403, detail="global kill disabled in multi-tenant mode")
        
        state.audit.record("kill_switch.tripped", actor="api",
                           engagement_id=body.engagement_id, scope="engagement")
        return {"killed": body.engagement_id}

    # -- live event feed (WebSocket) --------------------------------------
    @app.websocket("/engagements/{engagement_id}/ws")
    async def ws_events(websocket: WebSocket, engagement_id: str, token: str = "") -> None:
        # WS can't use header-based Depends cleanly; take the JWT as a query param.
        try:
            user = decode_token(token)
        except HTTPException:
            await websocket.close(code=4401)
            return
        await websocket.accept()
        try:
            require(engagement_id, user["tenant_id"])  # 404-guard: raises if not found/authorized
        except HTTPException:
            await websocket.close(code=4404)
            return

        q = state.bus.subscribe(engagement_id)
        try:
            # Replay anything already recorded (durable across restarts), then stream live.
            recorded = state.events_for(engagement_id, user["tenant_id"])
            for ev in list(recorded):
                await websocket.send_json(ev)
            # Kick off the run only if nothing has ever run for it (don't re-run recorded history).
            if not recorded and engagement_id not in state._running and engagement_id not in state.reports:
                domains, hosts = state.seeds.get(engagement_id, ([], []))
                asyncio.create_task(_safe_run(state, engagement_id, user["tenant_id"], domains, hosts))
            while True:
                msg = await q.get()
                await websocket.send_json(msg)
                if msg.get("type") == "run.complete":
                    break
        except WebSocketDisconnect:
            pass
        finally:
            state.bus.unsubscribe(engagement_id, q)

    from fastapi.staticfiles import StaticFiles

    if dist_dir.exists() and dist_dir.is_dir():
        assets_dir = dist_dir / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")
        
        @app.get("/{catchall:path}")
        async def serve_spa(catchall: str):
            file_path = dist_dir / catchall
            if file_path.is_file():
                return FileResponse(file_path)
            return FileResponse(dist_dir / "index.html")

    return app


async def _safe_run(state: AppState, engagement_id: str, tenant_id: str, domains, hosts) -> None:
    try:
        await state.run_engagement(engagement_id, tenant_id, seed_domains=domains, seed_hosts=hosts)
    except EngagementError as exc:
        state.bus.publish(engagement_id, {"type": "run.error", "phase": "start",
                                          "detail": str(exc), "payload": {}})


app = create_app()
