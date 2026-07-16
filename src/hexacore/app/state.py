"""Shared application state + the run orchestration the API calls.

Holds the audited EngagementService, the shared KillSwitch, per-engagement ApprovalGates, stored
event logs, and per-engagement FindingStores â€” all in memory for now (behind the same interfaces
a Postgres backend will later implement). `run_engagement` builds a SafetyLayer from the
engagement's scope and drives the deterministic runner on the configured backend, publishing
events to the bus as they happen.
"""
from __future__ import annotations

import asyncio
import os
from typing import Optional

from hexacore.engagements import EngagementService
from hexacore.findings import FindingStore
from hexacore.safety import (
    ActionClassifier, ApprovalGate, AuditLog, KillSwitch, SafetyLayer, ScopeValidator,
)
from hexacore_tools import CapabilityExecutor, RunnerSettings, build_backend
from hexacore_tools.adapters import default_registry
from hexacore_agent import RunEvent, RunSession, SimpleEngagementRunner

from .bus import EventBus


def _event_to_dict(ev) -> dict:
    return {"type": ev.type, "phase": ev.phase, "detail": ev.detail, "payload": ev.payload}


class AppState:
    def __init__(self, *, settings: Optional[RunnerSettings] = None, backend=None):
        self.audit = AuditLog()
        self.kill_switch = KillSwitch()
        # Durable engagements when HEXACORE_DB_URL is set; in-memory otherwise (default/tests).
        repo = None
        self.event_repo = None
        self.report_repo = None
        if os.getenv("HEXACORE_DB_URL"):
            from hexacore.persistence import SqlEngagementRepository, SqlEventRepository, SqlReportRepository
            repo = SqlEngagementRepository()
            self.event_repo = SqlEventRepository()
            self.report_repo = SqlReportRepository()
        self.service = EngagementService(repository=repo, audit=self.audit,
                                         kill_switch=self.kill_switch)
        self.settings = settings or RunnerSettings.from_env()
        self._backend_override = backend   # inject a fixture/sandbox backend in tests
        self.bus = EventBus()

        self.gates: dict[str, ApprovalGate] = {}
        self.events: dict[str, list[dict]] = {}
        self.stores: dict[str, FindingStore] = {}
        # Per-engagement RunSession, kept alive across /run calls so a resume (e.g. after
        # approving a gated action) only executes what's new instead of replaying the whole
        # golden path. Lost on process restart -- in-memory, same lifetime as everything else here.
        self.sessions: dict[str, RunSession] = {}
        self.reports: dict[str, object] = {}
        self.seeds: dict[str, tuple[list, list]] = {}
        self._running: set[str] = set()
        self._schedule_repo = None

    def schedule_repository(self):
        """Shared schedule repo (lazy so plain AppState() in tests never touches the DB file)."""
        if self._schedule_repo is None:
            from hexacore.persistence import SqlScheduleRepository
            self._schedule_repo = SqlScheduleRepository()
        return self._schedule_repo

    def gate_for(self, engagement_id: str) -> ApprovalGate:
        return self.gates.setdefault(engagement_id, ApprovalGate())

    def events_for(self, engagement_id: str, tenant_id: str) -> list[dict]:
        """Recorded RunEvents â€” durable store when configured, else this session's memory."""
        if self.event_repo is not None:
            return self.event_repo.list(engagement_id, tenant_id)
        return self.events.get(engagement_id, [])

    def report_for(self, engagement_id: str, tenant_id: str) -> Optional[object]:
        if self.report_repo is not None:
            return self.report_repo.get(engagement_id, tenant_id)
        return self.reports.get(engagement_id)

    # -- Phase 5: continuous monitoring ----------------------------------
    # ponytail: series runs come from in-memory `reports`; persist EngagementReport to make
    # deltas/trends span >2 runs and survive restart.
    def _series_runs(self, schedule_id: str, tenant_id: str) -> list:
        runs = [e for e in self.service.repo.list(tenant_id=tenant_id)
                if e.schedule_id == schedule_id and self.report_for(e.id, tenant_id) is not None]
        runs.sort(key=lambda e: e.created_at)
        return runs

    def monitoring(self, schedule_id: str, tenant_id: str) -> dict:
        """Run-over-run delta between a schedule's two most recent runs-with-reports."""
        from hexacore.monitoring import delta_summary
        runs = self._series_runs(schedule_id, tenant_id)
        result: dict = {"schedule_id": schedule_id, "runs": len(runs), "delta": None}
        if len(runs) >= 2:
            prev, curr = runs[-2], runs[-1]
            pf = [f.to_dict() for f in self.report_for(prev.id, tenant_id).findings]
            cf = [f.to_dict() for f in self.report_for(curr.id, tenant_id).findings]
            result["delta"] = delta_summary(pf, cf)
            result["previous_run"] = {"id": prev.id, "name": prev.name}
            result["current_run"] = {"id": curr.id, "name": curr.name}
        return result

    def trend(self, schedule_id: str, tenant_id: str) -> dict:
        """Severity counts of each run in the series, oldest first (the exposure timeline)."""
        runs = self._series_runs(schedule_id, tenant_id)
        return {"schedule_id": schedule_id, "points": [
            {"id": e.id, "name": e.name, "at": e.created_at.isoformat(),
             "counts": self.report_for(e.id, tenant_id).counts.to_dict()} for e in runs]}

    def configure_runner(self, settings: RunnerSettings) -> dict:
        """Replace the live runner settings after validating the backend config."""
        settings.validate()
        self.settings = settings
        self._backend_override = None
        return self.runner_status()

    def runner_status(self) -> dict:
        """Return the effective runner config plus a readiness check for the UI/API."""
        if self._backend_override is not None:
            name = getattr(self._backend_override, "name", self._backend_override.__class__.__name__)
            return {
                "backend": name,
                "configured_backend": self.settings.backend,
                "ready": True,
                "detail": "injected test runner",
                "dryrun": name == "dryrun",
                "docker": self._docker_settings_dict(),
                "vm": self._vm_settings_dict(redact=True),
            }
        try:
            backend = build_backend(self.settings)
            check = backend.check()
            return {
                "backend": getattr(backend, "name", self.settings.backend),
                "configured_backend": self.settings.backend,
                "ready": check.ok,
                "detail": check.detail,
                "dryrun": getattr(backend, "name", "") == "dryrun",
                "docker": self._docker_settings_dict(),
                "vm": self._vm_settings_dict(redact=True),
            }
        except Exception as exc:
            return {
                "backend": self.settings.backend,
                "configured_backend": self.settings.backend,
                "ready": False,
                "detail": str(exc),
                "dryrun": self.settings.backend == "dryrun",
                "docker": self._docker_settings_dict(),
                "vm": self._vm_settings_dict(redact=True),
            }

    def _docker_settings_dict(self) -> dict:
        d = self.settings.docker
        return {"image": d.image, "network": d.network, "docker_bin": d.docker_bin,
                "runtime": d.runtime}

    def _vm_settings_dict(self, *, redact: bool = False) -> dict:
        v = self.settings.vm
        return {"host": v.host, "user": v.user, "port": v.port, "key_path": v.key_path,
                "password": "********" if redact and v.password else v.password,
                "connect_timeout": v.connect_timeout}
    def _build_runner(self, engagement, on_event) -> tuple[SimpleEngagementRunner, object]:
        backend = self._backend_override or build_backend(self.settings)
        safety = SafetyLayer(
            scope_validator=ScopeValidator(engagement.scope),
            classifier=ActionClassifier(),
            gate=self.gate_for(engagement.id),
            kill_switch=self.kill_switch,
            audit=self.audit,
        )
        runtime = self.settings.docker.runtime if self.settings.docker else None
        executor = CapabilityExecutor(safety=safety, registry=default_registry(), sandbox=backend, runtime=runtime)
        return SimpleEngagementRunner(executor, on_event=on_event), backend

    async def run_engagement(self, engagement_id: str, tenant_id: str, *, seed_domains, seed_hosts):
        """Start + run an engagement to completion in a worker thread; stream events live.

        Raises EngagementError (from service.start) if it cannot start â€” the caller maps that to
        HTTP 400. Returns the EngagementReport.
        """
        loop = asyncio.get_running_loop()
        self.bus.bind_loop(loop)
        engagement = self.service._require(engagement_id, tenant_id=tenant_id)  # noqa: SLF001 (internal accessor)
        self.events.setdefault(engagement_id, [])
        self._running.add(engagement_id)

        def on_event(ev):
            d = _event_to_dict(ev)
            self.events[engagement_id].append(d)
            if self.event_repo is not None:
                self.event_repo.append(engagement_id, tenant_id, d)
            self.bus.publish(engagement_id, d)

        def _run():
            # start transition happens in-thread so its EngagementError surfaces to the caller.
            self.service.start(engagement_id, actor="api", tenant_id=tenant_id)
            runner_status = self.runner_status()
            on_event(RunEvent("runner.status", "start",
                              f"runner {runner_status['backend']}: {runner_status['detail']}",
                              runner_status))
            runner, _ = self._build_runner(engagement, on_event)
            session = self.sessions.setdefault(engagement_id, RunSession())
            return runner.run(engagement, seed_domains=seed_domains, seed_hosts=seed_hosts,
                              session=session)

        try:
            report = await loop.run_in_executor(None, _run)
        finally:
            self._running.discard(engagement_id)
        self.stores[engagement_id] = None  # findings live on the report
        self.reports[engagement_id] = report
        if self.report_repo is not None:
            self.report_repo.save(report, tenant_id)
        if report.gated:
            self.service.pause(engagement_id, actor="api", reason="awaiting gate approval",
                               tenant_id=tenant_id)
        else:
            self.service.complete(engagement_id, actor="api", tenant_id=tenant_id)
        self.bus.publish(engagement_id, {"type": "run.complete", "phase": "report",
                                         "detail": f"{report.counts.total} findings",
                                         "payload": report.counts.to_dict()})
        return report

