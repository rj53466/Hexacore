"""Scheduling Engine (MVP).
Uses a simple asyncio loop and croniter to manage recurring engagements.
"""
import asyncio
from datetime import datetime, timezone
import json
import logging
import os
import urllib.request
from croniter import croniter

from .app.state import AppState
from .persistence import SqlScheduleRepository

logger = logging.getLogger(__name__)


def _post_alert(url: str, payload: dict) -> None:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    urllib.request.urlopen(req, timeout=10).close()


def maybe_alert(state, schedule_id: str, tenant_id: str, *, post=_post_alert) -> bool:
    """POST the monitoring delta to HEXACORE_ALERT_WEBHOOK when a new high/critical appears.
    Returns whether an alert fired. `post` is injectable for tests."""
    from .persistence import TenantConfigRepository
    
    url = TenantConfigRepository().get_webhook(tenant_id)
    if not url:
        # Fallback to env var for legacy/global config
        url = os.getenv("HEXACORE_ALERT_WEBHOOK")
    
    if not url:
        return False
    result = state.monitoring(schedule_id, tenant_id)
    delta = result.get("delta")
    if not (delta and delta["alert"]):
        return False
    try:
        post(url, {"event": "new_exposure", **result})
    except Exception as exc:  # a flaky webhook must never break the scheduler
        logger.error(f"alert webhook failed: {exc}")
    return True

class Scheduler:
    def __init__(self, state: AppState, schedule_repo: SqlScheduleRepository):
        self.state = state
        self.repo = schedule_repo
        self._running = False
        self._task = None

    def start(self):
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._loop())

    def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()

    async def _loop(self):
        logger.info("Scheduler loop started.")
        while self._running:
            try:
                await self._check_schedules()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(f"Scheduler loop error: {exc}")
            
            await asyncio.sleep(60)

    async def _check_schedules(self):
        now = datetime.now(timezone.utc)
        schedules = self.repo.list_all_active()
        for sched in schedules:
            if not sched.next_run:
                # Calculate next run if not set
                cron = croniter(sched.cron, now)
                sched.next_run = cron.get_next(datetime)
                self.repo.save(sched)
                continue

            # Ensure both datetime objects are offset-aware
            next_run_aware = sched.next_run
            if next_run_aware.tzinfo is None:
                next_run_aware = next_run_aware.replace(tzinfo=timezone.utc)
                
            if next_run_aware <= now:
                await self._execute_schedule(sched)
                
                # Update next run
                cron = croniter(sched.cron, now)
                sched.next_run = cron.get_next(datetime)
                self.repo.save(sched)

    async def _execute_schedule(self, sched):
        logger.info(f"Executing schedule {sched.id} for target {sched.target_engagement_id}")
        base_eng = self.state.service.repo.get(sched.target_engagement_id, tenant_id=sched.tenant_id)
        if not base_eng:
            logger.warning(f"Target engagement {sched.target_engagement_id} not found for schedule {sched.id}")
            return
            
        # Clone engagement to create a new run
        new_name = f"{base_eng.name} - Scheduled Run {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}"
        new_eng = self.state.service.create(
            name=new_name,
            client=base_eng.client,
            created_by="scheduler",
            model_profile=base_eng.model_profile,
            tenant_id=base_eng.tenant_id
        )
        eid = new_eng.id

        # Copy scope, roe, authorization
        if base_eng.scope:
            self.state.service.set_scope(eid, base_eng.scope, actor="scheduler", tenant_id=sched.tenant_id)
        if base_eng.roe:
            self.state.service.set_roe(eid, base_eng.roe, actor="scheduler", tenant_id=sched.tenant_id)
        if base_eng.authorization:
            self.state.service.authorize(eid, base_eng.authorization, actor="scheduler", tenant_id=sched.tenant_id)

        # Persist clone metadata on the canonical object (durable repos return fresh objects, so a
        # stale local reference would drop schedule_id and break monitoring — same trap as the loader).
        new_eng = self.state.service._require(eid, tenant_id=sched.tenant_id)
        new_eng.autonomy_profile = base_eng.autonomy_profile
        new_eng.is_recurring = True
        new_eng.schedule_id = sched.id
        self.state.service.repo.save(new_eng)

        # Trigger run
        domains, hosts = self.state.seeds.get(base_eng.id, ([], []))
        self.state.seeds[eid] = (domains, hosts)

        try:
            # We don't await the full run here to avoid blocking the scheduler loop
            asyncio.create_task(self._safe_run(eid, new_eng.tenant_id, domains, hosts, sched.id))
        except Exception as e:
            logger.error(f"Failed to trigger scheduled engagement {new_eng.id}: {e}")

    async def _safe_run(self, engagement_id: str, tenant_id: str, domains, hosts, schedule_id=None):
        try:
            await self.state.run_engagement(engagement_id, tenant_id, seed_domains=domains, seed_hosts=hosts)
        except Exception as exc:
            self.state.bus.publish(engagement_id, {"type": "run.error", "phase": "start",
                                              "detail": str(exc), "payload": {}})
            return
        if schedule_id:  # alert if this run introduced a new high/critical vs the previous one
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, maybe_alert, self.state, schedule_id, tenant_id)
