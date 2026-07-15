"""SQLAlchemy-backed engagement persistence (Epic A3).

Implements the same EngagementRepository interface the in-memory store uses, so nothing above it
changes. SQLite by default (file `hexacore.db`); Postgres via `HEXACORE_DB_URL`
(e.g. postgresql+psycopg://user:pw@host/hexacore). The Engagement aggregate (scope, authorization,
RoE) is stored as JSON columns — the dataclass shapes ARE the schema — and reconstituted on load.

ponytail: one table of JSON columns -> `create_all`, no Alembic. Migrations buy nothing for a
single JSON-blob table (the dataclass shapes ARE the schema); if the columns ever stabilise into a
real relational schema that needs versioned migrations, add Alembic then. Findings/audit/approvals
persist later behind their own stores.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from .models import (
    AuthMethod,
    Authorization,
    Engagement,
    EngagementStatus,
    RulesOfEngagement,
)
from .safety.actions import ActionClass
from .safety.scope import Scope

DEFAULT_URL = os.getenv("HEXACORE_DB_URL", "sqlite:///hexacore.db")


class Base(DeclarativeBase):
    pass


class EngagementRow(Base):
    __tablename__ = "engagements"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), default="default")
    name: Mapped[str] = mapped_column(String(255))
    client: Mapped[str] = mapped_column(String(255))
    created_by: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32))
    model_profile: Mapped[str] = mapped_column(String(32))
    autonomy_profile: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[str] = mapped_column(String(64))
    is_recurring: Mapped[bool] = mapped_column(default=False)
    schedule_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    scope_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    authorization_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    roe_json: Mapped[str] = mapped_column(Text)


def _dump_scope(s: Optional[Scope]) -> Optional[str]:
    if s is None:
        return None
    return json.dumps({"allow_domains": s.allow_domains, "allow_cidrs": s.allow_cidrs,
                       "deny_list": s.deny_list, "max_action_class": s.max_action_class.value})


def _load_scope(raw: Optional[str]) -> Optional[Scope]:
    if not raw:
        return None
    d = json.loads(raw)
    return Scope(allow_domains=d["allow_domains"], allow_cidrs=d["allow_cidrs"],
                 deny_list=d["deny_list"],
                 max_action_class=ActionClass.parse(d["max_action_class"]))


def _dump_auth(a: Optional[Authorization]) -> Optional[str]:
    if a is None:
        return None
    return json.dumps({"authorizer_name": a.authorizer_name, "authorizer_email": a.authorizer_email,
                       "method": a.method.value, "document_ref": a.document_ref,
                       "scope_hash": a.scope_hash, "verified_by": a.verified_by,
                       "signed_at": a.signed_at.isoformat(), "id": a.id})


def _load_auth(raw: Optional[str]) -> Optional[Authorization]:
    if not raw:
        return None
    d = json.loads(raw)
    return Authorization(authorizer_name=d["authorizer_name"], authorizer_email=d["authorizer_email"],
                         method=AuthMethod(d["method"]), document_ref=d.get("document_ref"),
                         scope_hash=d.get("scope_hash"), verified_by=d.get("verified_by"),
                         signed_at=datetime.fromisoformat(d["signed_at"]), id=d["id"])


def _dump_roe(r: RulesOfEngagement) -> str:
    return json.dumps({"window_start": r.window_start.isoformat() if r.window_start else None,
                       "window_end": r.window_end.isoformat() if r.window_end else None,
                       "requests_per_sec": r.requests_per_sec, "concurrency": r.concurrency,
                       "off_limits": r.off_limits, "notes": r.notes})


def _load_roe(raw: str) -> RulesOfEngagement:
    d = json.loads(raw or "{}")
    return RulesOfEngagement(
        window_start=datetime.fromisoformat(d["window_start"]) if d.get("window_start") else None,
        window_end=datetime.fromisoformat(d["window_end"]) if d.get("window_end") else None,
        requests_per_sec=d.get("requests_per_sec"), concurrency=d.get("concurrency"),
        off_limits=d.get("off_limits", []), notes=d.get("notes", ""))


def _to_row(e: Engagement) -> EngagementRow:
    return EngagementRow(
        id=e.id, tenant_id=e.tenant_id, name=e.name, client=e.client, created_by=e.created_by,
        status=e.status.value, model_profile=e.model_profile, autonomy_profile=e.autonomy_profile,
        created_at=e.created_at.isoformat(), is_recurring=e.is_recurring, schedule_id=e.schedule_id,
        scope_json=_dump_scope(e.scope), authorization_json=_dump_auth(e.authorization),
        roe_json=_dump_roe(e.roe))


def _to_engagement(r: EngagementRow) -> Engagement:
    return Engagement(
        name=r.name, client=r.client, created_by=r.created_by, tenant_id=r.tenant_id,
        status=EngagementStatus(r.status), scope=_load_scope(r.scope_json),
        authorization=_load_auth(r.authorization_json), roe=_load_roe(r.roe_json),
        model_profile=r.model_profile, autonomy_profile=r.autonomy_profile,
        created_at=datetime.fromisoformat(r.created_at), id=r.id,
        is_recurring=r.is_recurring, schedule_id=r.schedule_id)


class SqlEngagementRepository:
    """Durable EngagementRepository. Instantiate once; safe to reopen on the same URL."""

    def __init__(self, url: str = DEFAULT_URL):
        self.engine = create_engine(url)
        Base.metadata.create_all(self.engine)

    def add(self, engagement: Engagement) -> None:
        self.save(engagement)

    def save(self, engagement: Engagement) -> None:
        with Session(self.engine) as s:
            s.merge(_to_row(engagement))   # upsert by primary key
            s.commit()

    def get(self, engagement_id: str, tenant_id: str = "default") -> Optional[Engagement]:
        with Session(self.engine) as s:
            row = s.scalars(select(EngagementRow).where(
                EngagementRow.id == engagement_id,
                EngagementRow.tenant_id == tenant_id
            )).first()
            return _to_engagement(row) if row else None

    def list(self, tenant_id: str = "default") -> list[Engagement]:
        with Session(self.engine) as s:
            rows = s.scalars(select(EngagementRow).where(EngagementRow.tenant_id == tenant_id)).all()
            return [_to_engagement(r) for r in rows]


class ScheduleRow(Base):
    __tablename__ = "schedules"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), default="default")
    cron: Mapped[str] = mapped_column(String(255))
    target_engagement_id: Mapped[str] = mapped_column(String(64))
    next_run: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True)


from .models import Schedule


def _to_schedule_row(s: Schedule) -> ScheduleRow:
    return ScheduleRow(
        id=s.id,
        tenant_id=s.tenant_id,
        cron=s.cron,
        target_engagement_id=s.target_engagement_id,
        next_run=s.next_run.isoformat() if s.next_run else None,
        enabled=s.enabled
    )


def _to_schedule(r: ScheduleRow) -> Schedule:
    return Schedule(
        cron=r.cron,
        target_engagement_id=r.target_engagement_id,
        next_run=datetime.fromisoformat(r.next_run) if r.next_run else None,
        enabled=r.enabled,
        id=r.id,
        tenant_id=r.tenant_id
    )


class EventRow(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    engagement_id: Mapped[str] = mapped_column(String(64), index=True)
    tenant_id: Mapped[str] = mapped_column(String(255), default="default")
    type: Mapped[str] = mapped_column(String(64))
    phase: Mapped[str] = mapped_column(String(32))
    detail: Mapped[str] = mapped_column(Text)
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(64))


class SqlEventRepository:
    """Durable RunEvent log so the console's Audit Log survives a server restart.
    Insertion order (autoincrement id) is the event order — no explicit seq needed.
    """
    def __init__(self, url: str = DEFAULT_URL):
        self.engine = create_engine(url)
        Base.metadata.create_all(self.engine)

    def append(self, engagement_id: str, tenant_id: str, ev: dict) -> None:
        with Session(self.engine) as s:
            s.add(EventRow(
                engagement_id=engagement_id, tenant_id=tenant_id,
                type=ev.get("type", ""), phase=ev.get("phase", ""), detail=ev.get("detail", ""),
                payload_json=json.dumps(ev.get("payload", {})),
                created_at=datetime.now().isoformat()))
            s.commit()

    def list(self, engagement_id: str, tenant_id: str = "default") -> list[dict]:
        with Session(self.engine) as s:
            rows = s.scalars(select(EventRow).where(
                EventRow.engagement_id == engagement_id,
                EventRow.tenant_id == tenant_id,
            ).order_by(EventRow.id)).all()
            return [{"type": r.type, "phase": r.phase, "detail": r.detail,
                     "payload": json.loads(r.payload_json)} for r in rows]


class SqlScheduleRepository:
    def __init__(self, url: str = DEFAULT_URL):
        self.engine = create_engine(url)
        Base.metadata.create_all(self.engine)

    def save(self, schedule: Schedule) -> None:
        with Session(self.engine) as s:
            s.merge(_to_schedule_row(schedule))
            s.commit()

    def get(self, schedule_id: str, tenant_id: str = "default") -> Optional[Schedule]:
        with Session(self.engine) as s:
            row = s.scalars(select(ScheduleRow).where(
                ScheduleRow.id == schedule_id,
                ScheduleRow.tenant_id == tenant_id
            )).first()
            return _to_schedule(row) if row else None

    def list(self, tenant_id: str = "default") -> list[Schedule]:
        with Session(self.engine) as s:
            rows = s.scalars(select(ScheduleRow).where(ScheduleRow.tenant_id == tenant_id)).all()
            return [_to_schedule(r) for r in rows]

    def list_all_active(self) -> list[Schedule]:
        with Session(self.engine) as s:
            rows = s.scalars(select(ScheduleRow).where(ScheduleRow.enabled == True)).all()
            return [_to_schedule(r) for r in rows]


from hexacore_agent.runner import EngagementReport, RunEvent
from hexacore.findings import SeverityCounts
from hexacore_tools.base import Finding, Severity
from hexacore.safety.approval import Approval, ApprovalState


class ReportRow(Base):
    __tablename__ = "reports"
    engagement_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), default="default")
    name: Mapped[str] = mapped_column(String(255))
    counts_json: Mapped[str] = mapped_column(Text)
    findings_json: Mapped[str] = mapped_column(Text)
    events_json: Mapped[str] = mapped_column(Text)
    gated_json: Mapped[str] = mapped_column(Text)
    denied_targets_json: Mapped[str] = mapped_column(Text)


def _dump_report(r: EngagementReport, tenant_id: str) -> ReportRow:
    counts_json = json.dumps(r.counts.to_dict())
    findings_json = json.dumps([f.to_dict() for f in r.findings])
    events_json = json.dumps([{"type": e.type, "phase": e.phase, "detail": e.detail, "payload": e.payload} for e in r.events])
    
    gated_list = []
    for a in r.gated:
        gated_list.append({
            "tool_run_id": a.tool_run_id,
            "engagement_id": a.engagement_id,
            "capability": a.capability,
            "target": a.target,
            "action_class": a.action_class,
            "resume_token": a.resume_token,
            "id": a.id,
            "state": a.state.value,
            "requested_at": a.requested_at.isoformat(),
            "decided_at": a.decided_at.isoformat() if a.decided_at else None,
            "decided_by": a.decided_by,
            "limits": a.limits
        })
    gated_json = json.dumps(gated_list)
    denied_targets_json = json.dumps(r.denied_targets)

    return ReportRow(
        engagement_id=r.engagement_id,
        tenant_id=tenant_id,
        name=r.name,
        counts_json=counts_json,
        findings_json=findings_json,
        events_json=events_json,
        gated_json=gated_json,
        denied_targets_json=denied_targets_json
    )


def _load_report(row: ReportRow) -> EngagementReport:
    counts_d = json.loads(row.counts_json)
    # the frontend / count dict expects 'total', but SeverityCounts dataclass doesn't have it in __init__
    if "total" in counts_d:
        del counts_d["total"]
    counts = SeverityCounts(**counts_d)

    findings = []
    for fd in json.loads(row.findings_json):
        findings.append(Finding(
            title=fd["title"],
            severity=Severity.parse(fd["severity"]),
            source=fd["source"],
            affected_asset=fd["affected_asset"],
            description=fd.get("description", ""),
            cvss_vector=fd.get("cvss_vector"),
            cwe=fd.get("cwe"),
            cve=fd.get("cve", []),
            attack_techniques=fd.get("attack_techniques", []),
            remediation=fd.get("remediation", ""),
            evidence=fd.get("evidence", {}),
            raw_ref=fd.get("raw_ref")
        ))

    events = []
    for ed in json.loads(row.events_json):
        events.append(RunEvent(
            type=ed["type"],
            phase=ed["phase"],
            detail=ed["detail"],
            payload=ed.get("payload", {})
        ))

    gated = []
    for gd in json.loads(row.gated_json):
        a = Approval(
            tool_run_id=gd["tool_run_id"],
            engagement_id=gd["engagement_id"],
            capability=gd["capability"],
            target=gd["target"],
            action_class=gd["action_class"],
            resume_token=gd["resume_token"],
            id=gd["id"],
            state=ApprovalState(gd["state"]),
            requested_at=datetime.fromisoformat(gd["requested_at"]),
            decided_at=datetime.fromisoformat(gd["decided_at"]) if gd.get("decided_at") else None,
            decided_by=gd.get("decided_by"),
            limits=gd.get("limits", {})
        )
        gated.append(a)
    
    denied_targets = json.loads(row.denied_targets_json)

    return EngagementReport(
        engagement_id=row.engagement_id,
        name=row.name,
        counts=counts,
        findings=findings,
        events=events,
        gated=gated,
        denied_targets=denied_targets
    )


class SqlReportRepository:
    def __init__(self, url: str = DEFAULT_URL):
        self.engine = create_engine(url)
        Base.metadata.create_all(self.engine)

    def save(self, report: EngagementReport, tenant_id: str = "default") -> None:
        with Session(self.engine) as s:
            s.merge(_dump_report(report, tenant_id))
            s.commit()

    def get(self, engagement_id: str, tenant_id: str = "default") -> Optional[EngagementReport]:
        with Session(self.engine) as s:
            row = s.scalars(select(ReportRow).where(
                ReportRow.engagement_id == engagement_id,
                ReportRow.tenant_id == tenant_id
            )).first()
            return _load_report(row) if row else None


class TenantConfigRow(Base):
    __tablename__ = "tenant_configs"
    tenant_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    alert_webhook: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)


class TenantConfigRepository:
    def __init__(self, url: str = DEFAULT_URL):
        self.engine = create_engine(url)
        Base.metadata.create_all(self.engine)

    def get_webhook(self, tenant_id: str) -> Optional[str]:
        with Session(self.engine) as s:
            row = s.scalars(select(TenantConfigRow).where(TenantConfigRow.tenant_id == tenant_id)).first()
            return row.alert_webhook if row else None

    def set_webhook(self, tenant_id: str, webhook_url: str) -> None:
        with Session(self.engine) as s:
            row = s.scalars(select(TenantConfigRow).where(TenantConfigRow.tenant_id == tenant_id)).first()
            if not row:
                row = TenantConfigRow(tenant_id=tenant_id, alert_webhook=webhook_url)
                s.add(row)
            else:
                row.alert_webhook = webhook_url
            s.commit()



