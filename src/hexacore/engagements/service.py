"""Engagement lifecycle service (Brain/01 §5, Brain/05 §3, Epic A9).

The single rule this enforces, and the M0 exit test (Brain/02 §2):

    An engagement cannot transition to RUNNING without a valid Scope AND an Authorization that
    is bound (by scope_hash) to that exact Scope. If the scope changes after authorization, the
    binding breaks and the engagement is frozen until re-authorized.

Every refusal and transition is written to the append-only audit log. A repository interface
keeps this storage-agnostic; the in-memory implementation is what the safety tests run against,
and a SQLAlchemy-backed one drops in later (Epic A3) without touching this logic.
"""
from __future__ import annotations

from typing import Optional, Protocol

from ..models import (
    Authorization,
    Engagement,
    EngagementStatus,
    RulesOfEngagement,
    hash_scope,
)
from ..safety.audit import AuditLog
from ..safety.killswitch import KillSwitch
from ..safety.scope import Scope


class EngagementError(Exception):
    """Raised when a lifecycle transition is not permitted."""


class EngagementRepository(Protocol):
    def add(self, engagement: Engagement) -> None: ...
    def get(self, engagement_id: str, tenant_id: str = "default") -> Optional[Engagement]: ...
    def list(self, tenant_id: str = "default") -> list[Engagement]: ...
    def save(self, engagement: Engagement) -> None: ...   # persist a mutation (upsert)


class InMemoryEngagementRepository:
    def __init__(self) -> None:
        self._store: dict[str, Engagement] = {}

    def add(self, engagement: Engagement) -> None:
        self._store[engagement.id] = engagement

    def get(self, engagement_id: str, tenant_id: str = "default") -> Optional[Engagement]:
        eng = self._store.get(engagement_id)
        if eng and eng.tenant_id == tenant_id:
            return eng
        return None

    def list(self, tenant_id: str = "default") -> list[Engagement]:
        return [e for e in self._store.values() if e.tenant_id == tenant_id]

    def save(self, engagement: Engagement) -> None:
        # Object identity means in-memory mutations already stick; keep the interface uniform.
        self._store[engagement.id] = engagement


# Statuses from which a fresh RUNNING transition is legal.
_STARTABLE = {EngagementStatus.SCOPED, EngagementStatus.PAUSED}


class EngagementService:
    def __init__(
        self,
        *,
        repository: Optional[EngagementRepository] = None,
        audit: Optional[AuditLog] = None,
        kill_switch: Optional[KillSwitch] = None,
    ):
        self.repo = repository or InMemoryEngagementRepository()
        self.audit = audit or AuditLog()
        self.kill_switch = kill_switch or KillSwitch()

    # -- helpers ----------------------------------------------------------
    def _require(self, engagement_id: str, tenant_id: str = "default") -> Engagement:
        eng = self.repo.get(engagement_id, tenant_id=tenant_id)
        if eng is None:
            raise EngagementError(f"no engagement {engagement_id!r}")
        return eng

    def _audit(self, event_type: str, eng: Engagement, actor: str, **payload) -> None:
        self.audit.record(event_type, actor=actor, engagement_id=eng.id, **payload)
        # Every transition audits right after mutating eng, so persist here (one hook, all paths).
        self.repo.save(eng)

    # -- lifecycle --------------------------------------------------------
    def create(self, *, name: str, client: str, created_by: str,
               model_profile: str = "local", tenant_id: str = "default") -> Engagement:
        eng = Engagement(name=name, client=client, created_by=created_by,
                         model_profile=model_profile, tenant_id=tenant_id)
        self.repo.add(eng)
        self._audit("engagement.created", eng, actor=created_by, name=name, client=client)
        return eng

    def set_scope(self, engagement_id: str, scope: Scope, *, actor: str, tenant_id: str = "default") -> Engagement:
        eng = self._require(engagement_id, tenant_id=tenant_id)
        if eng.status is EngagementStatus.RUNNING:
            raise EngagementError("cannot change scope of a running engagement; pause it first")

        eng.scope = scope
        # A scope change invalidates any prior authorization binding (Brain/05 §3 freeze rule).
        if eng.authorization is not None and not eng.authorization_matches_scope():
            eng.status = EngagementStatus.DRAFT
            self._audit("engagement.frozen", eng, actor=actor,
                        reason="scope changed after authorization; re-authorization required")
        elif eng.authorization_matches_scope():
            eng.status = EngagementStatus.SCOPED
        else:
            # Scope present, no (matching) authorization yet -> stays pre-scoped.
            eng.status = EngagementStatus.DRAFT
        self._audit("engagement.scoped", eng, actor=actor,
                    max_action_class=scope.max_action_class.value)
        return eng

    def set_roe(self, engagement_id: str, roe: RulesOfEngagement, *, actor: str, tenant_id: str = "default") -> Engagement:
        eng = self._require(engagement_id, tenant_id=tenant_id)
        eng.roe = roe
        self._audit("engagement.roe_set", eng, actor=actor)
        return eng

    def authorize(self, engagement_id: str, authorization: Authorization,
                  *, actor: str, tenant_id: str = "default") -> Engagement:
        eng = self._require(engagement_id, tenant_id=tenant_id)
        if eng.scope is None:
            raise EngagementError("cannot authorize before a scope is defined")
        if not authorization.is_complete():
            raise EngagementError("authorization is incomplete (missing signer or document)")

        # Bind the authorization to the current scope.
        authorization.scope_hash = hash_scope(eng.scope)
        eng.authorization = authorization
        eng.status = EngagementStatus.SCOPED
        self._audit("engagement.authorized", eng, actor=actor,
                    authorizer=authorization.authorizer_name,
                    method=authorization.method.value, scope_hash=authorization.scope_hash)
        return eng

    def start(self, engagement_id: str, *, actor: str, tenant_id: str = "default") -> Engagement:
        """Transition to RUNNING. THIS is the gate (M0 exit test)."""
        eng = self._require(engagement_id, tenant_id=tenant_id)

        def deny(reason: str) -> None:
            self._audit("engagement.start_denied", eng, actor=actor, reason=reason)
            raise EngagementError(reason)

        if self.kill_switch.is_killed(eng.id):
            deny("kill switch is engaged")
        if eng.scope is None:
            deny("no scope defined")
        if eng.authorization is None:
            deny("no authorization on file")
        if not eng.authorization.is_complete():
            deny("authorization is incomplete")
        if not eng.authorization_matches_scope():
            deny("authorization does not match the current scope (scope changed since signing)")
        if eng.status not in _STARTABLE:
            deny(f"cannot start from status {eng.status.value}")

        eng.status = EngagementStatus.RUNNING
        self._audit("engagement.started", eng, actor=actor)
        return eng

    def complete(self, engagement_id: str, *, actor: str, tenant_id: str = "default") -> Engagement:
        """Mark a finished run done (RUNNING -> REPORTING -> DONE)."""
        eng = self._require(engagement_id, tenant_id=tenant_id)
        eng.status = EngagementStatus.DONE
        self._audit("engagement.completed", eng, actor=actor)
        return eng

    def pause(self, engagement_id: str, *, actor: str, reason: str = "", tenant_id: str = "default") -> Engagement:
        eng = self._require(engagement_id, tenant_id=tenant_id)
        eng.status = EngagementStatus.PAUSED
        self._audit("engagement.paused", eng, actor=actor, reason=reason)
        return eng

    def abort(self, engagement_id: str, *, actor: str, reason: str = "", tenant_id: str = "default") -> Engagement:
        eng = self._require(engagement_id, tenant_id=tenant_id)
        self.kill_switch.trip(eng.id)
        eng.status = EngagementStatus.ABORTED
        self._audit("engagement.aborted", eng, actor=actor, reason=reason)
        return eng
