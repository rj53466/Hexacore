"""Core domain entities (Brain/01 §4). Lightweight dataclasses; these map onto the SQLAlchemy
engagement table in `persistence.py` (created via `create_all`; SQLite default, Postgres via
`HEXACORE_DB_URL`). Keeping them storage-agnostic lets the lifecycle logic (and its safety tests)
run without a database.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from .safety.scope import Scope


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uid() -> str:
    return str(uuid.uuid4())


class EngagementStatus(Enum):
    DRAFT = "draft"          # created, no scope yet
    SCOPED = "scoped"        # scope + authorization present; may plan, not yet running
    RUNNING = "running"
    PAUSED = "paused"        # kill switch or operator pause
    REPORTING = "reporting"
    DONE = "done"
    ABORTED = "aborted"


class AuthMethod(Enum):
    CLICK_SIGN = "click-sign"
    UPLOADED_DOCUMENT = "uploaded-document"
    CONTRACT_REFERENCE = "contract-reference"


def hash_scope(scope: Scope) -> str:
    """Stable hash of the technical boundary. Binds an Authorization to the exact scope it was
    signed against so scope can't silently change post-signing (Brain/05 §3)."""
    canonical = json.dumps(
        {
            "allow_domains": sorted(scope.allow_domains),
            "allow_cidrs": sorted(scope.allow_cidrs),
            "deny_list": sorted(scope.deny_list),
            "max_action_class": scope.max_action_class.value,
        },
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class RulesOfEngagement:
    """Behavioural boundary (Brain/05 §5). Enforced by the agent/tool layer in later phases."""
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    requests_per_sec: Optional[int] = None
    concurrency: Optional[int] = None
    off_limits: list[str] = field(default_factory=list)  # e.g. DoS, social-engineering
    notes: str = ""


@dataclass
class Authorization:
    """Legal boundary (Brain/05 §3). No engagement runs without one."""
    authorizer_name: str
    authorizer_email: str
    method: AuthMethod
    document_ref: Optional[str] = None        # object-store key of the signed permission / SoW
    scope_hash: Optional[str] = None          # hash of the Scope at signing time
    signed_at: datetime = field(default_factory=_now)
    verified_by: Optional[str] = None
    id: str = field(default_factory=_uid)

    def is_complete(self) -> bool:
        # A click-sign attestation needs no document; the other methods must reference one.
        if not self.authorizer_name or not self.authorizer_email:
            return False
        if self.method is not AuthMethod.CLICK_SIGN and not self.document_ref:
            return False
        return True


@dataclass
class Schedule:
    """Recurring assessment configuration."""
    cron: str
    target_engagement_id: str
    next_run: Optional[datetime] = None
    enabled: bool = True
    id: str = field(default_factory=_uid)
    tenant_id: str = "default"


@dataclass
class Engagement:
    name: str
    client: str
    created_by: str
    tenant_id: str = "default"
    status: EngagementStatus = EngagementStatus.DRAFT
    scope: Optional[Scope] = None
    authorization: Optional[Authorization] = None
    roe: RulesOfEngagement = field(default_factory=RulesOfEngagement)
    model_profile: str = "local"
    autonomy_profile: str = "supervised"   # scan-only | supervised | assisted (Brain/05 §4b)
    created_at: datetime = field(default_factory=_now)
    id: str = field(default_factory=_uid)
    is_recurring: bool = False
    schedule_id: Optional[str] = None

    def authorization_matches_scope(self) -> bool:
        """True only if a complete authorization is bound to the *current* scope."""
        if self.scope is None or self.authorization is None:
            return False
        if not self.authorization.is_complete():
            return False
        return self.authorization.scope_hash == hash_scope(self.scope)
