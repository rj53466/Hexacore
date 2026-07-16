"""Load an engagement from a scope file (Brain/07 §6, Epic I4).

`engagements/*.yaml` -> Engagement + Scope + (optional) Authorization, created through the
EngagementService so every step is audited. The file is what `make engage` consumes. If the
authorization block is omitted, the engagement is created but cannot start — which is exactly the
deny-by-default behaviour we want to be able to demonstrate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

from .engagements import EngagementService
from .models import AuthMethod, Authorization, Engagement, RulesOfEngagement
from .safety.actions import ActionClass
from .safety.scope import Scope


@dataclass
class LoadedEngagement:
    engagement: Engagement
    seed_domains: list[str] = field(default_factory=list)
    seed_hosts: list[str] = field(default_factory=list)


def _parse_dt(value) -> Optional[datetime]:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _strip_wildcard(domain: str) -> str:
    return domain[2:] if domain.startswith("*.") else domain


def load_engagement(path: str | Path, service: EngagementService,
                    *, actor: str = "loader") -> LoadedEngagement:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return create_from_mapping(data, service, actor=actor)


def create_from_mapping(data: dict, service: EngagementService,
                        *, actor: str = "loader", tenant_id: str = "default") -> LoadedEngagement:
    """Create an engagement from a parsed mapping (used by the file loader and the HTTP API).

    Every mutation goes through the service under `tenant_id` so it persists correctly with a
    durable repo (which returns fresh objects per call — a local reference would go stale). The
    canonical engagement is re-read at the end, so the result reflects the true persisted state
    in both in-memory and durable modes.
    """
    name = data.get("name") or "unnamed-engagement"
    client = data.get("client") or "unknown"

    scope_data = data.get("scope") or {}
    scope = Scope(
        allow_domains=list(scope_data.get("allow_domains", [])),
        allow_cidrs=list(scope_data.get("allow_cidrs", [])),
        deny_list=list(scope_data.get("deny_list", [])),
        max_action_class=ActionClass.parse(scope_data.get("max_action_class", "active-scan")),
    )

    eng = service.create(name=name, client=client, created_by=actor,
                         model_profile=data.get("model_profile", "local"), tenant_id=tenant_id)
    eid = eng.id
    service.set_scope(eid, scope, actor=actor, tenant_id=tenant_id)

    # Rules of engagement (window / rate limits / off-limits).
    window = scope_data.get("window") or {}
    rl = scope_data.get("rate_limits") or {}
    service.set_roe(eid, RulesOfEngagement(
        window_start=_parse_dt(window.get("start")),
        window_end=_parse_dt(window.get("end")),
        requests_per_sec=rl.get("requests_per_sec"),
        concurrency=rl.get("concurrency"),
        off_limits=list(scope_data.get("off_limits", [])),
    ), actor=actor, tenant_id=tenant_id)

    # Optional authorization.
    auth_data = data.get("authorization")
    if auth_data:
        authorization = Authorization(
            authorizer_name=auth_data.get("authorizer_name", ""),
            authorizer_email=auth_data.get("authorizer_email", ""),
            method=AuthMethod(auth_data.get("method", "click-sign")),
            document_ref=auth_data.get("document_ref"),
            verified_by=auth_data.get("verified_by"),
        )
        service.authorize(eid, authorization, actor=actor, tenant_id=tenant_id)

    # autonomy_profile isn't a lifecycle transition; set it on the canonical object and persist.
    eng = service._require(eid, tenant_id=tenant_id)
    eng.autonomy_profile = data.get("autonomy_profile", "supervised")
    service.repo.save(eng)

    # Seed targets: explicit, else derived from allowed domains.
    seeds = data.get("seeds") or {}
    seed_domains = list(seeds.get("domains") or
                        [_strip_wildcard(d) for d in scope.allow_domains])
    seed_hosts = list(seeds.get("hosts") or [])

    return LoadedEngagement(engagement=eng, seed_domains=seed_domains, seed_hosts=seed_hosts)
