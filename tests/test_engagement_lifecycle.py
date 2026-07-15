"""Phase-0 M0 exit test (Brain/02 §2, Epic A exit test):

    create engagement -> add scope -> try to start without authorization => DENIED + audited;
    add authorization => allowed to start. Plus the scope-change freeze (Brain/05 §3).
"""
import pytest

from hexacore.engagements import EngagementError, EngagementService
from hexacore.models import AuthMethod, Authorization, EngagementStatus
from hexacore.safety import ActionClass, AuditLog, KillSwitch, Scope


def make_scope(max_action_class=ActionClass.ACTIVE_SCAN, extra_domain=None):
    domains = ["*.acme-staging.com"]
    if extra_domain:
        domains.append(extra_domain)
    return Scope(allow_domains=domains, allow_cidrs=["10.20.30.0/24"],
                 deny_list=["10.20.30.5"], max_action_class=max_action_class)


def make_auth():
    return Authorization(
        authorizer_name="Jane Doe", authorizer_email="jane@acme.example",
        method=AuthMethod.CLICK_SIGN,
    )


def build_service():
    return EngagementService(audit=AuditLog(), kill_switch=KillSwitch())


def new_engagement(svc):
    return svc.create(name="acme-staging", client="ACME", created_by="user:alice")


# --- M0 exit test --------------------------------------------------------

def test_cannot_start_without_scope():
    svc = build_service()
    eng = new_engagement(svc)
    with pytest.raises(EngagementError):
        svc.start(eng.id, actor="user:alice")
    assert svc.audit.events_of_type("engagement.start_denied")


def test_cannot_start_without_authorization_and_it_is_audited():
    svc = build_service()
    eng = new_engagement(svc)
    svc.set_scope(eng.id, make_scope(), actor="user:alice")
    with pytest.raises(EngagementError) as exc:
        svc.start(eng.id, actor="user:alice")
    assert "authorization" in str(exc.value)
    denials = svc.audit.events_of_type("engagement.start_denied")
    assert denials and denials[-1].payload["reason"].startswith("no authorization")
    assert svc.repo.get(eng.id).status is not EngagementStatus.RUNNING


def test_start_allowed_with_scope_and_authorization():
    svc = build_service()
    eng = new_engagement(svc)
    svc.set_scope(eng.id, make_scope(), actor="user:alice")
    svc.authorize(eng.id, make_auth(), actor="user:alice")
    started = svc.start(eng.id, actor="user:alice")
    assert started.status is EngagementStatus.RUNNING
    assert svc.audit.events_of_type("engagement.started")


# --- authorization completeness -----------------------------------------

def test_incomplete_authorization_rejected():
    svc = build_service()
    eng = new_engagement(svc)
    svc.set_scope(eng.id, make_scope(), actor="user:alice")
    bad = Authorization(authorizer_name="", authorizer_email="x@y.z",
                        method=AuthMethod.CLICK_SIGN)
    with pytest.raises(EngagementError):
        svc.authorize(eng.id, bad, actor="user:alice")


def test_uploaded_doc_auth_needs_document_ref():
    svc = build_service()
    eng = new_engagement(svc)
    svc.set_scope(eng.id, make_scope(), actor="user:alice")
    no_doc = Authorization(authorizer_name="Jane", authorizer_email="j@acme.example",
                           method=AuthMethod.UPLOADED_DOCUMENT)  # no document_ref
    with pytest.raises(EngagementError):
        svc.authorize(eng.id, no_doc, actor="user:alice")


def test_cannot_authorize_before_scope():
    svc = build_service()
    eng = new_engagement(svc)
    with pytest.raises(EngagementError):
        svc.authorize(eng.id, make_auth(), actor="user:alice")


# --- scope-change freeze (Brain/05 §3) ----------------------------------

def test_scope_change_after_authorization_freezes_engagement():
    svc = build_service()
    eng = new_engagement(svc)
    svc.set_scope(eng.id, make_scope(), actor="user:alice")
    svc.authorize(eng.id, make_auth(), actor="user:alice")

    # Quietly widen the scope after signing -> binding breaks -> frozen.
    svc.set_scope(eng.id, make_scope(extra_domain="*.prod.acme.com"), actor="user:alice")
    frozen = svc.repo.get(eng.id)
    assert frozen.status is EngagementStatus.DRAFT
    assert svc.audit.events_of_type("engagement.frozen")

    with pytest.raises(EngagementError) as exc:
        svc.start(eng.id, actor="user:alice")
    assert "scope" in str(exc.value)


def test_reauthorization_after_scope_change_allows_start():
    svc = build_service()
    eng = new_engagement(svc)
    svc.set_scope(eng.id, make_scope(), actor="user:alice")
    svc.authorize(eng.id, make_auth(), actor="user:alice")
    svc.set_scope(eng.id, make_scope(extra_domain="*.prod.acme.com"), actor="user:alice")
    # Re-sign against the new scope.
    svc.authorize(eng.id, make_auth(), actor="user:alice")
    started = svc.start(eng.id, actor="user:alice")
    assert started.status is EngagementStatus.RUNNING


# --- kill switch integration --------------------------------------------

def test_killed_engagement_cannot_start():
    ks = KillSwitch()
    svc = EngagementService(audit=AuditLog(), kill_switch=ks)
    eng = new_engagement(svc)
    svc.set_scope(eng.id, make_scope(), actor="user:alice")
    svc.authorize(eng.id, make_auth(), actor="user:alice")
    ks.trip(eng.id)
    with pytest.raises(EngagementError) as exc:
        svc.start(eng.id, actor="user:alice")
    assert "kill switch" in str(exc.value)


def test_abort_trips_kill_switch_and_sets_status():
    svc = build_service()
    eng = new_engagement(svc)
    svc.set_scope(eng.id, make_scope(), actor="user:alice")
    svc.authorize(eng.id, make_auth(), actor="user:alice")
    svc.start(eng.id, actor="user:alice")
    svc.abort(eng.id, actor="user:alice", reason="client called stop")
    assert svc.repo.get(eng.id).status is EngagementStatus.ABORTED
    assert svc.kill_switch.is_killed(eng.id)
