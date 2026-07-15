"""SQLAlchemy persistence: engagements + mutations survive a fresh repository/engine."""
from hexacore.engagements import EngagementService
from hexacore.models import AuthMethod, Authorization, EngagementStatus
from hexacore.persistence import SqlEngagementRepository
from hexacore.safety import ActionClass, AuditLog, KillSwitch, Scope


def _url(tmp_path):
    return f"sqlite:///{tmp_path / 'hexa.db'}"


def _scope():
    return Scope(allow_domains=["acme-staging.com"], allow_cidrs=["10.20.30.0/24"],
                 deny_list=["10.20.30.5"], max_action_class=ActionClass.ACTIVE_SCAN)


def _auth():
    return Authorization(authorizer_name="Jane", authorizer_email="j@acme.example",
                         method=AuthMethod.CLICK_SIGN)


def test_engagement_survives_new_repo(tmp_path):
    url = _url(tmp_path)
    svc = EngagementService(repository=SqlEngagementRepository(url),
                            audit=AuditLog(), kill_switch=KillSwitch())
    eng = svc.create(name="acme", client="ACME", created_by="op")
    svc.set_scope(eng.id, _scope(), actor="op")
    svc.authorize(eng.id, _auth(), actor="op")
    svc.start(eng.id, actor="op")
    eid = eng.id

    # Reopen: brand-new repo + engine on the same file.
    repo2 = SqlEngagementRepository(url)
    loaded = repo2.get(eid)
    assert loaded is not None
    assert loaded.status is EngagementStatus.RUNNING
    assert loaded.scope.allow_domains == ["acme-staging.com"]
    assert loaded.scope.max_action_class is ActionClass.ACTIVE_SCAN
    assert loaded.authorization.authorizer_name == "Jane"
    assert loaded.authorization_matches_scope()   # scope_hash persisted + still binds


def test_list_and_scope_freeze_persist(tmp_path):
    url = _url(tmp_path)
    repo = SqlEngagementRepository(url)
    svc = EngagementService(repository=repo, audit=AuditLog(), kill_switch=KillSwitch())
    e1 = svc.create(name="a", client="c", created_by="op")
    svc.create(name="b", client="c", created_by="op")
    svc.set_scope(e1.id, _scope(), actor="op")
    svc.authorize(e1.id, _auth(), actor="op")
    # Widen scope after auth -> freeze (DRAFT) must persist.
    svc.set_scope(e1.id, Scope(allow_domains=["acme-staging.com", "extra.test"],
                               max_action_class=ActionClass.ACTIVE_SCAN), actor="op")

    repo2 = SqlEngagementRepository(url)
    assert len(repo2.list()) == 2
    assert repo2.get(e1.id).status is EngagementStatus.DRAFT   # frozen, persisted


def test_start_refusal_not_persisted_as_running(tmp_path):
    url = _url(tmp_path)
    svc = EngagementService(repository=SqlEngagementRepository(url),
                            audit=AuditLog(), kill_switch=KillSwitch())
    eng = svc.create(name="a", client="c", created_by="op")
    svc.set_scope(eng.id, _scope(), actor="op")   # no authorization
    try:
        svc.start(eng.id, actor="op")
    except Exception:
        pass
    assert SqlEngagementRepository(url).get(eng.id).status is not EngagementStatus.RUNNING
