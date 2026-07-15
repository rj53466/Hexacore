import json

from hexacore.safety import AuditLog, KillSwitch


# --- kill switch ---------------------------------------------------------

def test_per_engagement_kill():
    ks = KillSwitch()
    ks.trip("eng-1")
    assert ks.is_killed("eng-1")
    assert not ks.is_killed("eng-2")


def test_global_kill_halts_all():
    ks = KillSwitch()
    ks.trip()
    assert ks.is_killed("eng-1") and ks.is_killed("eng-2") and ks.is_killed(None)


def test_reset():
    ks = KillSwitch()
    ks.trip("eng-1")
    ks.reset("eng-1")
    assert not ks.is_killed("eng-1")


def test_trip_notifies_listener():
    seen = []
    ks = KillSwitch(on_trip=seen.append)
    ks.trip("eng-9")
    assert seen == ["eng-9"]


# --- audit log -----------------------------------------------------------

def test_audit_appends_to_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("scope.denied", actor="agent", engagement_id="eng-1", target="evil.com")
    log.record("command.authorized", actor="agent", engagement_id="eng-1", target="ok.com")
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["type"] == "scope.denied"
    assert first["payload"]["target"] == "evil.com"
    assert "at" in first and "id" in first


def test_audit_mirror_and_filter(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("scope.denied", actor="agent")
    log.record("gate.requested", actor="agent")
    log.record("scope.denied", actor="agent")
    assert len(log.events) == 3
    assert len(log.events_of_type("scope.denied")) == 2


def test_audit_has_no_mutation_api():
    # Append-only: the writer must not expose update/delete.
    log = AuditLog(mirror=True)
    for name in ("update", "delete", "remove", "clear", "pop"):
        assert not hasattr(log, name)
