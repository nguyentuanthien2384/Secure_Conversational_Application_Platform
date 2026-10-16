"""Request-level IDS state and its immutable evidence commit together."""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import OperationalError

from src.app.audit_chain import verify_chain
from src.app.ids import Detection
from src.app.models import AuditEvent, IntrusionDetection, IntrusionSource


def _scan_hits(_surface):
    return [
        ("ATOMIC-001", "high", "First request signature", "secret first evidence"),
        ("ATOMIC-002", "high", "Second request signature", "secret second evidence"),
    ]


def _seed_state(app):
    def detection(ip, severity):
        return Detection(
            rule_id="SEED", severity=severity, engine="test", description="Existing state",
            source_ip=ip, path="/seed", method="GET", evidence_sha256="0" * 64,
        )
    state = app.state.intrusion_state
    state.record(detection("192.0.2.44", "high"))
    state.record(detection("192.0.2.44", "high"))
    state.record(detection("testclient", "low"))
    with app.state.database.session_factory() as db:
        return {
            "history": list(db.scalars(select(IntrusionDetection.payload_json).order_by(IntrusionDetection.id))),
            "scores": db.get(IntrusionSource, "testclient").score_times_json,
        }


@pytest.mark.parametrize("failed_entry", ["first_signature", "second_signature", "block", "commit"])
def test_ids_request_rolls_back_all_state_and_evidence_on_audit_failure(
    client, app, monkeypatch, failed_entry,
):
    baseline = _seed_state(app)
    emitted = []
    anchored = []
    monkeypatch.setattr("src.app.main.scan_text", _scan_hits)
    monkeypatch.setattr("src.app.audit.emit_security_event", lambda *args, **kwargs: emitted.append(args))
    app.state.audit_checkpoint_service = SimpleNamespace(
        maybe_anchor=lambda db, entry: anchored.append(entry.id),
    )
    inserted = []

    def fail_selected_entry(_conn, _cursor, statement, _parameters, context, _many):
        if not statement.lstrip().lower().startswith("insert into audit_events"):
            return
        for values in context.compiled_parameters:
            inserted.append(values["event_type"])
            rejected = (
                failed_entry == "first_signature" and len(inserted) == 1
                or failed_entry == "second_signature" and len(inserted) == 2
                or failed_entry == "block" and values["event_type"] == "ids.block"
            )
            if rejected:
                raise OperationalError("private storage fault", None, RuntimeError("private reason"))

    def fail_commit(_db):
        if failed_entry == "commit":
            raise OperationalError("private commit fault", None, RuntimeError("private reason"))

    engine = app.state.database.engine
    sessions = app.state.database.session_factory
    event.listen(engine, "before_cursor_execute", fail_selected_entry)
    event.listen(sessions, "before_commit", fail_commit)
    try:
        response = client.get("/api/health")
    finally:
        event.remove(engine, "before_cursor_execute", fail_selected_entry)
        event.remove(sessions, "before_commit", fail_commit)
    assert response.status_code == 503, response.text
    assert response.headers["Retry-After"] and response.headers["X-Request-ID"]
    assert "private" not in response.text
    assert inserted
    assert not emitted and not anchored, "Uncommitted evidence must never reach SIEM or WORM"
    with app.state.database.session_factory() as db:
        assert list(db.scalars(select(AuditEvent))) == []
        assert list(db.scalars(select(IntrusionDetection.payload_json).order_by(IntrusionDetection.id))) == baseline["history"]
        source = db.get(IntrusionSource, "testclient")
        assert source.score_times_json == baseline["scores"] and source.blocked_until is None
    assert app.state.intrusion_state.is_blocked("192.0.2.44")[0], "A failed new detection cannot remove an existing ban"
    assert app.state.intrusion_state.is_blocked("testclient") == (False, 0)


def test_ids_request_commits_multiple_signatures_one_ban_and_ordered_seals(client, app, monkeypatch):
    monkeypatch.setattr("src.app.main.scan_text", _scan_hits)
    emitted = []
    anchored = []

    def observe_delivery(event_type, **kwargs):
        with app.state.database.session_factory() as db:
            assert len(list(db.scalars(select(AuditEvent)))) == 3
            assert db.get(IntrusionSource, "testclient").blocked_until is not None
        emitted.append(event_type)

    monkeypatch.setattr("src.app.audit.emit_security_event", observe_delivery)
    app.state.audit_checkpoint_service = SimpleNamespace(
        maybe_anchor=lambda db, entry: anchored.append(entry.event_type),
    )
    response = client.get("/api/health")
    assert response.status_code == 403 and int(response.headers["Retry-After"]) > 0
    assert emitted == anchored == ["ids.signature", "ids.signature", "ids.block"]
    with app.state.database.session_factory() as db:
        entries = list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))
        assert [entry.target_id for entry in entries] == ["ATOMIC-001", "ATOMIC-002", "testclient"]
        assert all(entry.outcome == "blocked" for entry in entries)
        assert len({entry.request_id for entry in entries}) == 1
        assert all("secret" not in entry.details_json for entry in entries)
        assert len(list(db.scalars(select(IntrusionDetection.id)))) == 2
        verification = verify_chain(db, app.state.audit_key)
        assert verification.intact and verification.verified == 3
    again = client.get("/api/health")
    assert again.status_code == 403
    assert emitted == ["ids.signature", "ids.signature", "ids.block"]


def test_concurrent_ids_requests_make_one_audited_ban_without_bypassing_it(client, app, monkeypatch):
    monkeypatch.setattr("src.app.main.scan_text", _scan_hits)
    ready = threading.Barrier(4)
    original = app.state.intrusion_state.is_blocked
    initial_reads = set()
    initial_lock = threading.Lock()

    def synchronized_read(source_ip, *, db=None):
        result = original(source_ip, db=db)
        if db is None:
            with initial_lock:
                first = threading.get_ident() not in initial_reads
                initial_reads.add(threading.get_ident())
            if first:
                ready.wait(timeout=10)
        return result

    monkeypatch.setattr(app.state.intrusion_state, "is_blocked", synchronized_read)
    with ThreadPoolExecutor(max_workers=4) as executor:
        responses = list(executor.map(lambda _: client.get("/api/health"), range(4)))
    assert all(response.status_code == 403 for response in responses), [response.status_code for response in responses]
    with app.state.database.session_factory() as db:
        entries = list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))
        assert [entry.event_type for entry in entries].count("ids.block") == 1
        signatures = [entry for entry in entries if entry.event_type == "ids.signature"]
        assert len(signatures) == 8
        assert len({entry.request_id for entry in signatures}) == 4
        assert all(entry.outcome == "blocked" for entry in signatures)
        assert verify_chain(db, app.state.audit_key).intact
        assert len(json.loads(db.get(IntrusionSource, "testclient").score_times_json)) == app.state.settings.ids_block_threshold
