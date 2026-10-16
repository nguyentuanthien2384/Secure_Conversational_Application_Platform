"""Audit persistence preserves transaction ordering and committed response state."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest
from sqlalchemy import event, inspect, select, text
from starlette.requests import Request

from scripts import create_admin as provision
from src.app.audit import record_audit
from src.app.audit_chain import derive_audit_key, verify_chain
from src.app.audit_checkpoint import AuditCheckpointError
from src.app.db import Database
from src.app.models import AuditEvent, User


@pytest.fixture
def audit_database(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'audit-transactions.db'}")
    database.create_all()
    try:
        yield database
    finally:
        database.engine.dispose()


def audit_request(key: bytes, *, checkpoint_service=None) -> Request:
    application = SimpleNamespace(state=SimpleNamespace(
        audit_key=key,
        audit_checkpoint_service=checkpoint_service,
    ))
    return Request({
        "type": "http",
        "app": application,
        "method": "POST",
        "path": "/test/audit",
        "headers": [],
        "client": ("127.0.0.1", 12345),
    })


def test_sqlite_audit_only_writer_does_not_deadlock_business_writer(audit_database):
    key = derive_audit_key("audit-transaction-test-secret")
    request = audit_request(key)
    with audit_database.session_factory() as db:
        user = User(username="lock-order-user", password_hash="test-hash", role="user")
        db.add(user)
        db.commit()
        user_id = user.id

    business_locked = threading.Event()
    contender_attempted = threading.Event()
    results: dict[str, object] = {}

    def before_sql(_connection, _cursor, statement, _parameters, _context, _many):
        # Detect the audit-only request reaching its first chain statement.
        # This also catches the former implementation's SELECT under the
        # process mutex, making the old lock inversion fail deterministically.
        if (threading.current_thread().name == "audit-only-contender"
                and "audit_events" in statement.lower()):
            contender_attempted.set()

    def business_writer():
        try:
            with audit_database.session_factory() as db:
                db.execute(text("PRAGMA busy_timeout=1500"))
                user = db.get(User, user_id)
                user.role = "moderator"
                db.flush()
                business_locked.set()
                assert contender_attempted.wait(timeout=5), "audit-only writer did not start"
                entry = record_audit(
                    db, request, "test.business.change", actor_id=user_id,
                    target_type="user", target_id=user_id,
                )
                results["business"] = entry.id
        except BaseException as error:
            results["business"] = error
            business_locked.set()

    def audit_only_writer():
        try:
            assert business_locked.wait(timeout=5), "business writer did not acquire its lock"
            with audit_database.session_factory() as db:
                db.execute(text("PRAGMA busy_timeout=1500"))
                entry = record_audit(db, request, "test.audit.only")
                results["audit_only"] = entry.id
        except BaseException as error:
            results["audit_only"] = error

    first = threading.Thread(target=business_writer, name="business-writer", daemon=True)
    second = threading.Thread(target=audit_only_writer, name="audit-only-contender", daemon=True)
    event.listen(audit_database.engine, "before_cursor_execute", before_sql)
    try:
        first.start()
        second.start()
        first.join(timeout=8)
        second.join(timeout=8)
    finally:
        contender_attempted.set()
        business_locked.set()
        first.join(timeout=3)
        second.join(timeout=3)
        event.remove(audit_database.engine, "before_cursor_execute", before_sql)

    assert not first.is_alive() and not second.is_alive(), "audit lock ordering deadlocked"
    assert isinstance(results.get("business"), int), repr(results)
    assert isinstance(results.get("audit_only"), int), repr(results)
    assert results["business"] < results["audit_only"]
    with audit_database.session_factory() as db:
        assert db.get(User, user_id).role == "moderator"
        verification = verify_chain(db, key)
        assert verification.intact and verification.verified == 2


def test_checkpoint_rollback_does_not_expire_committed_response_objects(audit_database):
    key = derive_audit_key("checkpoint-isolation-test-secret")
    observed = []

    class FailingCheckpoint:
        def maybe_anchor(self, checkpoint_db, audit_event):
            observed.append(checkpoint_db)
            # Reproduce the checkpoint service's rollback on a delivery or
            # persistence error after the business/audit commit has succeeded.
            checkpoint_db.scalar(select(AuditEvent.id))
            checkpoint_db.rollback()
            raise AuditCheckpointError("Simulated checkpoint delivery failure")

    request = audit_request(key, checkpoint_service=FailingCheckpoint())
    with audit_database.session_factory() as db:
        user = User(username="checkpoint-response", password_hash="test-hash", role="admin")
        db.add(user)
        db.flush()
        user_id = user.id
        entry = record_audit(
            db, request, "test.committed.account", target_type="user", target_id=user_id,
        )
        assert len(observed) == 1 and observed[0] is not db
        assert not inspect(user).expired_attributes
        assert not inspect(entry).expired_attributes
        entry_id = entry.id

    # Response serialization must still work after the request DB session is
    # closed; a checkpoint rollback must not force a reload of committed data.
    assert user.id == user_id and user.username == "checkpoint-response"
    assert user.role == "admin" and user.is_active is True
    assert entry.id == entry_id and entry.entry_hash
    with audit_database.session_factory() as db:
        assert db.get(User, user_id).role == "admin"
        verification = verify_chain(db, key)
        assert verification.intact and verification.verified == 1


def test_cli_claims_new_account_before_chain_lock_without_committing(
    audit_database, settings, monkeypatch,
):
    original_append_lock = provision.append_lock
    observed = []

    @contextmanager
    def checked_append_lock(db):
        created = db.scalar(select(User).where(User.username == "cli-lock-order"))
        assert created is not None, "claim the account before taking the audit lock"
        assert inspect(created).persistent
        with audit_database.session_factory() as observer:
            assert observer.get(User, created.id) is None, "account committed before audit"
        observed.append(created.id)
        with original_append_lock(db):
            yield

    monkeypatch.setattr(provision, "append_lock", checked_append_lock)
    configured = replace(settings, environment="production", security_profile="standard")
    user_id = provision.create_administrator(
        configured, audit_database, username="cli-lock-order",
        password="River Copper Evening Lantern 9274",
    )
    assert observed == [user_id]
    with audit_database.session_factory() as db:
        assert db.get(User, user_id).role == "admin"
        verification = verify_chain(db, derive_audit_key(configured.secret_key))
        assert verification.intact and verification.verified == 1
