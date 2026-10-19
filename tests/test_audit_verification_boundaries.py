from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

import src.app.main as app_module
from src.app.audit_chain import append_lock, derive_audit_key, seal_event, verify_chain
from src.app.audit_checkpoint import AuditCheckpointIntegrityError, AuditCheckpointService
from src.app.db import Database
from src.app.main import create_app
from src.app.models import AuditCheckpoint, AuditEvent, User
from tests.conftest import register_and_login

SECRET = "audit-verification-boundary-test-secret"


@pytest.fixture()
def audit_database(tmp_path: Path):
    database = Database(f"sqlite:///{tmp_path / 'audit-boundaries.db'}")
    database.create_all()
    try:
        yield database
    finally:
        database.engine.dispose()


def _append_event(
    database: Database,
    *,
    secret: str = SECRET,
    event_id: int | None = None,
) -> AuditEvent:
    with database.session_factory() as db:
        event = AuditEvent(event_type="test.boundary", outcome="success", details_json="{}")
        with append_lock(db):
            seal_event(db, event, derive_audit_key(secret))
            if event_id is not None:
                # PostgreSQL sequences keep advancing after a deleted suffix.
                # Explicit ids reproduce that behavior on the SQLite test DB.
                event.id = event_id
            db.add(event)
            db.commit()
        return event


def _remote_service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    token_file = tmp_path / "worm-token"
    token_file.write_text("test-only-worm-token", encoding="utf-8")
    service = AuditCheckpointService(
        SECRET,
        interval=1,
        endpoint="https://worm.example.test/checkpoints",
        token_file=str(token_file),
    )
    deliveries: list[str] = []

    def deliver(_document, checkpoint_id):
        deliveries.append(checkpoint_id)
        return "sha256:" + "a" * 64

    monkeypatch.setattr(service, "_deliver", deliver)
    return service, deliveries


@pytest.mark.parametrize("digest", ["é" * 64, "short", "g" * 64, ""])
def test_malformed_event_digest_reports_broken_chain(audit_database, digest):
    event = _append_event(audit_database)
    with audit_database.session_factory() as db:
        row = db.get(AuditEvent, event.id)
        assert row is not None
        row.entry_hash = digest
        db.commit()

        verdict = verify_chain(db, derive_audit_key(SECRET))

    assert verdict.intact is False
    assert verdict.first_broken_id == event.id
    assert verdict.reason == "entry_hash_mismatch"


@pytest.mark.parametrize("field", ["root_hash", "signature"])
@pytest.mark.parametrize("digest", ["é" * 64, "short", "g" * 64, ""])
def test_malformed_checkpoint_digest_reports_broken_checkpoint(
    audit_database, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field, digest,
):
    service, _ = _remote_service(tmp_path, monkeypatch)
    _append_event(audit_database)
    with audit_database.session_factory() as db:
        checkpoint = service.anchor(db)
        assert checkpoint is not None
        setattr(checkpoint, field, digest)
        db.commit()

        verdict = service.verify_latest(db)

    assert verdict.present is True
    assert verdict.intact is False
    assert verdict.fully_anchored is False
    expected = "checkpoint_root_mismatch" if field == "root_hash" else "checkpoint_signature_mismatch"
    assert verdict.reason == expected


@pytest.mark.parametrize("event_id", [0, -1])
def test_invalid_checkpoint_event_id_reports_missing_anchored_event(
    audit_database, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, event_id,
):
    service, _ = _remote_service(tmp_path, monkeypatch)
    _append_event(audit_database)
    with audit_database.session_factory() as db:
        checkpoint = service.anchor(db)
        assert checkpoint is not None
        checkpoint.last_event_id = event_id
        db.commit()

        verdict = service.verify_latest(db)

    assert verdict.intact is False
    assert verdict.fully_anchored is False
    assert verdict.reason == "anchored_event_missing"


@pytest.mark.parametrize("operation", ["anchor", "maybe_anchor", "ensure_latest_anchored"])
@pytest.mark.parametrize("damage", ["deleted_tail", "signature", "root_hash"])
def test_new_anchor_cannot_conceal_an_existing_broken_checkpoint(
    audit_database, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation, damage,
):
    service, deliveries = _remote_service(tmp_path, monkeypatch)
    _append_event(audit_database, event_id=1)
    with audit_database.session_factory() as db:
        assert service.anchor(db) is not None
    _append_event(audit_database, event_id=2)
    with audit_database.session_factory() as db:
        checkpoint = service.anchor(db)
        assert checkpoint is not None
        damaged_checkpoint_id = checkpoint.id
        if damage == "deleted_tail":
            event = db.get(AuditEvent, 2)
            assert event is not None
            db.delete(event)
        else:
            setattr(checkpoint, damage, "f" * 64)
        db.commit()
        assert service.verify_latest(db).intact is False

    # Ordinary audit appends can continue after an anchoring failure. They must
    # never erase the evidence by making a new, apparently healthy checkpoint.
    latest = _append_event(audit_database, event_id=3)
    deliveries_before = len(deliveries)
    with audit_database.session_factory() as db:
        # Evidence, not an outage: callers must not report a WORM failure.
        with pytest.raises(AuditCheckpointIntegrityError):
            if operation == "maybe_anchor":
                service.maybe_anchor(db, latest)
            else:
                getattr(service, operation)(db)
        db.rollback()
        verdict = service.verify_latest(db)
        checkpoint = db.scalar(
            select(AuditCheckpoint).order_by(AuditCheckpoint.last_event_id.desc()).limit(1)
        )

    assert verdict.intact is False
    assert checkpoint is not None
    assert checkpoint.id == damaged_checkpoint_id
    assert checkpoint.last_event_id == 2
    assert len(deliveries) == deliveries_before


@pytest.mark.parametrize("invalid_append", [False, True])
def test_admin_verdict_does_not_mix_verified_chain_with_a_later_checkpoint(
    settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid_append,
):
    token_file = tmp_path / "high-worm-token"
    token_file.write_text("test-only-high-worm-token", encoding="utf-8")
    high_settings = replace(
        settings,
        security_profile="high",
        audit_worm_endpoint="https://worm.example.test/checkpoints",
        audit_worm_token_file=str(token_file),
        audit_checkpoint_interval=1,
        audit_max_unanchored_events=0,
    )
    app = create_app(high_settings)
    service = app.state.audit_checkpoint_service
    monkeypatch.setattr(service, "_deliver", lambda *_args: "sha256:" + "b" * 64)

    try:
        with TestClient(app) as client:
            token = register_and_login(client, "audit-boundary-admin")
            with app.state.database.session_factory() as db:
                admin = db.scalar(select(User).where(User.username == "audit-boundary-admin"))
                assert admin is not None
                admin.role = "admin"
                admin.mfa_enabled = True
                db.commit()

            appended_ids: list[int] = []

            def verify_then_concurrent_append(db, key, **kwargs):
                verdict = verify_chain(db, key, **kwargs)
                with app.state.database.session_factory() as writer:
                    event = AuditEvent(
                        event_type="test.concurrent.append", outcome="success", details_json="{}",
                    )
                    with append_lock(writer):
                        seal_event(writer, event, key)
                        if invalid_append:
                            event.entry_hash = "f" * 64
                        writer.add(event)
                        writer.commit()
                    appended_ids.append(event.id)
                    assert service.anchor(writer) is not None
                return verdict

            monkeypatch.setattr(app_module, "verify_chain", verify_then_concurrent_append)
            response = client.get(
                "/api/admin/audit/verify", headers={"Authorization": f"Bearer {token}"},
            )

            assert response.status_code == 200, response.text
            payload = response.json()
            assert len(appended_ids) == 1
            assert payload["chain_intact"] is True
            assert payload["checkpoint_fully_anchored"] is True
            assert payload["checkpoint_latest_event_id"] == appended_ids[0]
            assert payload["verified_through_event_id"] < appended_ids[0]
            assert payload["verification_scope_changed"] is True
            assert payload["high_assurance_intact"] is False
            with app.state.database.session_factory() as db:
                actual = verify_chain(db, app.state.audit_key)
            assert actual.intact is not invalid_append
    finally:
        app.state.database.engine.dispose()


def test_admin_verdict_retains_high_assurance_for_a_matching_verified_checkpoint(
    settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    token_file = tmp_path / "matching-worm-token"
    token_file.write_text("test-only-matching-worm-token", encoding="utf-8")
    high_settings = replace(
        settings,
        security_profile="high",
        audit_worm_endpoint="https://worm.example.test/checkpoints",
        audit_worm_token_file=str(token_file),
        audit_checkpoint_interval=1,
        audit_max_unanchored_events=0,
    )
    app = create_app(high_settings)
    service = app.state.audit_checkpoint_service
    monkeypatch.setattr(service, "_deliver", lambda *_args: "sha256:" + "c" * 64)
    try:
        with TestClient(app) as client:
            token = register_and_login(client, "matching-checkpoint-admin")
            with app.state.database.session_factory() as db:
                admin = db.scalar(select(User).where(User.username == "matching-checkpoint-admin"))
                assert admin is not None
                admin.role = "admin"
                admin.mfa_enabled = True
                db.commit()

            response = client.get(
                "/api/admin/audit/verify", headers={"Authorization": f"Bearer {token}"},
            )

            assert response.status_code == 200, response.text
            payload = response.json()
            assert payload["chain_intact"] is True
            assert payload["checkpoint_fully_anchored"] is True
            assert payload["high_assurance_intact"] is True
            assert payload["verification_scope_changed"] is False
            assert payload["verified_through_event_id"] == payload["checkpoint_last_event_id"]
            assert payload["verified_through_event_id"] == payload["checkpoint_latest_event_id"]
            assert payload["verified_through_entry_hash"] == payload["checkpoint_root_hash"]
    finally:
        app.state.database.engine.dispose()
