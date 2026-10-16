"""Historical anchors remain evidence after a newer checkpoint is present."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from src.app.audit_chain import derive_audit_key, verify_chain
from src.app.audit_checkpoint import AuditCheckpointError, canonical_checkpoint, sign_checkpoint
from src.app.db import Database, utcnow
from src.app.models import AuditCheckpoint, AuditEvent
from tests.test_audit_verification_boundaries import (
    SECRET,
    _append_event,
    _remote_service,
)


@pytest.fixture
def audit_database(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'checkpoint-history.db'}")
    database.create_all()
    try:
        yield database
    finally:
        database.engine.dispose()


def superseded_damage(database, service, damage):
    _append_event(database, event_id=1)
    with database.session_factory() as db:
        service.anchor(db)
    _append_event(database, event_id=2)
    with database.session_factory() as db:
        old = service.anchor(db)
        old_id = old.id
        if damage == "deleted_tail":
            db.delete(db.get(AuditEvent, 2))
        else:
            setattr(old, damage, "f" * 64)
        db.commit()
    latest = _append_event(database, event_id=3)
    # Model a valid newer checkpoint created by an older app before the guard
    # was added. The old contradictory evidence must still be checked today.
    with database.session_factory() as db:
        checkpoint_id, created_at = str(uuid.uuid4()), utcnow()
        payload = canonical_checkpoint(
            checkpoint_id=checkpoint_id, last_event_id=latest.id,
            root_hash=latest.entry_hash, created_at=created_at,
        )
        db.add(AuditCheckpoint(
            id=checkpoint_id, last_event_id=latest.id, root_hash=latest.entry_hash,
            signature=sign_checkpoint(service.key, payload),
            signer_uri="hmac-sha256://scap/audit-checkpoint-v1", signer_version="v1",
            created_at=created_at, delivered_at=created_at, external_receipt="sha256:" + "a" * 64,
        ))
        db.commit()
    return old_id, checkpoint_id, latest


@pytest.mark.parametrize("damage", ["deleted_tail", "signature", "root_hash"])
@pytest.mark.parametrize("operation", ["verify_latest", "anchor", "maybe_anchor", "ensure_latest_anchored"])
def test_superseded_bad_checkpoint_cannot_be_ignored(
    audit_database, tmp_path, monkeypatch, damage, operation,
):
    service, deliveries = _remote_service(tmp_path, monkeypatch)
    old_id, latest_id, _latest = superseded_damage(audit_database, service, damage)
    incoming = _append_event(audit_database, event_id=4) if operation == "maybe_anchor" else None
    delivery_count = len(deliveries)
    with audit_database.session_factory() as db:
        if operation != "verify_latest":
            with pytest.raises(AuditCheckpointError):
                if operation == "maybe_anchor":
                    service.maybe_anchor(db, incoming)
                else:
                    getattr(service, operation)(db)
            db.rollback()
        verdict = service.verify_latest(db)
        assert verdict.intact is False
        assert verdict.fully_anchored is False
        data = verdict.as_dict()
        assert data["checkpoint_failed_id"] == old_id
        assert data["checkpoint_failed_event_id"] == 2
        assert data["checkpoint_reason"].startswith("historical_")
        assert db.scalar(select(AuditCheckpoint.id).order_by(AuditCheckpoint.last_event_id.desc()).limit(1)) == latest_id
    assert len(deliveries) == delivery_count


def test_healthy_checkpoint_history_retains_full_assurance(audit_database, tmp_path, monkeypatch):
    service, _ = _remote_service(tmp_path, monkeypatch)
    for event_id in range(1, 5):
        _append_event(audit_database, event_id=event_id)
        with audit_database.session_factory() as db:
            service.anchor(db)
    with audit_database.session_factory() as db:
        assert verify_chain(db, derive_audit_key(SECRET)).intact
        verdict = service.verify_latest(db)
        assert verdict.intact and verdict.fully_anchored
        assert verdict.as_dict()["checkpoint_failed_id"] is None
