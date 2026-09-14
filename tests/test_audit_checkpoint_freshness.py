from __future__ import annotations

from pathlib import Path

import pytest

from src.app.audit_chain import append_lock, derive_audit_key, seal_event
from src.app.audit_checkpoint import AuditCheckpointService
from src.app.db import Database
from src.app.models import AuditEvent


def _append_event(database: Database, secret: str, event_type: str) -> AuditEvent:
    with database.session_factory() as db:
        event = AuditEvent(event_type=event_type, outcome="success", details_json="{}")
        with append_lock(db):
            seal_event(db, event, derive_audit_key(secret))
            db.add(event)
            db.commit()
            db.refresh(event)
        return event


def _remote_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secret: str,
    *,
    max_unanchored_events: int,
) -> AuditCheckpointService:
    token_file = tmp_path / "worm-token"
    token_file.write_text("test-worm-token-material", encoding="utf-8")
    service = AuditCheckpointService(
        secret,
        endpoint="https://worm.example.test/checkpoints",
        token_file=str(token_file),
        max_unanchored_events=max_unanchored_events,
    )
    monkeypatch.setattr(
        service,
        "_deliver",
        lambda _document, _checkpoint_id: "sha256:" + "a" * 64,
    )
    return service


def test_checkpoint_reports_latest_tail_and_full_external_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    secret = "checkpoint-freshness-test-secret"
    database = Database(f"sqlite:///{tmp_path / 'audit.db'}")
    database.create_all()
    service = _remote_service(
        tmp_path,
        monkeypatch,
        secret,
        max_unanchored_events=0,
    )

    first = _append_event(database, secret, "test.first")
    with database.session_factory() as db:
        checkpoint = service.anchor(db)
        assert checkpoint is not None
        verification = service.verify_latest(db)

    assert verification.last_event_id == first.id
    assert verification.latest_event_id == first.id
    assert verification.unanchored_events == 0
    assert verification.fresh is True
    assert verification.fully_anchored is True
    assert verification.as_dict()["checkpoint_fully_anchored"] is True

    second = _append_event(database, secret, "test.second")
    with database.session_factory() as db:
        verification = service.verify_latest(db)

    assert verification.last_event_id == first.id
    assert verification.latest_event_id == second.id
    assert verification.unanchored_events == 1
    assert verification.fresh is False
    assert verification.fully_anchored is False


def test_freshness_budget_does_not_claim_full_anchoring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    secret = "checkpoint-budget-test-secret"
    database = Database(f"sqlite:///{tmp_path / 'budget.db'}")
    database.create_all()
    strict_service = _remote_service(
        tmp_path,
        monkeypatch,
        secret,
        max_unanchored_events=0,
    )

    _append_event(database, secret, "test.anchor")
    with database.session_factory() as db:
        assert strict_service.anchor(db) is not None
    latest = _append_event(database, secret, "test.tail")

    tolerant_service = _remote_service(
        tmp_path,
        monkeypatch,
        secret,
        max_unanchored_events=1,
    )
    with database.session_factory() as db:
        verification = tolerant_service.verify_latest(db)

    assert verification.latest_event_id == latest.id
    assert verification.unanchored_events == 1
    assert verification.fresh is True
    assert verification.fully_anchored is False


def test_missing_checkpoint_counts_all_events_as_unanchored(tmp_path: Path):
    secret = "missing-checkpoint-test-secret"
    database = Database(f"sqlite:///{tmp_path / 'missing.db'}")
    database.create_all()
    latest = _append_event(database, secret, "test.unanchored.one")
    latest = _append_event(database, secret, "test.unanchored.two")
    service = AuditCheckpointService(secret, max_unanchored_events=100)

    with database.session_factory() as db:
        verification = service.verify_latest(db)

    assert verification.present is False
    assert verification.latest_event_id == latest.id
    assert verification.unanchored_events == 2
    assert verification.fresh is False
    assert verification.fully_anchored is False
    assert verification.reason == "missing_checkpoint"


def test_checkpoint_rejects_negative_freshness_budget():
    with pytest.raises(ValueError, match="cannot be negative"):
        AuditCheckpointService("test-secret", max_unanchored_events=-1)
