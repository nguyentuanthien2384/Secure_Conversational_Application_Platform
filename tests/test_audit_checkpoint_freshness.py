from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from src.app.audit_chain import append_lock, derive_audit_key, seal_event
from src.app.audit_checkpoint import AuditCheckpointError, AuditCheckpointService
from src.app.db import Database
from src.app.main import create_app
from src.app.models import AuditEvent, User
from tests.conftest import register_and_login


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


def test_worm_retry_reuses_the_same_checkpoint_idempotency_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    secret = "checkpoint-idempotency-test-secret"
    database = Database(f"sqlite:///{tmp_path / 'idempotency.db'}")
    database.create_all()
    _append_event(database, secret, "test.idempotent.anchor")
    token_file = tmp_path / "idempotency-worm-token"
    token_file.write_text("test-worm-token-material", encoding="utf-8")
    service = AuditCheckpointService(
        secret,
        endpoint="https://worm.example.test/checkpoints",
        token_file=str(token_file),
    )
    attempted_ids: list[str] = []

    def flaky_delivery(_document, checkpoint_id):
        attempted_ids.append(checkpoint_id)
        if len(attempted_ids) == 1:
            raise AuditCheckpointError("simulated lost response")
        return "sha256:" + "d" * 64

    monkeypatch.setattr(service, "_deliver", flaky_delivery)
    with database.session_factory() as db:
        with pytest.raises(AuditCheckpointError, match="lost response"):
            service.anchor(db)
        checkpoint = service.anchor(db)

    assert checkpoint is not None
    assert attempted_ids == [checkpoint.id, checkpoint.id]


def test_local_checkpoint_is_never_reported_as_high_assurance(
    client: TestClient, app
):
    token = register_and_login(client, "local-checkpoint-admin")
    with app.state.database.session_factory() as db:
        admin = db.scalar(select(User).where(User.username == "local-checkpoint-admin"))
        assert admin is not None
        admin.role = "admin"
        db.commit()

    headers = {"Authorization": f"Bearer {token}"}
    checkpoint = client.post("/api/admin/audit/checkpoint", headers=headers)
    assert checkpoint.status_code == 200, checkpoint.text
    assert checkpoint.json()["externally_delivered"] is False

    verification = client.get("/api/admin/audit/verify", headers=headers)
    assert verification.status_code == 200, verification.text
    assert verification.json()["chain_intact"] is True
    assert verification.json()["checkpoint_intact"] is True
    assert verification.json()["external_checkpoint_required"] is False
    assert verification.json()["high_assurance_intact"] is False


def _high_worm_app(settings, tmp_path: Path):
    token_file = tmp_path / "strict-worm-token"
    token_file.write_text("strict-worm-test-token", encoding="utf-8")
    strict_settings = replace(
        settings,
        security_profile="high",
        audit_worm_endpoint="https://worm.example.test/checkpoints",
        audit_worm_token_file=str(token_file),
        audit_checkpoint_interval=1,
        audit_max_unanchored_events=0,
        audit_worm_probe_interval_seconds=300,
    )
    return create_app(strict_settings)


def test_high_readiness_fails_closed_and_recovers_unanchored_tail(
    settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    app = _high_worm_app(settings, tmp_path)
    service = app.state.audit_checkpoint_service
    deliveries: list[str] = []

    def deliver(_document, checkpoint_id):
        deliveries.append(checkpoint_id)
        return "sha256:" + "b" * 64

    monkeypatch.setattr(service, "_deliver", deliver)
    with TestClient(app) as client:
        # High-profile startup creates and externally anchors a signed event.
        assert deliveries
        startup_checkpoint_id = deliveries[-1]
        service._last_external_success_monotonic = None
        ready = client.get("/api/ready")
        assert ready.status_code == 200
        assert ready.json() == {"status": "ready"}
        assert deliveries[-1] == startup_checkpoint_id
        delivery_count = len(deliveries)
        assert client.get("/api/ready").status_code == 200
        assert len(deliveries) == delivery_count

        def unavailable(_document, _checkpoint_id):
            failed_deliveries.append(_checkpoint_id)
            raise AuditCheckpointError("simulated WORM outage")

        failed_deliveries: list[str] = []
        monkeypatch.setattr(service, "_deliver", unavailable)
        _append_event(app.state.database, settings.secret_key, "test.pending.tail")
        unavailable_response = client.get("/api/ready")
        assert unavailable_response.status_code == 503
        assert unavailable_response.json() == {"status": "unavailable"}
        assert unavailable_response.headers["Retry-After"] == "30"
        assert "worm" not in unavailable_response.text.lower()
        # A public caller cannot amplify the outage into repeated external
        # connection attempts during the advertised retry window.
        assert client.get("/api/ready").status_code == 503
        assert len(failed_deliveries) == 1

        monkeypatch.setattr(service, "_deliver", deliver)
        service._last_external_failure_monotonic = None
        recovered = client.get("/api/ready")
        assert recovered.status_code == 200
        with app.state.database.session_factory() as db:
            verification = service.verify_latest(db)
        assert verification.unanchored_events == 0
        assert verification.fully_anchored is True


def test_admin_verification_never_calls_an_unanchored_tail_high_assurance(
    settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    app = _high_worm_app(settings, tmp_path)
    service = app.state.audit_checkpoint_service
    monkeypatch.setattr(
        service,
        "_deliver",
        lambda _document, _checkpoint_id: "sha256:" + "c" * 64,
    )

    with TestClient(app) as client:
        token = register_and_login(client, "freshness-integration-admin")
        with app.state.database.session_factory() as db:
            admin = db.scalar(
                select(User).where(User.username == "freshness-integration-admin")
            )
            assert admin is not None
            admin.role = "admin"
            # This integration test exercises the audit verdict, not MFA
            # enrollment; high-profile admin access itself still enforces MFA.
            admin.mfa_enabled = True
            db.commit()

        good = client.get(
            "/api/admin/audit/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert good.status_code == 200
        assert good.json()["checkpoint_fully_anchored"] is True
        assert good.json()["high_assurance_intact"] is True

        def unavailable(_document, _checkpoint_id):
            raise AuditCheckpointError("simulated WORM outage")

        monkeypatch.setattr(service, "_deliver", unavailable)
        _append_event(app.state.database, settings.secret_key, "test.unanchored.integration")
        degraded = client.get(
            "/api/admin/audit/verify",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert degraded.status_code == 200
        assert degraded.json()["checkpoint_unanchored_events"] >= 1
        assert degraded.json()["checkpoint_fully_anchored"] is False
        assert degraded.json()["high_assurance_intact"] is False


def test_high_startup_refuses_an_unavailable_worm_sink(
    settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    app = _high_worm_app(settings, tmp_path)

    def unavailable(_document, _checkpoint_id):
        raise AuditCheckpointError("simulated WORM outage")

    monkeypatch.setattr(app.state.audit_checkpoint_service, "_deliver", unavailable)
    with pytest.raises(RuntimeError, match="refusing high-security startup"):
        with TestClient(app):
            pass
