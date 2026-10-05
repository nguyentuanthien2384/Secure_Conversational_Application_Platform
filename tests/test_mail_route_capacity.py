from __future__ import annotations

import json
from dataclasses import replace

import pytest
from sqlalchemy import select

from src.app.account_recovery import derive_password_reset_key, derive_recovery_code_key, issue_code
from src.app.db import utcnow
from src.app.mailer import MailBusy, MailUnavailable
from src.app.main import create_app
from src.app.models import AccountEmail, AccountRecoveryCode, AuditEvent, User
from tests.conftest import register_and_login
from tests.test_account_recovery import Recorder, add_verified_email, auth


@pytest.fixture
def mail(app):
    recorder = Recorder()
    app.state.mailer.transport = recorder
    app.state.mailer.background = False
    return recorder


@pytest.mark.parametrize("failure", [MailBusy, MailUnavailable])
def test_reset_queue_failure_does_not_reveal_accounts(client, app, mail, monkeypatch, failure):
    token = register_and_login(client, "mail-capacity-owner")
    add_verified_email(client, mail, token, "owner@example.com")

    def reject(*args, **kwargs):
        raise failure("transport details must not reach the response")

    monkeypatch.setattr(app.state.mailer, "send", reject)
    existing = client.post("/api/auth/password-reset/request", json={
        "identifier": "mail-capacity-owner",
    })
    unknown = client.post("/api/auth/password-reset/request", json={
        "identifier": "mail-capacity-unknown",
    })
    assert existing.status_code == unknown.status_code == 202
    assert existing.json() == unknown.json()
    assert "transport details" not in existing.text
    with app.state.database.session_factory() as db:
        pending = db.scalar(select(AccountRecoveryCode).where(
            AccountRecoveryCode.purpose == "password_reset",
            AccountRecoveryCode.consumed_at.is_(None),
        ))
        assert pending is None
        events = db.scalars(select(AuditEvent).where(
            AuditEvent.event_type == "auth.password_reset.request",
            AuditEvent.outcome == "failure",
        )).all()
        assert any(json.loads(event.details_json).get("reason") == "mail_unavailable"
                   for event in events)


def test_authenticated_email_busy_is_retryable_without_error_details(client, app, mail, monkeypatch):
    token = register_and_login(client, "mail-capacity-auth")

    def reject(*args, **kwargs):
        raise MailBusy("sensitive backend details")

    monkeypatch.setattr(app.state.mailer, "send", reject)
    response = client.post("/api/auth/email", headers=auth(token), json={
        "email": "owner@example.com",
    })
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "10"
    assert response.headers["Cache-Control"] == "no-store"
    assert "sensitive backend details" not in response.text


def test_failed_reset_delivery_cannot_burn_newer_issued_code(client, app, mail, monkeypatch):
    token = register_and_login(client, "mail-concurrent-reset")
    add_verified_email(client, mail, token, "owner@example.com")

    def newer_issuance_then_reject(*args, **kwargs):
        # Simulate another request issuing a fresh code after the first request
        # committed and before its mail failure was reported.
        with app.state.database.session_factory() as db:
            user = db.scalar(select(User).where(User.username == "mail-concurrent-reset"))
            email = db.get(AccountEmail, user.id)
            key = derive_password_reset_key(
                derive_recovery_code_key(app.state.settings.secret_key), user_id=user.id,
                password_hash=user.password_hash, normalized_email=email.normalized_email,
            )
            issue_code(db, key, user_id=user.id, purpose="password_reset", now=utcnow(), minutes=15)
            db.commit()
        raise MailBusy("queue busy")

    monkeypatch.setattr(app.state.mailer, "send", newer_issuance_then_reject)
    response = client.post("/api/auth/password-reset/request", json={
        "identifier": "mail-concurrent-reset",
    })
    assert response.status_code == 202
    with app.state.database.session_factory() as db:
        records = db.scalars(select(AccountRecoveryCode).where(
            AccountRecoveryCode.purpose == "password_reset",
        ).order_by(AccountRecoveryCode.created_at)).all()
        assert len(records) == 2
        assert records[0].consumed_at is not None
        assert records[1].consumed_at is None


def test_mail_capacity_visible_only_to_admin_without_addresses(client, app, mail):
    token = register_and_login(client, "mail-capacity-admin")
    assert client.get("/api/admin/availability", headers=auth(token)).status_code == 403
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "mail-capacity-admin"))
        user.role = "admin"
        db.commit()
    response = client.get("/api/admin/availability", headers=auth(token))
    assert response.status_code == 200
    assert response.json()["mail"] == {
        "limit": 32, "active": 0, "rejected": 0, "delivered": 0,
        "failed": 0, "closed": False,
    }
    assert "owner@example.com" not in response.text


@pytest.mark.parametrize("field,value", [
    ("mail_max_pending", 0), ("mail_outbox_max_files", 10_001),
    ("mail_outbox_max_bytes", 65_535),
])
def test_mail_limits_reject_unsafe_direct_configuration(settings, field, value):
    with pytest.raises(ValueError, match="MAIL_"):
        create_app(replace(settings, **{field: value}))
