"""SMS budgets outlive bearer rows and opt-out, with bounded proof retention."""
from __future__ import annotations

import uuid
from datetime import timedelta

from sqlalchemy import func, select

from src.app.db import utcnow
from src.app.models import AuthSession, SecurityPhoneChallenge
from src.app.retention import enforce_retention
from tests import test_security_notifications as notification_regressions
from tests.conftest import register_and_login
from tests.test_security_notifications import (
    auth,
    phone_request,
    verify_phone,
)

notices = notification_regressions.notices
settings = notification_regressions.settings


def _proof(user_id, session_id, *, created_at, consumed_at=None, expires_at=None):
    return SecurityPhoneChallenge(
        id=str(uuid.uuid4()), user_id=user_id, auth_session_id=session_id,
        phone_hash=uuid.uuid4().hex * 2, phone_ciphertext="encrypted", phone_nonce="nonce",
        code_hash="0" * 64, created_at=created_at,
        expires_at=expires_at or created_at + timedelta(minutes=5), consumed_at=consumed_at,
    )


def test_sms_daily_budget_survives_expired_bearer_retention(client, app, notices):
    token = register_and_login(client, "sms-bearer-retention")
    claims = app.state.token_service.decode(token)
    new_login = client.post("/api/auth/login", json={
        "username": "sms-bearer-retention", "password": "Correct Horse Battery1",
    })
    assert new_login.status_code == 200
    new_token = new_login.json()["access_token"]
    now = utcnow()
    with app.state.database.session_factory() as db:
        rows = [
            _proof(claims["sub"], claims["jti"], created_at=now - timedelta(hours=2))
            for _ in range(10)
        ]
        db.add_all(rows)
        db.get(AuthSession, claims["jti"]).expires_at = now - timedelta(seconds=1)
        db.commit()
        result = enforce_retention(db, now=now)
        assert result.expired_auth_sessions == 1
        assert result.expired_phone_challenges == 0
        db.expire_all()  # Foreign-key SET NULL executes in the database.
        remaining = list(db.scalars(select(SecurityPhoneChallenge)))
        assert len(remaining) == 10
        assert all(row.auth_session_id is None for row in remaining)
        challenge_id = remaining[0].id
    assert verify_phone(client, token, challenge_id, "00000000").status_code == 401
    assert verify_phone(client, new_token, challenge_id, "00000000").status_code == 400
    response = client.post("/api/auth/notifications/phone/request", headers=auth(new_token),
                           json={"phone": "+84901234599"})
    assert response.status_code == 429
    assert "SMS" in response.json()["detail"]


def test_sms_opt_out_invalidates_proofs_without_resetting_issuance_budget(client, app, notices):
    token = register_and_login(client, "sms-opt-out-budget")
    latest_id = latest_code = None
    for suffix in ("67", "68", "69"):
        latest_id, latest_code = phone_request(client, token, notices, "+849012345" + suffix)
    assert client.delete("/api/auth/notifications/phone", headers=auth(token)).status_code == 204
    assert verify_phone(client, token, latest_id, latest_code).status_code == 400
    with app.state.database.session_factory() as db:
        rows = list(db.scalars(select(SecurityPhoneChallenge)))
        assert len(rows) == 3
        assert all(row.consumed_at is not None for row in rows)
        assert all(row.phone_ciphertext == row.phone_nonce == "" for row in rows)
        assert all(row.code_hash == "0" * 64 for row in rows)
    # A new number avoids the separate in-memory target limiter: SQL issuance
    # history alone must still reject this fourth SMS request.
    response = client.post("/api/auth/notifications/phone/request", headers=auth(token),
                           json={"phone": "+84901234599"})
    assert response.status_code == 429
    assert "SMS" in response.json()["detail"]


def test_sms_proof_retention_keeps_quota_window_and_is_bounded_and_dry_run(client, app):
    token = register_and_login(client, "sms-proof-retention")
    claims = app.state.token_service.decode(token)
    now = utcnow()
    with app.state.database.session_factory() as db:
        old = [
            _proof(claims["sub"], claims["jti"], created_at=now - timedelta(days=3, minutes=index),
                   consumed_at=now if index % 2 else None)
            for index in range(4)
        ]
        retained = [
            _proof(claims["sub"], claims["jti"], created_at=now - timedelta(hours=age))
            for age in (23, 25)
        ]
        retained.append(_proof(claims["sub"], claims["jti"],
                               created_at=now - timedelta(days=3),
                               expires_at=now + timedelta(minutes=1)))
        db.add_all(old + retained)
        db.commit()
        retained_ids = {row.id for row in retained}
        dry = enforce_retention(db, now=now, batch_size=2, dry_run=True)
        assert dry.expired_phone_challenges == 2 and dry.dry_run
        assert db.scalar(select(func.count()).select_from(SecurityPhoneChallenge)) == 7
        for _ in range(2):
            assert enforce_retention(db, now=now, batch_size=2).expired_phone_challenges == 2
        assert enforce_retention(db, now=now, batch_size=2).expired_phone_challenges == 0
        assert set(db.scalars(select(SecurityPhoneChallenge.id))) == retained_ids
