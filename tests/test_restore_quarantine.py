"""Snapshot quarantine invalidates credentials while preserving sealed data."""

from __future__ import annotations

import time
from datetime import timedelta, timezone

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import OperationalError

from scripts.quarantine_restored_database import (
    MAX_TOKEN_VERSION,
    activate_reviewed_users,
    quarantine,
)
from src.app.db import utcnow
from src.app.models import (
    AccountRecoveryCode,
    AuditEvent,
    AuthSession,
    E2eeDevice,
    E2eeDeviceChallenge,
    E2eePreKey,
    MfaRecoveryCode,
    User,
    WebAuthnChallenge,
)
from tests.conftest import register_and_login


def test_quarantine_retires_bearers_factors_and_prekeys_without_rewriting_audit(client, app):
    token = register_and_login(client, "reviewed.restore")
    now = utcnow()
    used = now - timedelta(days=1)
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "reviewed.restore"))
        user.role = "admin"
        user_id, old_version = user.id, user.token_version
        other = User(username="unreviewed.restore", password_hash="unused", is_active=False)
        device = E2eeDevice(user_id=user_id, display_name="Restored device", identity_key_b64="public",
                            signed_prekey_b64="public", signed_prekey_signature_b64="signature",
                            fingerprint="restore-fingerprint", trust_state="trusted")
        db.add_all([other, device])
        db.flush()
        db.add_all([
            E2eePreKey(device_id=device.id, key_id="new", public_key_b64="public"),
            E2eePreKey(device_id=device.id, key_id="used", public_key_b64="public",
                       consumed_at=used, consumed_by_user_id=user_id),
            E2eeDeviceChallenge(user_id=user_id, challenge_hash="a" * 64,
                                expires_at=now + timedelta(minutes=10)),
            WebAuthnChallenge(user_id=user_id, purpose="authenticate", challenge="public",
                              expires_at=now + timedelta(minutes=10)),
            MfaRecoveryCode(user_id=user_id, code_hash="unused-hash"),
            AccountRecoveryCode(user_id=user_id, purpose="password_reset", code_hash="b" * 64,
                                 expires_at=now + timedelta(minutes=10)),
        ])
        db.commit()
        audit_before = [(row.id, row.entry_hash) for row in db.scalars(select(AuditEvent))]
        result = quarantine(db)
    assert result["users_quarantined"] == 2
    assert result["sessions_revoked"] >= 1
    assert result["e2ee_prekeys_retired"] == 2
    assert result["challenges_removed"] == 2
    with app.state.database.session_factory() as db:
        restored = db.get(User, user_id)
        assert not restored.is_active
        assert old_version < restored.token_version <= MAX_TOKEN_VERSION
        assert restored.mfa_last_counter >= int(time.time()) // 30 + 1
        assert all(row.revoked_at is not None and row.last_step_up_at is None
                   for row in db.scalars(select(AuthSession)))
        assert all(row.used_at is not None for row in db.scalars(select(MfaRecoveryCode)))
        assert all(row.consumed_at is not None for row in db.scalars(select(AccountRecoveryCode)))
        keys = {row.key_id: row for row in db.scalars(select(E2eePreKey))}
        assert all(row.consumed_at is not None for row in keys.values())
        assert keys["used"].consumed_at.replace(tzinfo=timezone.utc) == used
        assert keys["used"].consumed_by_user_id == user_id
        assert [(row.id, row.entry_hash) for row in db.scalars(select(AuditEvent))] == audit_before
        assert activate_reviewed_users(db, ["reviewed.restore"]) == {"reviewed_users_activated": 1}
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/auth/me", headers=headers).status_code == 401
    with app.state.database.session_factory() as db:
        assert db.get(User, user_id).is_active
        assert not db.scalar(select(User).where(User.username == "unreviewed.restore")).is_active
    assert client.post("/api/auth/login", json={"username": "reviewed.restore",
                                               "password": "Correct Horse Battery1"}).status_code == 200


def test_quarantine_failure_rolls_back_all_changes(client, app):
    register_and_login(client, "restore.atomic")
    with app.state.database.session_factory() as db:
        original = db.scalar(select(User).where(User.username == "restore.atomic"))
        user_id, version = original.id, original.token_version

    def unavailable(_conn, _cursor, statement, *_args):
        if statement.lower().lstrip().startswith("update auth_sessions"):
            raise OperationalError("isolated restore fault", None, RuntimeError("fault"))

    event.listen(app.state.database.engine, "before_cursor_execute", unavailable)
    try:
        with app.state.database.session_factory() as db, pytest.raises(OperationalError):
            quarantine(db)
    finally:
        event.remove(app.state.database.engine, "before_cursor_execute", unavailable)
    with app.state.database.session_factory() as db:
        assert db.get(User, user_id).is_active
        assert db.get(User, user_id).token_version == version
        assert all(row.revoked_at is None for row in db.scalars(select(AuthSession)))


@pytest.mark.parametrize("names", [[], ["restore.checked", "restore.checked"],
                                     ["restore.checked", "missing.user"]])
def test_review_activation_is_explicit_and_atomic(client, app, names):
    register_and_login(client, "restore.checked")
    with app.state.database.session_factory() as db:
        quarantine(db)
        with pytest.raises(ValueError):
            activate_reviewed_users(db, names)
    with app.state.database.session_factory() as db:
        assert not db.scalar(select(User).where(User.username == "restore.checked")).is_active


def test_quarantine_refuses_token_version_overflow(client, app):
    register_and_login(client, "restore.version")
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "restore.version"))
        user.token_version = MAX_TOKEN_VERSION
        db.commit()
        with pytest.raises(ValueError, match="safely be advanced"):
            quarantine(db)
    with app.state.database.session_factory() as db:
        assert db.scalar(select(User).where(User.username == "restore.version")).is_active
