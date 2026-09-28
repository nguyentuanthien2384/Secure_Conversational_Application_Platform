from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from scripts.seed_learning_data import LEARN_PASSPHRASE, seed_learning_data
from src.app.audit_chain import derive_audit_key, verify_chain
from src.app.config import Settings
from src.app.db import Database, utcnow
from src.app.demo_seed import seed_demo_data
from src.app.ids import detect_anomalies
from src.app.main import create_app
from src.app.models import AuditEvent, AuthSession, ChatSession, SecureMessage, User
from src.app.security import CryptoService, PasswordService


@pytest.fixture
def database(settings):
    database = Database(settings.database_url)
    yield database
    database.engine.dispose()


def _counts(db):
    return tuple(db.scalar(select(func.count()).select_from(model)) for model in (
        User, ChatSession, SecureMessage, AuditEvent, AuthSession,
    ))


def _assert_correlations(db, username):
    user_id = db.scalar(select(User.id).where(User.username == username))
    findings = {item.code: item for item in detect_anomalies(db) if item.subject == user_id}
    assert findings["IDS-DISTRIBUTED-BRUTEFORCE"].source_count == 3
    assert findings["IDS-AUTH-SUCCESS-AFTER-FAILURES"].count == 6
    evidence_id = findings["IDS-AUTH-SUCCESS-AFTER-FAILURES"].evidence_event_id
    evidence = db.get(AuditEvent, evidence_id)
    assert evidence.outcome == "success"
    assert json.loads(evidence.details_json)["synthetic"] is True


def test_standard_demo_seed_is_idempotent_sealed_and_has_recent_correlations(
    settings, database, monkeypatch,
):
    def no_env():
        raise AssertionError("Explicit audit key must avoid reading .env")

    monkeypatch.setattr(Settings, "from_env", no_env)
    key = derive_audit_key(settings.secret_key)
    passwords = PasswordService()
    crypto = CryptoService(settings.master_encryption_key)
    seed_args = (database, passwords, crypto)
    seed_demo_data(*seed_args, audit_key=key, log=lambda _: None)
    with database.session_factory() as db:
        initial = _counts(db)
        assert initial == (11, 24, 54, 173, 0)
        chain = verify_chain(db, key)
        assert chain.intact and chain.verified == chain.total == 173
        assert all(json.loads(row.details_json)["synthetic"]
                   for row in db.scalars(select(AuditEvent)))
        _assert_correlations(db, "lab.alice")
        first = db.scalar(select(SecureMessage))
        assert crypto.decrypt(first.ciphertext, first.nonce, first.session_id,
                              first.role, first.key_version)

    seed_demo_data(*seed_args, audit_key=key, log=lambda _: None)
    with database.session_factory() as db:
        assert _counts(db) == initial

    seed_demo_data(*seed_args, audit_key=key, refresh_telemetry=True, log=lambda _: None)
    with database.session_factory() as db:
        assert _counts(db) == (11, 24, 54, 192, 0)
        assert verify_chain(db, key).intact


def test_explicit_none_disables_sealing_without_reading_environment(database, settings, monkeypatch):
    monkeypatch.setattr(Settings, "from_env", lambda: pytest.fail("Unexpected .env read"))
    seed_demo_data(database, PasswordService(), CryptoService(settings.master_encryption_key),
                   audit_key=None, log=lambda _: None)
    with database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(AuditEvent)) == 173
        assert db.scalar(select(AuditEvent.id).where(AuditEvent.entry_hash.is_not(None))) is None


def test_learning_seed_mfa_devices_chain_and_idempotency(settings, database, monkeypatch):
    monkeypatch.setattr(Settings, "from_env", lambda: pytest.fail("Unexpected .env read"))
    info = seed_learning_data(settings, log=lambda _: None)
    assert info is not None
    key = derive_audit_key(settings.secret_key)
    with database.session_factory() as db:
        initial = _counts(db)
        assert initial[:3] == (5, 5, 18)
        assert initial[3] == 89
        assert initial[4] == 3
        chain = verify_chain(db, key)
        assert chain.intact and chain.verified == chain.total == info["sealed"]
        _assert_correlations(db, "learn.user")
        mfa_user = db.scalar(select(User).where(User.username == "learn.mfa"))
        assert mfa_user.mfa_enabled
        crypto = CryptoService(settings.master_encryption_key)
        assert crypto.decrypt_secret(mfa_user.mfa_secret_ciphertext, mfa_user.mfa_secret_nonce,
                                     context=f"mfa:{mfa_user.id}") == info["mfa_secret"]
        devices = list(db.scalars(select(AuthSession).where(AuthSession.revoked_at.is_(None))))
        assert len(devices) == 2
        now = utcnow()
        for device in devices:
            assert device.expires_at.replace(tzinfo=timezone.utc) > now
            assert device.last_activity_at.replace(tzinfo=timezone.utc) + timedelta(
                minutes=settings.session_idle_minutes,
            ) > now
            assert device.root_issued_at.replace(tzinfo=timezone.utc) + timedelta(
                hours=settings.session_absolute_hours,
            ) > now
    assert seed_learning_data(settings, log=lambda _: None) is None
    with database.session_factory() as db:
        assert _counts(db) == initial

    app = create_app(settings)
    with TestClient(app) as client:
        response = client.post("/api/auth/login", json={
            "username": "learn.user", "password": LEARN_PASSPHRASE,
        })
        assert response.status_code == 200
        response = client.get("/api/auth/sessions", headers={
            "Authorization": f"Bearer {response.json()['access_token']}",
        })
        assert response.status_code == 200
        assert len(response.json()) == 3  # two samples plus this actual login
        assert sum(row["is_current"] for row in response.json()) == 1


def test_learning_seed_rejects_production_before_opening_database(settings, monkeypatch):
    monkeypatch.setattr("scripts.seed_learning_data.Database",
                        lambda _: pytest.fail("Production database must not be opened"))
    with pytest.raises(ValueError, match="development"):
        seed_learning_data(replace(settings, environment="production"), log=lambda _: None)
