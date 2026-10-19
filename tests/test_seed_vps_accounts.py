"""Familiar demo accounts on a production VPS use a private password, never the public one."""

from __future__ import annotations

import base64
from dataclasses import replace

import pytest
from sqlalchemy import func, select

from scripts import seed_vps_accounts as seed
from src.app.audit_chain import derive_audit_key, verify_chain
from src.app.config import Settings
from src.app.db import Database
from src.app.demo_seed import ALL_DEMO_USERS, DEMO_PASSPHRASE
from src.app.models import AuditEvent, ChatSession, SecureMessage, User
from src.app.security import CryptoService, PasswordService

PASSWORD = "Lantern Harbour Copper Morning 5813"


@pytest.fixture
def vps_settings(tmp_path):
    return Settings(
        environment="production",
        security_profile="standard",
        database_url=f"sqlite:///{tmp_path / 'vps.db'}",
        secret_key="vps-demo-accounts-test-key-only-0001",
        master_encryption_key=base64.urlsafe_b64encode(b"V" * 32).decode("ascii"),
        password_breach_check=False,
        audit_chain_enabled=True,
    )


@pytest.fixture
def database(vps_settings):
    isolated = Database(vps_settings.database_url)
    isolated.create_all()
    try:
        yield isolated
    finally:
        isolated.engine.dispose()


@pytest.fixture
def events(monkeypatch):
    emitted = []
    monkeypatch.setattr(seed, "emit_security_event", lambda *a, **k: emitted.append((a, k)))
    return emitted


def test_creates_familiar_accounts_with_private_password(vps_settings, database, events):
    logs = []
    created = seed.seed_vps_accounts(vps_settings, database, password=PASSWORD, log=logs.append)
    assert created == [username for username, _ in ALL_DEMO_USERS]
    crypto = CryptoService(vps_settings.master_encryption_key)
    with database.session_factory() as db:
        users = {user.username: user for user in db.scalars(select(User))}
        assert {name: user.role for name, user in users.items()} == dict(ALL_DEMO_USERS)
        boss = users["demo.boss"]
        assert PasswordService().verify(boss.password_hash, PASSWORD)
        assert not PasswordService().verify(boss.password_hash, DEMO_PASSPHRASE)
        message = db.scalar(select(SecureMessage).join(ChatSession)
                            .where(ChatSession.owner_id == users["demo.user"].id).limit(1))
        assert crypto.decrypt(message.ciphertext, message.nonce, message.session_id,
                              message.role, message.key_version)
        # Only the provisioning record: no synthetic failures that could lock accounts.
        audit = list(db.scalars(select(AuditEvent)))
        assert [event.event_type for event in audit] == ["admin.demo_accounts_create"]
        assert verify_chain(db, derive_audit_key(vps_settings.secret_key)).intact
    output = repr((audit[0].details_json, logs, events))
    assert PASSWORD not in output and DEMO_PASSPHRASE not in output


@pytest.mark.parametrize("password,reason", [
    (DEMO_PASSPHRASE, "public demo password"),
    ("short", "15 to 128"),
])
def test_public_or_weak_password_creates_nothing(vps_settings, database, events, password, reason):
    with pytest.raises(seed.AdminProvisioningError, match=reason):
        seed.seed_vps_accounts(vps_settings, database, password=password)
    with database.session_factory() as db:
        assert db.scalar(select(func.count(User.id))) == 0
        assert db.scalar(select(func.count(AuditEvent.id))) == 0
    assert events == []


def test_existing_accounts_keep_their_password_and_rerun_is_a_no_op(vps_settings, database, events):
    with database.session_factory() as db, db.begin():
        db.add(User(username="demo.user", password_hash="kept-hash", role="user"))
    created = seed.seed_vps_accounts(vps_settings, database, password=PASSWORD, log=lambda *_: None)
    assert "demo.user" not in created and len(created) == len(ALL_DEMO_USERS) - 1
    assert seed.seed_vps_accounts(vps_settings, database, password=PASSWORD, log=lambda *_: None) == []
    with database.session_factory() as db:
        assert db.scalar(select(User.password_hash).where(User.username == "demo.user")) == "kept-hash"
        assert db.scalar(select(func.count(AuditEvent.id))) == 1
    assert len(events) == 1


def test_sample_alerts_are_opt_in_and_keep_the_chain_intact(vps_settings, database, events):
    seed.seed_vps_accounts(vps_settings, database, password=PASSWORD,
                           sample_alerts=True, log=lambda *_: None)
    with database.session_factory() as db:
        assert db.scalar(select(func.count(AuditEvent.id)).where(AuditEvent.request_id.like("seed-%"))) > 0
        assert verify_chain(db, derive_audit_key(vps_settings.secret_key)).intact


def test_requires_standard_production_profile(vps_settings, database, events):
    with pytest.raises(seed.AdminProvisioningError, match="standard production"):
        seed.seed_vps_accounts(replace(vps_settings, environment="development"), database, password=PASSWORD)


def test_never_seeds_demo_accounts_into_a_high_security_deployment(vps_settings, database, events):
    # create_admin accepts a fully configured high profile; this shared check must not.
    high = replace(vps_settings, security_profile="high",
                   audit_worm_endpoint="https://worm.example.test/checkpoints")
    with pytest.raises(seed.AdminProvisioningError, match="standard production"):
        seed.seed_vps_accounts(high, database, password=PASSWORD)
    with database.session_factory() as db:
        assert db.scalar(select(func.count(User.id))) == 0


def test_cli_refuses_piped_passwords(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert seed.main([]) == 1
    assert "interactive terminal" in capsys.readouterr().err
