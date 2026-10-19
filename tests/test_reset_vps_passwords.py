"""One private password for existing VPS accounts: unlocked, signed out and audited."""

from __future__ import annotations

import base64
from dataclasses import replace
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from scripts import reset_vps_passwords as reset
from src.app.audit_chain import derive_audit_key, verify_chain
from src.app.config import Settings
from src.app.db import Database, utcnow
from src.app.demo_seed import DEMO_PASSPHRASE
from src.app.models import AuditEvent, AuthSession, User
from src.app.security import PasswordService

OLD_PASSWORD = "Lantern Harbour Copper Morning 5813"
NEW_PASSWORD = "Granite Orchard Velvet Comet 2741"


@pytest.fixture
def vps_settings(tmp_path):
    return Settings(
        environment="production",
        security_profile="standard",
        database_url=f"sqlite:///{tmp_path / 'vps.db'}",
        secret_key="vps-password-reset-test-key-only-01",
        master_encryption_key=base64.urlsafe_b64encode(b"V" * 32).decode("ascii"),
        password_breach_check=False,
        audit_chain_enabled=True,
    )


@pytest.fixture
def database(vps_settings):
    isolated = Database(vps_settings.database_url)
    isolated.create_all()
    old_hash = PasswordService().hash(OLD_PASSWORD)
    now = utcnow()
    with isolated.session_factory() as db, db.begin():
        for username, role in (("demo.boss", "admin"), ("demo.user", "user"), ("operator", "admin")):
            user = User(username=username, password_hash=old_hash, role=role,
                        failed_login_attempts=5, locked_until=now + timedelta(minutes=15))
            db.add(user)
            db.flush()
            db.add(AuthSession(jti=f"jti-{username}", user_id=user.id,
                               session_family_id=f"jti-{username}",
                               expires_at=now + timedelta(minutes=30)))
    try:
        yield isolated
    finally:
        isolated.engine.dispose()


@pytest.fixture
def events(monkeypatch):
    emitted = []
    monkeypatch.setattr(reset, "emit_security_event", lambda *a, **k: emitted.append((a, k)))
    return emitted


def _users(database):
    with database.session_factory() as db:
        return {user.username: user for user in db.scalars(select(User))}


def test_demo_accounts_get_the_new_password_unlocked_and_signed_out(vps_settings, database, events):
    before = _users(database)
    changed = reset.reset_vps_passwords(vps_settings, database, password=NEW_PASSWORD)
    assert changed == ["demo.boss", "demo.user"]
    users = _users(database)
    passwords = PasswordService()
    for name in changed:
        user = users[name]
        assert passwords.verify(user.password_hash, NEW_PASSWORD)
        assert not passwords.verify(user.password_hash, OLD_PASSWORD)
        assert (user.failed_login_attempts, user.locked_until) == (0, None)
        assert user.token_version == before[name].token_version + 1
    # Without --all-users, accounts outside the project's demo set are untouched.
    operator = users["operator"]
    assert operator.password_hash == before["operator"].password_hash
    assert operator.failed_login_attempts == 5
    with database.session_factory() as db:
        revoked = {jti for jti, at in db.execute(select(AuthSession.jti, AuthSession.revoked_at))
                   if at is not None}
        assert revoked == {"jti-demo.boss", "jti-demo.user"}
        audit = list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))
        assert [(event.event_type, event.target_id) for event in audit] == [
            ("admin.password_reset", users[name].id) for name in sorted(
                changed, key=lambda name: users[name].id)
        ]
        assert verify_chain(db, derive_audit_key(vps_settings.secret_key)).intact
    assert len(events) == 2
    output = repr(([event.details_json for event in audit], events))
    assert NEW_PASSWORD not in output and OLD_PASSWORD not in output


def test_all_users_includes_every_account(vps_settings, database, events):
    changed = reset.reset_vps_passwords(vps_settings, database, password=NEW_PASSWORD, all_users=True)
    assert changed == ["demo.boss", "demo.user", "operator"]
    assert PasswordService().verify(_users(database)["operator"].password_hash, NEW_PASSWORD)
    assert reset.target_usernames(database, all_users=True) == changed


@pytest.mark.parametrize("password,reason", [
    (DEMO_PASSPHRASE, "public demo password"),
    ("short", "15 to 128"),
    ("Granite Orchard Velvet Cómet 2741", "Vietnamese input method"),
    ("Granite Orchard Velvet Co\udcc3met 2741", "Vietnamese input method"),
])
def test_public_weak_or_garbled_password_changes_nothing(vps_settings, database, events, password, reason):
    before = {name: user.password_hash for name, user in _users(database).items()}
    with pytest.raises(reset.AdminProvisioningError, match=reason):
        reset.reset_vps_passwords(vps_settings, database, password=password, all_users=True)
    assert {name: user.password_hash for name, user in _users(database).items()} == before
    with database.session_factory() as db:
        assert db.scalar(select(func.count(AuditEvent.id))) == 0
    assert events == []


def test_no_matching_accounts_is_a_no_op(vps_settings, tmp_path, events):
    empty = Database(f"sqlite:///{tmp_path / 'empty.db'}")
    empty.create_all()
    try:
        assert reset.reset_vps_passwords(vps_settings, empty, password=NEW_PASSWORD) == []
        with empty.session_factory() as db:
            assert db.scalar(select(func.count(AuditEvent.id))) == 0
    finally:
        empty.engine.dispose()
    assert events == []


def test_requires_standard_production_profile(vps_settings, database, events):
    with pytest.raises(reset.AdminProvisioningError, match="standard production"):
        reset.reset_vps_passwords(replace(vps_settings, environment="development"), database,
                                  password=NEW_PASSWORD)
    high = replace(vps_settings, security_profile="high",
                   audit_worm_endpoint="https://worm.example.test/checkpoints")
    with pytest.raises(reset.AdminProvisioningError, match="standard production"):
        reset.reset_vps_passwords(high, database, password=NEW_PASSWORD)
    assert PasswordService().verify(_users(database)["demo.boss"].password_hash, OLD_PASSWORD)


def test_cli_refuses_piped_passwords(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert reset.main([]) == 1
    assert "interactive terminal" in capsys.readouterr().err


def test_cli_never_echoes_a_password_argument(capsys):
    with pytest.raises(SystemExit):
        reset.main(["--password", NEW_PASSWORD])
    captured = capsys.readouterr()
    assert NEW_PASSWORD not in captured.out + captured.err
