from __future__ import annotations

import json
import os
import sqlite3
import warnings
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

from scripts import secure_backup as backup
from src.app.audit_chain import derive_audit_key, seal_event, verify_chain
from src.app.db import Database
from src.app.main import create_app
from src.app.models import (
    AccountRecoveryCode,
    AuditEvent,
    AuthSession,
    ChatSession,
    E2eeDevice,
    E2eeDeviceChallenge,
    E2eePreKey,
    MfaRecoveryCode,
    SessionKeyEpoch,
    User,
    WebAuthnChallenge,
)
from src.app.security import TokenService

_PASSWORD = "Synthetic backup passphrase 2026!"
_AUDIT_SECRET = "Synthetic-audit-key-never-in-the-archive"


@pytest.fixture()
def sample_database(tmp_path):
    path = tmp_path / "source.db"
    database = Database(f"sqlite:///{path.as_posix()}")
    database.create_all()
    now = datetime.now(timezone.utc)
    with database.session_factory() as session:
        user = User(id="user-a", username="reviewed-admin", password_hash="synthetic-hash",
                    role="admin", token_version=7)
        disabled = User(id="user-b", username="disabled-user", password_hash="synthetic-hash",
                        is_active=False, token_version=9)
        session.add_all([user, disabled])
        session.flush()
        device = E2eeDevice(id="device-a", user_id=user.id, display_name="synthetic-device",
                            identity_key_b64="synthetic-public-identity",
                            signed_prekey_b64="synthetic-public-prekey",
                            signed_prekey_signature_b64="synthetic-signature",
                            fingerprint="synthetic-fingerprint", trust_state="trusted")
        session.add(device)
        session.flush()
        session.add_all([
            E2eePreKey(device_id=device.id, key_id="available", public_key_b64="synthetic-public-unused"),
            E2eePreKey(device_id=device.id, key_id="consumed", public_key_b64="synthetic-public-consumed",
                       consumed_at=now, consumed_by_user_id=user.id),
            AuthSession(jti="live-token", user_id=user.id, session_family_id="live-family",
                        expires_at=now + timedelta(hours=1), last_step_up_at=now),
            AuthSession(jti="already-revoked", user_id=user.id, session_family_id="old-family",
                        expires_at=now + timedelta(hours=1), revoked_at=now),
            MfaRecoveryCode(user_id=user.id, code_hash="synthetic-hash"),
            AccountRecoveryCode(user_id=user.id, purpose="password_reset", code_hash="a" * 64,
                                expires_at=now + timedelta(minutes=10)),
            WebAuthnChallenge(user_id=user.id, purpose="authenticate", challenge="synthetic",
                              expires_at=now + timedelta(minutes=5)),
            E2eeDeviceChallenge(user_id=user.id, challenge_hash="b" * 64,
                                expires_at=now + timedelta(minutes=5)),
        ])
        chat = ChatSession(id="chat-a", owner_id=user.id, current_crypto_epoch=2,
                           wrapped_dek="synthetic-wrapped-dek-2", kek_uri="local://synthetic",
                           kek_version="2", crypto_suite="AES-256-GCM")
        session.add(chat)
        session.flush()
        for epoch in (1, 2):
            session.add(SessionKeyEpoch(session_id=chat.id, epoch=epoch,
                                       wrapped_dek=f"synthetic-wrapped-dek-{epoch}",
                                       kek_uri="local://synthetic", kek_version=str(epoch)))
        event = AuditEvent(actor_id=user.id, event_type="synthetic.backup", outcome="success")
        seal_event(session, event, derive_audit_key(_AUDIT_SECRET))
        session.commit()
    database.engine.dispose()
    return path


@pytest.fixture()
def archive(sample_database, tmp_path):
    result = tmp_path / "backup.scapbak"
    report = backup.backup_database(sample_database, result, _PASSWORD)
    assert report["status"] == "backed_up" and report["keys_exported"] is False
    return result


def _rows(path: Path, sql: str):
    with closing(sqlite3.connect(path)) as connection:
        return connection.execute(sql).fetchall()


def _temporary_files(parent: Path):
    return list(parent.glob("scap-backup-*")) + list(parent.glob("scap-restore-*"))


def test_authenticated_roundtrip_quarantines_accounts_preserves_audit_and_wrapped_keys(
    sample_database, archive, tmp_path,
):
    output = tmp_path / "restored.db"
    original_audit = _rows(sample_database, "SELECT * FROM audit_events")
    original_epochs = _rows(sample_database, "SELECT * FROM session_key_epochs ORDER BY epoch")
    original_chats = _rows(sample_database, "SELECT * FROM chat_sessions")
    report = backup.restore_database(archive, output, _PASSWORD)
    assert report["status"] == "restored_offline"
    assert report["requires_account_revocation_review"] is True
    assert report["users_quarantined"] == 2 and report["reviewed_users_activated"] == 0
    assert report["sessions_revoked"] == 2
    assert report["mfa_recovery_codes_consumed"] == report["account_recovery_codes_consumed"] == 1
    assert report["challenges_removed"] == 2
    assert report["e2ee_prekeys_retired"] == 2
    assert _rows(output, "SELECT is_active FROM users") == [(0,), (0,)]
    versions = dict(_rows(output, "SELECT username, token_version FROM users"))
    assert 7 < versions["reviewed-admin"] <= (1 << 63) - 1
    assert 9 < versions["disabled-user"] <= (1 << 63) - 1
    assert all(row[0] is not None and row[1] is None for row in _rows(
        output, "SELECT revoked_at, last_step_up_at FROM auth_sessions",
    ))
    assert _rows(output, "SELECT used_at IS NOT NULL FROM mfa_recovery_codes") == [(1,)]
    assert _rows(output, "SELECT consumed_at IS NOT NULL FROM account_recovery_codes") == [(1,)]
    assert _rows(output, "SELECT * FROM webauthn_challenges") == []
    assert _rows(output, "SELECT * FROM e2ee_device_challenges") == []
    assert _rows(output, "SELECT * FROM audit_events") == original_audit
    assert _rows(output, "SELECT * FROM session_key_epochs ORDER BY epoch") == original_epochs
    assert _rows(output, "SELECT * FROM chat_sessions") == original_chats
    restored = Database(f"sqlite:///{output.as_posix()}")
    with restored.session_factory() as session:
        assert verify_chain(session, derive_audit_key(_AUDIT_SECRET)).intact
    restored.engine.dispose()
    assert not _temporary_files(tmp_path)
    assert _PASSWORD.encode() not in archive.read_bytes()
    assert b"reviewed-admin" not in archive.read_bytes()
    assert _AUDIT_SECRET.encode() not in archive.read_bytes()


def test_explicit_reviewed_account_activation_does_not_activate_other_accounts(archive, tmp_path):
    output = tmp_path / "reviewed.db"
    result = backup.restore_database(archive, output, _PASSWORD, reviewed_users=("reviewed-admin",))
    assert result["users_quarantined"] == result["reviewed_users_activated"] == 1
    assert dict(_rows(output, "SELECT username, is_active FROM users")) == {
        "reviewed-admin": 1, "disabled-user": 0,
    }


def test_restore_retires_one_time_prekeys_without_rewriting_previously_consumed_metadata(
    sample_database, archive, tmp_path,
):
    original = dict(_rows(sample_database, "SELECT key_id, consumed_at FROM e2ee_prekeys"))
    assert original["available"] is None and original["consumed"] is not None
    # This archived available key may already have been consumed on the live
    # device after the snapshot. Explicit account activation must not revive it.
    restored = tmp_path / "retired-prekeys.db"
    report = backup.restore_database(archive, restored, _PASSWORD, reviewed_users=("reviewed-admin",))
    assert report["e2ee_prekeys_retired"] == 2
    assert _rows(restored, "SELECT count(*) FROM e2ee_prekeys WHERE consumed_at IS NULL") == [(0,)]
    assert dict(_rows(restored, "SELECT key_id, consumed_at FROM e2ee_prekeys"))["consumed"] == original["consumed"]
    assert _rows(restored, "SELECT consumed_by_user_id FROM e2ee_prekeys WHERE key_id='consumed'") == [("user-a",)]


@pytest.mark.parametrize("names", [("missing",), ("reviewed-admin", "reviewed-admin"), ("",)])
def test_invalid_reviewed_account_fails_without_publishing(archive, tmp_path, names):
    output = tmp_path / "invalid-review.db"
    with pytest.raises(backup.BackupError):
        backup.restore_database(archive, output, _PASSWORD, reviewed_users=names)
    assert not output.exists() and not _temporary_files(tmp_path)


def test_online_snapshot_includes_uncheckpointed_wal(sample_database, tmp_path):
    output = tmp_path / "wal.scapbak"
    restored = tmp_path / "wal-restored.db"
    with closing(sqlite3.connect(sample_database)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE synthetic_marker(value TEXT)")
        writer.execute("INSERT INTO synthetic_marker VALUES ('committed-in-wal')")
        writer.commit()
        with closing(sqlite3.connect(sample_database.as_uri() + "?immutable=1", uri=True)) as old:
            assert old.execute("SELECT count(*) FROM sqlite_schema WHERE name='synthetic_marker'").fetchone() == (0,)
        backup.backup_database(sample_database, output, _PASSWORD)
        backup.restore_database(output, restored, _PASSWORD)
        assert _rows(restored, "SELECT * FROM synthetic_marker") == [("committed-in-wal",)]


@pytest.mark.parametrize("operation", ["backup", "restore"])
def test_existing_output_is_never_overwritten(operation, sample_database, archive, tmp_path):
    output = tmp_path / "existing.db"
    sentinel = b"operator-owned existing content"
    output.write_bytes(sentinel)
    with pytest.raises(backup.BackupError, match="Output must be a new file"):
        if operation == "backup":
            backup.backup_database(sample_database, output, _PASSWORD)
        else:
            backup.restore_database(archive, output, _PASSWORD)
    assert output.read_bytes() == sentinel and not _temporary_files(tmp_path)


def test_atomic_publication_refuses_output_created_during_backup(sample_database, tmp_path, monkeypatch):
    output = tmp_path / "race.scapbak"
    original_link = os.link

    def race(source, destination):
        Path(destination).write_bytes(b"concurrent operator file")
        return original_link(source, destination)

    monkeypatch.setattr(backup.os, "link", race)
    with pytest.raises(backup.BackupError, match="Output must be a new file"):
        backup.backup_database(sample_database, output, _PASSWORD)
    assert output.read_bytes() == b"concurrent operator file" and not _temporary_files(tmp_path)


def test_unsupported_publication_filesystem_fails_closed(sample_database, tmp_path, monkeypatch):
    def unavailable(*_args):
        raise OSError("Synthetic filesystem lacks hardlinks")

    monkeypatch.setattr(backup.os, "link", unavailable)
    output = tmp_path / "unsupported.scapbak"
    with pytest.raises(OSError):
        backup.backup_database(sample_database, output, _PASSWORD)
    assert not output.exists() and not _temporary_files(tmp_path)


@pytest.mark.parametrize("target_kind", ["input", "output", "parent"])
def test_symlink_paths_are_rejected(sample_database, tmp_path, target_kind):
    linked = tmp_path / "linked"
    target = tmp_path if target_kind == "parent" else sample_database
    try:
        linked.symlink_to(target, target_is_directory=target_kind == "parent")
    except OSError:
        pytest.skip("This Windows account cannot create symbolic links")
    source = linked if target_kind == "input" else sample_database
    output = linked / "new.scapbak" if target_kind == "parent" else linked if target_kind == "output" else tmp_path / "new.scapbak"
    with pytest.raises(backup.BackupError, match="Linked paths"):
        backup.backup_database(source, output, _PASSWORD)
    assert sample_database.exists() and not _temporary_files(tmp_path)


@pytest.mark.parametrize("field,value", [(1, 2), (2, 4_000_000_000), (3, 4_000_000_000), (4, 9999), (6, backup.MAX_DATABASE_BYTES + 1)])
def test_untrusted_header_is_rejected_before_kdf(archive, tmp_path, monkeypatch, field, value):
    payload = bytearray(archive.read_bytes())
    header = list(backup._HEADER.unpack(payload[:backup._HEADER.size]))
    header[field] = value
    payload[:backup._HEADER.size] = backup._HEADER.pack(*header)
    malformed = tmp_path / "invalid-header.scapbak"
    malformed.write_bytes(payload)

    def must_not_derive(*_args):
        pytest.fail("KDF must not run for an untrusted oversized/unsupported header")

    monkeypatch.setattr(backup, "_derive_key", must_not_derive)
    with pytest.raises(backup.BackupError, match="unsupported header"):
        backup.restore_database(malformed, tmp_path / "must-not-exist.db", _PASSWORD)


def test_oversized_archive_rejected_before_kdf(tmp_path, monkeypatch):
    oversized = tmp_path / "oversized.scapbak"
    with oversized.open("wb") as target:
        target.truncate(backup.MAX_DATABASE_BYTES + backup._HEADER.size + 17)
    monkeypatch.setattr(backup, "_derive_key", lambda *_: pytest.fail("KDF called on oversized input"))
    with pytest.raises(backup.BackupError, match="invalid size"):
        backup.restore_database(oversized, tmp_path / "oversized.db", _PASSWORD)


@pytest.mark.parametrize("change", ["ciphertext", "nonce", "salt", "created", "truncate", "append"])
def test_tampered_archive_never_publishes_plaintext(archive, tmp_path, change):
    payload = bytearray(archive.read_bytes())
    if change == "truncate":
        del payload[-10:]
    elif change == "append":
        payload.extend(b"injected")
    elif change == "ciphertext":
        payload[-1] ^= 1
    else:
        header = list(backup._HEADER.unpack(payload[:backup._HEADER.size]))
        if change == "created":
            header[5] += 1
        else:
            index = 8 if change == "nonce" else 7
            modified = bytearray(header[index])
            modified[-1] ^= 1
            header[index] = bytes(modified)
        payload[:backup._HEADER.size] = backup._HEADER.pack(*header)
    modified_archive = tmp_path / "tampered.scapbak"
    modified_archive.write_bytes(payload)
    output = tmp_path / "tampered.db"
    with pytest.raises(backup.BackupError):
        backup.restore_database(modified_archive, output, _PASSWORD)
    assert not output.exists() and not _temporary_files(tmp_path)


def test_wrong_passphrase_does_not_publish_or_echo_password(archive, tmp_path):
    wrong = "Another synthetic backup passphrase!"
    with pytest.raises(backup.BackupError, match="authentication failed") as captured:
        backup.restore_database(archive, tmp_path / "wrong.db", wrong)
    assert wrong not in str(captured.value) and _PASSWORD not in str(captured.value)
    assert not _temporary_files(tmp_path)


def test_non_sqlite_authenticated_payload_is_rejected(tmp_path):
    payload = b"Authenticated but not a SQLite database"
    salt, nonce = b"s" * 16, b"n" * 12
    header = backup._HEADER.pack(backup._MAGIC, 1, 3, 65536, 1, 1, len(payload), salt, nonce)
    archive = tmp_path / "not-sqlite.scapbak"
    archive.write_bytes(header + AESGCM(backup._derive_key(_PASSWORD, salt)).encrypt(nonce, payload, header))
    with pytest.raises(backup.BackupError, match="not a SQLite database"):
        backup.restore_database(archive, tmp_path / "invalid.db", _PASSWORD)


def test_non_scap_schema_is_rejected_before_archive_publication(tmp_path):
    source = tmp_path / "other.db"
    with closing(sqlite3.connect(source)) as connection:
        connection.execute("CREATE TABLE unrelated(value TEXT)")
    with pytest.raises(backup.BackupError, match="supported SCAP schema"):
        backup.backup_database(source, tmp_path / "other.scapbak", _PASSWORD)
    assert not (tmp_path / "other.scapbak").exists() and not _temporary_files(tmp_path)


def test_trigger_that_could_undo_quarantine_is_rejected(sample_database, tmp_path):
    with closing(sqlite3.connect(sample_database)) as connection:
        connection.execute("CREATE TRIGGER reenable AFTER UPDATE ON users BEGIN UPDATE users SET is_active=1; END")
    with pytest.raises(backup.BackupError, match="unsupported triggers"):
        backup.backup_database(sample_database, tmp_path / "trigger.scapbak", _PASSWORD)


def test_snapshot_size_and_deadline_are_bounded(sample_database, tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "MAX_DATABASE_BYTES", 1)
    with pytest.raises(backup.BackupError, match="64 MiB"):
        backup.backup_database(sample_database, tmp_path / "large.scapbak", _PASSWORD)
    monkeypatch.setattr(backup, "MAX_DATABASE_BYTES", 64 * 1024 * 1024)
    calls = iter((0.0, 31.0))
    monkeypatch.setattr(backup.time, "monotonic", lambda: next(calls, 31.0))
    with pytest.raises(backup.BackupError, match="30-second deadline"):
        backup.backup_database(sample_database, tmp_path / "slow.scapbak", _PASSWORD)
    assert not _temporary_files(tmp_path)


def test_cancellation_cleans_private_plaintext_snapshot(sample_database, tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "_derive_key", lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        backup.backup_database(sample_database, tmp_path / "cancelled.scapbak", _PASSWORD)
    assert not _temporary_files(tmp_path) and not (tmp_path / "cancelled.scapbak").exists()


@pytest.mark.parametrize("passphrase", ["", "short", "a" * 1025])
def test_passphrase_input_is_bounded(passphrase):
    with pytest.raises(backup.BackupError, match="16-1024"):
        backup._passphrase_bytes(passphrase)


def test_cli_getpass_confirmation_and_secret_free_result(sample_database, tmp_path, monkeypatch, capsys):
    prompts = []

    def getpass(prompt):
        prompts.append(prompt)
        return _PASSWORD

    monkeypatch.setattr(backup.getpass, "getpass", getpass)
    assert backup.main(["backup", "--database", str(sample_database), "--output", str(tmp_path / "cli.scapbak")]) == 0
    result = capsys.readouterr()
    assert json.loads(result.out)["status"] == "backed_up" and len(prompts) == 2
    assert _PASSWORD not in result.out + result.err and "reviewed-admin" not in result.out


def test_cli_restore_activates_only_explicitly_reviewed_account(archive, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(backup.getpass, "getpass", lambda _: _PASSWORD)
    output = tmp_path / "cli-restored.db"
    assert backup.main(["restore", "--archive", str(archive), "--output", str(output),
                        "--activate-reviewed-user", "reviewed-admin"]) == 0
    result = capsys.readouterr()
    assert json.loads(result.out)["reviewed_users_activated"] == 1
    assert "offline" in result.err and "reviewed-admin" not in result.out + result.err


def test_cli_refuses_echoed_getpass_fallback(monkeypatch, capsys, tmp_path):
    def echoed(_):
        warnings.warn("Synthetic hidden-input unavailable", backup.getpass.GetPassWarning, stacklevel=2)
        return _PASSWORD

    monkeypatch.setattr(backup.getpass, "getpass", echoed)
    assert backup.main(["backup", "--database", str(tmp_path / "missing.db"),
                        "--output", str(tmp_path / "new.scapbak")]) == 1
    assert "hidden password input" in capsys.readouterr().err


def test_cli_does_not_accept_passphrases_as_arguments(tmp_path, capsys):
    with pytest.raises(SystemExit) as captured:
        backup.main(["backup", "--database", str(tmp_path / "input.db"),
                     "--output", str(tmp_path / "output.scapbak"), "--passphrase", _PASSWORD])
    assert captured.value.code == 2
    assert _PASSWORD not in capsys.readouterr().err


def test_restored_live_bearer_refresh_and_mfa_challenge_fail_even_for_reviewed_account(
    client, settings, tmp_path,
):
    password = "Synthetic account password 2026!"
    assert client.post("/api/auth/register", json={"username": "reviewed.user", "password": password}).status_code == 201
    login = client.post("/api/auth/login", json={"username": "reviewed.user", "password": password})
    token = login.json()["access_token"]
    token_service = TokenService(settings.secret_key)
    claims = token_service.decode(token)
    pending_mfa = token_service.issue_mfa_challenge(claims["sub"], claims["ver"])
    source = Path(settings.database_url.removeprefix("sqlite:///"))
    encrypted = tmp_path / "live.scapbak"
    recovered = tmp_path / "live-restored.db"
    backup.backup_database(source, encrypted, _PASSWORD)
    backup.restore_database(encrypted, recovered, _PASSWORD, reviewed_users=("reviewed.user",))
    restored_app = create_app(replace(settings, database_url=f"sqlite:///{recovered.as_posix()}"))
    try:
        with TestClient(restored_app) as restored:
            headers = {"Authorization": f"Bearer {token}"}
            assert restored.get("/api/auth/me", headers=headers).status_code == 401
            assert restored.post("/api/auth/refresh", headers=headers).status_code == 401
            assert restored.post("/api/auth/mfa/verify", json={"mfa_token": pending_mfa, "code": "123456"}).status_code == 401
            assert restored.post("/api/auth/login", json={"username": "reviewed.user", "password": password}).status_code == 200
    finally:
        restored_app.state.database.engine.dispose()
