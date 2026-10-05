"""Exercise an isolated SQLite backup and recovery: python -m scripts.security_recovery_drill.

Only synthetic demo data is used. The database, snapshot and restored application
live in a disposable directory. No destination/database/key option is accepted;
this deliberately cannot serve as a backup command for an existing deployment.
The KEK and JWT signing key stay in this process, separately from the snapshot.
"""

from __future__ import annotations

import base64
import importlib
import io
import json
import secrets
import sqlite3
import tempfile
import time
from contextlib import closing, redirect_stdout
from dataclasses import replace
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select

from scripts.demo_local import demo_application
from src.app.demo_seed import DEMO_PASSPHRASE
from src.app.envelope import ENVELOPE_SCHEME, EnvelopeCryptoService, EnvelopeEncryptionError
from src.app.key_management import LocalAesKeyProvider
from src.app.models import ChatSession, SecureMessage, SessionKeyEpoch, User, uuid4_str

_PORT = 8765  # TestClient never opens a listening socket.
_MESSAGE = "Synthetic recovery drill message."
_ACCOUNT_SECRET = "SYNTHETIC-ACCOUNT-SECRET-FOR-RECOVERY-DRILL"
_MARKER = "latest-committed-wal-state"


class RecoveryDrillError(RuntimeError):
    """A fixed check label, never a response body, token, path or key."""

    def __init__(self, check: str):
        self.check = check
        super().__init__("Recovery drill check failed.")


def _require(checks: list[dict[str, Any]], label: str, passed: bool) -> None:
    checks.append({"name": label, "passed": bool(passed)})
    if not passed:
        raise RecoveryDrillError(label)


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _login(client: TestClient, username: str, checks: list[dict[str, Any]], *, purpose: str) -> str:
    response = client.post(
        "/api/auth/login", json={"username": username, "password": DEMO_PASSPHRASE},
    )
    _require(checks, f"login_{purpose}", response.status_code == 200)
    token = response.json().get("access_token")
    _require(checks, f"token_{purpose}", isinstance(token, str) and bool(token))
    return token


def _key_metadata(database: Any, session_id: str, user_id: str) -> tuple[Any, ...]:
    """Compare complete wrapped-key metadata in memory; never emit its values."""
    with database.session_factory() as db:
        conversation = db.get(ChatSession, session_id)
        user = db.get(User, user_id)
        epochs = list(db.scalars(select(SessionKeyEpoch).where(
            SessionKeyEpoch.session_id == session_id,
        ).order_by(SessionKeyEpoch.epoch)))
        return (
            conversation.current_crypto_epoch, conversation.crypto_suite,
            conversation.wrapped_dek, conversation.kek_uri, conversation.kek_version,
            tuple((row.epoch, row.wrapped_dek, row.kek_uri, row.kek_version, row.crypto_suite)
                  for row in epochs),
            user.secret_wrapped_dek, user.secret_kek_uri, user.secret_kek_version,
            user.secret_crypto_epoch, user.mfa_secret_ciphertext, user.mfa_secret_nonce,
        )


def _online_backup(source: sqlite3.Connection, destination: Path) -> None:
    """SQLite's online backup API includes committed WAL pages in the snapshot."""
    with closing(sqlite3.connect(destination)) as target:
        source.backup(target)


def _snapshot_valid(path: Path) -> bool:
    with closing(sqlite3.connect(path)) as connection:
        try:
            return (
                connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
                and not connection.execute("PRAGMA foreign_key_check").fetchall()
                and connection.execute(
                    "SELECT value FROM recovery_drill_marker"
                ).fetchall() == [(_MARKER,)]
            )
        except sqlite3.DatabaseError:
            return False


def _tamper_rejected(service: EnvelopeCryptoService, db: Any,
                     conversation: ChatSession, row: SecureMessage,
                     target: Any, field: str, replacement: Any) -> bool:
    """Mutate only the restored ORM identity, with SQL autoflush disabled."""
    original = getattr(target, field)
    try:
        setattr(target, field, replacement)
        service.clear_cache()
        with db.no_autoflush:
            try:
                service.decrypt_message(db, conversation, row)
            except EnvelopeEncryptionError:
                return True
            return False
    finally:
        setattr(target, field, original)
        service.clear_cache()


def _changed_base64(value: str) -> str:
    payload = bytearray(base64.urlsafe_b64decode(value))
    payload[-1] ^= 1
    return base64.urlsafe_b64encode(payload).decode("ascii")


def _verify_crypto(app: Any, session_id: str, user_id: str,
                   expected: list[str], checks: list[dict[str, Any]]) -> None:
    service = app.state.envelope_crypto_service
    service.clear_cache()  # Restoration must unwrap stored keys, not use a warm cache.
    with app.state.database.session_factory() as db:
        conversation = db.get(ChatSession, session_id)
        rows = list(db.scalars(select(SecureMessage).where(
            SecureMessage.session_id == session_id,
        ).order_by(SecureMessage.message_index)))
        _require(checks, "envelope_messages_decrypt_with_retained_key",
                 bool(rows) and all(row.encryption_scheme == ENVELOPE_SCHEME for row in rows)
                 and [service.decrypt_message(db, conversation, row) for row in rows] == expected)
        user = db.get(User, user_id)
        _require(checks, "account_secret_decrypts_with_retained_key",
                 service.decrypt_user_secret(
                     user, ciphertext_b64=user.mfa_secret_ciphertext,
                     nonce_b64=user.mfa_secret_nonce, field=f"mfa:{user.id}",
                 ) == _ACCOUNT_SECRET)
        row = rows[0]
        epoch = db.scalar(select(SessionKeyEpoch).where(
            SessionKeyEpoch.session_id == session_id,
            SessionKeyEpoch.epoch == row.crypto_epoch,
        ))
        wrong_provider = LocalAesKeyProvider(
            {epoch.kek_version: secrets.token_bytes(32)}, active_version=epoch.kek_version,
            key_uri=epoch.kek_uri,
        )
        wrong_service = EnvelopeCryptoService(wrong_provider, cache_ttl_seconds=0)
        rejected = False
        try:
            wrong_service.decrypt_message(db, conversation, row)
        except EnvelopeEncryptionError:
            rejected = True
        _require(checks, "wrong_key_rejected", rejected)
        mutations = (
            ("ciphertext_tamper_rejected", row, "ciphertext", _changed_base64(row.ciphertext)),
            ("message_metadata_tamper_rejected", row, "message_index", row.message_index + 100),
            ("wrapped_dek_tamper_rejected", epoch, "wrapped_dek", _changed_base64(epoch.wrapped_dek)),
            ("kek_uri_tamper_rejected", epoch, "kek_uri", "local://recovery-drill/wrong-key"),
            ("kek_version_tamper_rejected", epoch, "kek_version", "unavailable-drill-version"),
            ("owner_metadata_tamper_rejected", conversation, "owner_id", "wrong-synthetic-owner"),
        )
        for label, target, field, replacement in mutations:
            _require(checks, label, _tamper_rejected(
                service, db, conversation, row, target, field, replacement,
            ))
        db.rollback()


def run_recovery_drill() -> dict[str, Any]:
    """Run synthetic end-to-end recovery and return only non-sensitive evidence."""
    started = time.monotonic()
    checks: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="scap-recovery-drill-") as temporary:
        directory = Path(temporary)
        # Gradio's mount message is harmless, but the command emits one JSON result.
        with redirect_stdout(io.StringIO()), demo_application(directory, _PORT) as source_app:
            base_url = f"http://127.0.0.1:{_PORT}"
            with TestClient(source_app, base_url=base_url) as client:
                active_token = _login(client, "demo.user", checks, purpose="valid_session")
                revoked_token = _login(client, "demo.user", checks, purpose="revoked_session")
                inactive_token = _login(client, "demo.mod", checks, purpose="inactive_account")
                admin_token = _login(client, "demo.boss", checks, purpose="administrator")
                created = client.post("/api/sessions", headers=_headers(active_token),
                                      json={"title": "Synthetic recovery drill"})
                _require(checks, "create_envelope_conversation", created.status_code == 201)
                session_id = created.json()["id"]
                sent = client.post(f"/api/sessions/{session_id}/messages",
                                   headers=_headers(active_token), json={"content": _MESSAGE})
                _require(checks, "offline_encrypted_message", sent.status_code == 201)
                _require(checks, "logout_before_backup", client.post(
                    "/api/auth/logout", headers=_headers(revoked_token),
                ).status_code == 204)
                users = client.get("/api/admin/users", headers=_headers(admin_token))
                _require(checks, "list_synthetic_users", users.status_code == 200)
                inactive_id = next(row["id"] for row in users.json()
                                   if row["username"] == "demo.mod")
                _require(checks, "disable_account_before_backup", client.patch(
                    f"/api/admin/users/{inactive_id}/status", headers=_headers(admin_token),
                    json={"is_active": False},
                ).status_code == 200)

            service = source_app.state.envelope_crypto_service
            with source_app.state.database.session_factory() as db:
                conversation = db.get(ChatSession, session_id)
                user = db.get(User, conversation.owner_id)
                user_id = user.id
                # Retain a historical epoch as well as the current epoch.
                service.rotate_session_dek(db, conversation)
                message_id = uuid4_str()
                index = service.next_message_index(db, session_id)
                ciphertext, nonce, epoch = service.encrypt_message(
                    db, conversation, plaintext=_MESSAGE, role="user",
                    message_uuid=message_id, message_index=index,
                )
                db.add(SecureMessage(
                    session_id=session_id, role="user", message_uuid=message_id,
                    message_index=index, ciphertext=ciphertext, nonce=nonce,
                    crypto_epoch=epoch, encryption_scheme=ENVELOPE_SCHEME,
                ))
                user.mfa_secret_ciphertext, user.mfa_secret_nonce = service.encrypt_user_secret(
                    user, plaintext=_ACCOUNT_SECRET, field=f"mfa:{user.id}",
                )
                # This is a synthetic stored secret, not an enrolled MFA factor.
                db.commit()
                expected = [service.decrypt_message(db, conversation, row) for row in db.scalars(
                    select(SecureMessage).where(SecureMessage.session_id == session_id)
                    .order_by(SecureMessage.message_index)
                )]
            metadata = _key_metadata(source_app.state.database, session_id, user_id)
            _require(checks, "historical_and_current_key_epochs_present", len(metadata[5]) == 2)
            source_path = directory / "demo.db"
            snapshot = directory / "restored.db"
            with closing(sqlite3.connect(source_path)) as source:
                source.execute("PRAGMA journal_mode=WAL")
                source.execute("PRAGMA wal_autocheckpoint=0")
                source.execute("CREATE TABLE recovery_drill_marker (value TEXT NOT NULL)")
                source.execute("INSERT INTO recovery_drill_marker (value) VALUES (?)", (_MARKER,))
                source.commit()
                _require(checks, "committed_wal_pages_present",
                         Path(str(source_path) + "-wal").stat().st_size > 32)
                # An immutable read deliberately ignores WAL, showing why copying
                # only the main .db file cannot capture this latest committed state.
                with closing(sqlite3.connect(
                    source_path.as_uri() + "?mode=ro&immutable=1", uri=True,
                )) as main_only:
                    missing = main_only.execute(
                        "SELECT count(*) FROM sqlite_master WHERE name='recovery_drill_marker'"
                    ).fetchone() == (0,)
                _require(checks, "main_file_alone_misses_latest_commit", missing)
                backup_started = time.monotonic()
                _online_backup(source, snapshot)
                backup_seconds = time.monotonic() - backup_started
            _require(checks, "snapshot_integrity_foreign_keys_and_latest_commit", _snapshot_valid(snapshot))
            snapshot_bytes = snapshot.read_bytes()
            _require(checks, "snapshot_excludes_sample_plaintexts_kek_and_jwt_key", not any(
                value in snapshot_bytes for value in (
                    _MESSAGE.encode(), _ACCOUNT_SECRET.encode(),
                    source_app.state.settings.master_encryption_key.encode(),
                    base64.urlsafe_b64decode(source_app.state.settings.master_encryption_key),
                    source_app.state.settings.secret_key.encode(),
                )
            ))
            del snapshot_bytes
            restore_started = time.monotonic()
            module = importlib.import_module("src.app.main")  # Already safely imported by demo_application.
            restored_settings = replace(
                source_app.state.settings, database_url=f"sqlite:///{snapshot.as_posix()}",
                dek_cache_seconds=0,
            )
            restored_app = module.create_app(restored_settings)
            try:
                _require(checks, "wrapped_keys_and_metadata_preserved",
                         _key_metadata(restored_app.state.database, session_id, user_id) == metadata)
                _verify_crypto(restored_app, session_id, user_id, expected, checks)
                with TestClient(restored_app, base_url=base_url) as restored:
                    _require(checks, "valid_session_works_after_restore", restored.get(
                        f"/api/sessions/{session_id}/messages", headers=_headers(active_token),
                    ).status_code == 200)
                    _require(checks, "logged_out_session_blocked_after_restore", restored.get(
                        "/api/auth/me", headers=_headers(revoked_token),
                    ).status_code == 401)
                    _require(checks, "inactive_account_token_blocked_after_restore", restored.get(
                        "/api/auth/me", headers=_headers(inactive_token),
                    ).status_code == 401)
                    _require(checks, "inactive_account_login_blocked_after_restore", restored.post(
                        "/api/auth/login", json={"username": "demo.mod", "password": DEMO_PASSPHRASE},
                    ).status_code == 401)
                    audit = restored.get("/api/admin/audit/verify", headers=_headers(admin_token))
                    _require(checks, "sealed_audit_chain_valid_after_restore",
                             audit.status_code == 200 and audit.json().get("chain_intact") is True)
                restore_seconds = time.monotonic() - restore_started
            finally:
                restored_app.state.envelope_crypto_service.clear_cache()
                restored_app.state.database.engine.dispose()
    return {
        "status": "passed", "scope": "disposable_offline_sqlite_demo",
        "checks": checks, "backup_seconds": round(backup_seconds, 6),
        "restore_and_verify_seconds": round(restore_seconds, 6),
        "total_seconds": round(time.monotonic() - started, 6),
        "keys_embedded_in_snapshot": False,
        "limitations": [
            "Synthetic local timings do not establish production RTO/RPO.",
            "The retained local KEK/JWT key is kept in memory; external Vault/KMS/WORM is not exercised.",
            "Revocations committed after a snapshot require reconciliation before a real restore is exposed.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Diễn tập phục hồi với SQLite demo tạm, ngoại tuyến.")
    parser.parse_args(argv)
    try:
        report = run_recovery_drill()
    except RecoveryDrillError as error:
        print(json.dumps({"status": "failed", "failed_check": error.check}))
        return 1
    except Exception:  # noqa: BLE001 - Do not leak tokens, key material or paths from diagnostics.
        print(json.dumps({"status": "failed", "failed_check": "unexpected_drill_error"}))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
