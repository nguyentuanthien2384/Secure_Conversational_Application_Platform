"""Encrypted local SQLite backup and offline restore into a NEW file only.

Usage (passphrases are requested through getpass, never arguments/environment):
    python -m scripts.secure_backup backup --database local.db --output copy.scapbak
    python -m scripts.secure_backup restore --archive copy.scapbak --output recovered.db

The archive contains the DB, including wrapped DEKs and key-version metadata,
but does not export .env, KEKs, signing keys or external Vault/WORM state. Keep
those separately. Restore revokes sessions and one-time credentials; operators
must reconcile account/password/MFA/recovery-email/passkey changes and E2EE
device revocations, memberships and epochs after the snapshot BEFORE serving
it. This is a bounded local SQLite tool, not a PostgreSQL backup tool.

The v1 framing stores fixed Argon2id parameters, salt, nonce, creation time and
SQLite byte length in a fixed header authenticated as AES-GCM additional data.
Untrusted headers and file sizes are rejected before allocating/deriving a key.
Temporary plaintext snapshots use a private directory, then are removed. On
Windows their ACL inherits the destination directory; chmod is not an ACL or
secure-erasure guarantee. Use an operator-owned directory on encrypted storage.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import sqlite3
import stat
import struct
import sys
import tempfile
import time
import warnings
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_DATABASE_BYTES = 64 * 1024 * 1024
BACKUP_DEADLINE_SECONDS = 30
_MAGIC = b"SCAPBK01"
_VERSION = 1
_KDF_TIME = 3
_KDF_MEMORY_KIB = 64 * 1024
_KDF_PARALLELISM = 1
_HEADER = struct.Struct(">8sBIIIQQ16s12s")
_TAG_BYTES = 16
_MAX_SQLITE_INTEGER = (1 << 63) - 1
_SCHEMA = {
    "users": {"id", "username", "token_version", "is_active", "mfa_last_counter"},
    "auth_sessions": {"jti", "revoked_at", "last_step_up_at"},
    "mfa_recovery_codes": {"used_at"},
    "account_recovery_codes": {"consumed_at"},
    "webauthn_challenges": {"id"},
    "e2ee_device_challenges": {"id"},
    "e2ee_prekeys": {"consumed_at"},
    "audit_events": {"entry_hash", "prev_hash"},
    "chat_sessions": {"wrapped_dek", "kek_version"},
    "session_key_epochs": {"wrapped_dek", "kek_version"},
}


class BackupError(RuntimeError):
    """Operator-facing fixed messages never containing data or passphrases."""


def _passphrase_bytes(passphrase: str) -> bytes:
    if not isinstance(passphrase, str):
        raise BackupError("Passphrase must contain 16-1024 UTF-8 bytes.")
    encoded = passphrase.encode("utf-8")
    if not 16 <= len(encoded) <= 1024:
        raise BackupError("Passphrase must contain 16-1024 UTF-8 bytes.")
    return encoded


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        _passphrase_bytes(passphrase), salt, time_cost=_KDF_TIME,
        memory_cost=_KDF_MEMORY_KIB, parallelism=_KDF_PARALLELISM,
        hash_len=32, type=Type.ID,
    )


def _checked_path(path: Path, *, existing: bool) -> Path:
    """Reject links/junctions, including parents; use trusted local directories.

    The atomic no-replace publish additionally closes the destination-exists
    race. It does not provide a hostile local administrator's handle sandbox.
    """
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        if part.is_symlink() or getattr(part, "is_junction", lambda: False)():
            raise BackupError("Linked paths are not supported.")
    if existing:
        if not path.is_file():
            raise BackupError("Input must be an existing regular file.")
    else:
        if os.path.lexists(path):
            raise BackupError("Output must be a new file.")
        if not path.parent.is_dir():
            raise BackupError("Output directory must already exist.")
    return path


def _open_input(path: Path) -> BinaryIO:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        checked = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(opened.st_mode) or (
            opened.st_dev, opened.st_ino
        ) != (checked.st_dev, checked.st_ino):
            raise BackupError("Input must remain the checked regular file.")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def _write_new(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(payload)
        target.flush()
        os.fsync(target.fileno())


def _publish_new(temporary: Path, output: Path) -> None:
    """Hard-link publication is atomic and never replaces any existing entry.

    Source and output are on the same filesystem. A filesystem without hard
    links fails closed, leaving no output, rather than falling back to replace.
    """
    _checked_path(output, existing=False)
    try:
        os.link(temporary, output)
    except FileExistsError as exc:
        raise BackupError("Output must be a new file.") from exc


def _validate_sqlite(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA trusted_schema=OFF")
    deadline = time.monotonic() + BACKUP_DEADLINE_SECONDS
    connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 10_000)
    if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise BackupError("SQLite integrity validation failed.")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise BackupError("SQLite foreign-key validation failed.")
    # SQL below is built only from these fixed literals, never file/user input.
    tables = {
        row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")
    }
    # This SCAP SQLite schema uses tables/indexes only. Triggers could otherwise
    # undo credential revocation or edit sealed audit rows during restore.
    if connection.execute("SELECT 1 FROM sqlite_schema WHERE type IN ('trigger', 'view') LIMIT 1").fetchone():
        raise BackupError("Database contains unsupported triggers or views.")
    for table, required in _SCHEMA.items():
        if table not in tables or not required.issubset({
            row[1] for row in connection.execute(f"PRAGMA table_info({table})")
        }):
            raise BackupError("Database does not match the supported SCAP schema.")


def _snapshot(source_path: Path, output: Path) -> None:
    if source_path.stat().st_size > MAX_DATABASE_BYTES:
        raise BackupError("Database exceeds the 64 MiB local backup limit.")
    started = time.monotonic()
    with closing(sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True, timeout=5)) as source:
        source.execute("PRAGMA query_only=ON")
        source.execute("PRAGMA trusted_schema=OFF")
        page_size = int(source.execute("PRAGMA page_size").fetchone()[0])

        def bounded_progress(_status: int, _remaining: int, pages: int) -> None:
            if pages * page_size > MAX_DATABASE_BYTES:
                raise BackupError("Database exceeds the 64 MiB local backup limit.")
            if time.monotonic() - started > BACKUP_DEADLINE_SECONDS:
                raise BackupError("SQLite snapshot exceeded its 30-second deadline.")

        # SQLite writes into this already-created private file. Its online
        # backup API includes committed WAL pages without copying sidecars.
        _write_new(output, b"")
        with closing(sqlite3.connect(output, timeout=5)) as destination:
            source.backup(destination, pages=256, progress=bounded_progress, sleep=0.05)
            destination.execute("PRAGMA journal_mode=DELETE")
            _validate_sqlite(destination)
    if output.stat().st_size > MAX_DATABASE_BYTES:
        raise BackupError("Database exceeds the 64 MiB local backup limit.")


def backup_database(database: Path, output: Path, passphrase: str) -> dict[str, object]:
    """Read an explicit SQLite path only, then publish one encrypted new file."""
    _passphrase_bytes(passphrase)
    database = _checked_path(database, existing=True)
    output = _checked_path(output, existing=False)
    with tempfile.TemporaryDirectory(prefix="scap-backup-", dir=output.parent) as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        snapshot = directory / "snapshot.db"
        _snapshot(database, snapshot)
        payload = snapshot.read_bytes()
        created = int(time.time())
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        header = _HEADER.pack(
            _MAGIC, _VERSION, _KDF_TIME, _KDF_MEMORY_KIB, _KDF_PARALLELISM,
            created, len(payload), salt, nonce,
        )
        encrypted = AESGCM(_derive_key(passphrase, salt)).encrypt(nonce, payload, header)
        archive = directory / "archive.scapbak"
        _write_new(archive, header + encrypted)
        _publish_new(archive, output)
    return {"status": "backed_up", "format_version": _VERSION,
            "database_bytes": len(payload), "created_at_unix": created,
            "keys_exported": False}


def _decrypt_archive(archive: Path, passphrase: str) -> tuple[bytes, int]:
    _passphrase_bytes(passphrase)
    with _open_input(archive) as source:
        size = os.fstat(source.fileno()).st_size
        if not _HEADER.size + _TAG_BYTES <= size <= _HEADER.size + _TAG_BYTES + MAX_DATABASE_BYTES:
            raise BackupError("Backup archive has an invalid size.")
        header = source.read(_HEADER.size)
        if len(header) != _HEADER.size:
            raise BackupError("Backup archive has an invalid header.")
        magic, version, kdf_time, memory, parallelism, created, length, salt, nonce = _HEADER.unpack(header)
        if (magic, version, kdf_time, memory, parallelism) != (
            _MAGIC, _VERSION, _KDF_TIME, _KDF_MEMORY_KIB, _KDF_PARALLELISM
        ) or not 16 <= length <= MAX_DATABASE_BYTES or not 1 <= created <= 253402300799:
            raise BackupError("Backup archive has an unsupported header.")
        if size != _HEADER.size + length + _TAG_BYTES:
            raise BackupError("Backup archive length does not match its header.")
        encrypted = source.read(length + _TAG_BYTES + 1)
        if len(encrypted) != length + _TAG_BYTES:
            raise BackupError("Backup archive length changed while reading.")
    try:
        payload = AESGCM(_derive_key(passphrase, salt)).decrypt(nonce, encrypted, header)
    except InvalidTag as exc:
        raise BackupError("Backup authentication failed; password or archive is invalid.") from exc
    if not payload.startswith(b"SQLite format 3\x00"):
        raise BackupError("Authenticated payload is not a SQLite database.")
    return payload, created


def _revoke_restored_credentials(path: Path, reviewed_users: tuple[str, ...]) -> dict[str, int]:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    with closing(sqlite3.connect(path, timeout=5)) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=DELETE")
        _validate_sqlite(connection)
        # A random increasing jump also invalidates stateless MFA tokens issued
        # AFTER this snapshot; a plain +1 could equal their later version.
        users = connection.execute("SELECT id, token_version FROM users").fetchall()
        if len(set(reviewed_users)) != len(reviewed_users) or any(
            not isinstance(name, str) or not 1 <= len(name) <= 64 for name in reviewed_users
        ):
            raise BackupError("Reviewed account names must be unique and contain 1-64 characters.")
        reviewed_ids = []
        for name in reviewed_users:
            row = connection.execute("SELECT id FROM users WHERE username=?", (name,)).fetchone()
            if row is None:
                raise BackupError("A reviewed account does not exist in this snapshot.")
            reviewed_ids.append(row[0])
        with connection:
            # Account/password/passkey revocations after a stale backup cannot
            # be inferred from that backup. Keep EVERY account inactive until
            # an OS-authorized operator explicitly names a reviewed account.
            connection.execute("UPDATE users SET is_active=0")
            for user_id, version in users:
                if not isinstance(version, int) or not 0 <= version <= _MAX_SQLITE_INTEGER - (1 << 32):
                    raise BackupError("Account token version is outside the supported restore range.")
                new_version = version + 1 + secrets.randbelow(_MAX_SQLITE_INTEGER - version)
                connection.execute("UPDATE users SET token_version=? WHERE id=?", (new_version, user_id))
            for user_id in reviewed_ids:
                connection.execute("UPDATE users SET is_active=1 WHERE id=?", (user_id,))
            # TOTP accepts a one-step future clock-skew window. Retire the
            # entire current window as well as counters retained in the DB.
            connection.execute(
                "UPDATE users SET mfa_last_counter=MAX(mfa_last_counter, ?)",
                (int(time.time()) // 30 + 1,),
            )
            sessions = connection.execute(
                "UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at, ?), last_step_up_at=NULL",
                (now,),
            ).rowcount
            # Consume all saved codes: a stale snapshot cannot know which codes
            # were used after it. Users regenerate their MFA backup codes after
            # recovery through the existing password + MFA protected workflow.
            mfa_codes = connection.execute(
                "UPDATE mfa_recovery_codes SET used_at=COALESCE(used_at, ?)", (now,),
            ).rowcount
            recovery_codes = connection.execute(
                "UPDATE account_recovery_codes SET consumed_at=COALESCE(consumed_at, ?)", (now,),
            ).rowcount
            # A public one-time prekey consumed after this snapshot must never
            # be handed out again. Device owners upload fresh prekeys only
            # after their device trust/epoch state has been reconciled.
            prekeys = connection.execute(
                "UPDATE e2ee_prekeys SET consumed_at=COALESCE(consumed_at, ?)", (now,),
            ).rowcount
            challenges = (
                connection.execute("DELETE FROM webauthn_challenges").rowcount
                + connection.execute("DELETE FROM e2ee_device_challenges").rowcount
            )
        _validate_sqlite(connection)
    return {"users_invalidated": len(users), "users_quarantined": len(users) - len(reviewed_ids),
            "reviewed_users_activated": len(reviewed_ids), "sessions_revoked": sessions,
            "mfa_recovery_codes_consumed": mfa_codes,
            "account_recovery_codes_consumed": recovery_codes,
            "e2ee_prekeys_retired": prekeys, "challenges_removed": challenges}


def restore_database(
    archive: Path, output: Path, passphrase: str, *, reviewed_users: tuple[str, ...] = (),
) -> dict[str, object]:
    """Authenticate before writing; publish only a sanitized NEW offline DB."""
    archive = _checked_path(archive, existing=True)
    output = _checked_path(output, existing=False)
    payload, created = _decrypt_archive(archive, passphrase)
    with tempfile.TemporaryDirectory(prefix="scap-restore-", dir=output.parent) as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        restored = directory / "restored.db"
        _write_new(restored, payload)
        counts = _revoke_restored_credentials(restored, reviewed_users)
        # fsync the modified SQLite main file after its transaction has closed.
        with restored.open("r+b") as source:
            os.fsync(source.fileno())
        _publish_new(restored, output)
    return {"status": "restored_offline", "format_version": _VERSION,
            "created_at_unix": created, "keys_exported": False,
            "requires_account_revocation_review": True, **counts}


def _prompt_passphrase(*, confirm: bool) -> str:
    with warnings.catch_warnings():
        # Refuse getpass's echoed fallback rather than exposing a secret in CI.
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            passphrase = getpass.getpass("Backup passphrase (16+ UTF-8 bytes): ")
            _passphrase_bytes(passphrase)
            if confirm and getpass.getpass("Confirm backup passphrase: ") != passphrase:
                raise BackupError("Passphrase confirmation did not match.")
            return passphrase
        except (getpass.GetPassWarning, EOFError) as exc:
            raise BackupError("A terminal with hidden password input is required.") from exc


def main(argv: list[str] | None = None) -> int:
    class QuietParser(argparse.ArgumentParser):
        def error(self, message: str) -> None:
            # argparse normally echoes unknown values. A mistaken attempt to
            # put a password in argv must not also copy it into console logs.
            self.exit(2, "Invalid command arguments. Use --help; passphrases require hidden terminal input.\n")

    parser = QuietParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False)
    commands = parser.add_subparsers(dest="operation", required=True)
    backup = commands.add_parser("backup", help="Encrypt a bounded online SQLite snapshot")
    backup.add_argument("--database", type=Path, required=True)
    backup.add_argument("--output", type=Path, required=True)
    restore = commands.add_parser("restore", help="Restore into a NEW offline SQLite file")
    restore.add_argument("--archive", type=Path, required=True)
    restore.add_argument("--output", type=Path, required=True)
    restore.add_argument(
        "--activate-reviewed-user", action="append", default=[], metavar="USERNAME",
        help="Explicit offline activation after reconciling later account/password/MFA/recovery-email/passkey changes and E2EE device revocations, memberships and epochs; repeat per reviewed account. Default: all accounts remain inactive.",
    )
    args = parser.parse_args(argv)
    try:
        password = _prompt_passphrase(confirm=args.operation == "backup")
        result = backup_database(args.database, args.output, password) if args.operation == "backup" else restore_database(args.archive, args.output, password, reviewed_users=tuple(args.activate_reviewed_user))
    except KeyboardInterrupt:
        print("Backup operation cancelled; no replacement was performed.", file=sys.stderr)
        return 130
    except BackupError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (OSError, sqlite3.DatabaseError, ValueError):
        print("Backup operation failed; verify storage access, schema and available space.", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    if args.operation == "restore":
        print("Keep this restored DB offline until later account/password/MFA/recovery-email/passkey changes, E2EE device revocations, memberships, epochs and external audit checkpoints have been reviewed. Retired one-time prekeys must be replaced after that review. Restore the required keys separately.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
