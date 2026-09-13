"""Migrate legacy shared-key messages to per-conversation envelope encryption."""

from __future__ import annotations

import argparse
import json

from sqlalchemy import select

from scripts.rewrap_deks import build_service
from src.app.config import Settings
from src.app.db import Database
from src.app.envelope import ENVELOPE_SCHEME
from src.app.models import ChatSession, SecureMessage, User


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate SCAP message encryption")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--batch-size", type=int, default=100)
    args = parser.parse_args()
    if args.limit < 0 or not 1 <= args.batch_size <= 1000:
        parser.error("invalid limit or batch size")
    settings = Settings.from_env()
    database = Database(settings.database_url)
    database.assert_schema_ready()
    service = build_service(settings)
    migrated = 0
    account_secrets = 0
    scanned = 0
    with database.session_factory() as db:
        stmt = (
            select(SecureMessage)
            .where(SecureMessage.encryption_scheme != ENVELOPE_SCHEME)
            .order_by(SecureMessage.id.asc())
        )
        if args.limit:
            stmt = stmt.limit(args.limit)
        rows = list(db.scalars(stmt))
        users = list(
            db.scalars(
                select(User).where(
                    User.mfa_secret_ciphertext.is_not(None),
                    User.secret_wrapped_dek.is_(None),
                )
            )
        )
        scanned = len(rows)
        if not args.dry_run:
            for row in rows:
                chat_session = db.get(ChatSession, row.session_id)
                if chat_session is None or chat_session.security_mode == "private_e2ee":
                    continue
                migrated += int(service.migrate_legacy_message(db, chat_session, row))
                if migrated and migrated % args.batch_size == 0:
                    db.commit()
            for user in users:
                if not user.mfa_secret_ciphertext or not user.mfa_secret_nonce:
                    continue
                secret = service.decrypt_user_secret(
                    user,
                    ciphertext_b64=user.mfa_secret_ciphertext,
                    nonce_b64=user.mfa_secret_nonce,
                    field=f"mfa:{user.id}",
                )
                try:
                    user.mfa_secret_ciphertext, user.mfa_secret_nonce = (
                        service.encrypt_user_secret(
                            user,
                            plaintext=secret,
                            field=f"mfa:{user.id}",
                        )
                    )
                    account_secrets += 1
                finally:
                    del secret
            db.commit()
        else:
            migrated = scanned
            account_secrets = len(users)
    service.clear_cache()
    print(
        json.dumps(
            {
                "dry_run": args.dry_run,
                "scanned": scanned,
                "migrated": migrated,
                "account_secrets": account_secrets,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
