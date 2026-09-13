"""Rewrap conversation/account DEKs after rotating a Vault/KMS KEK."""

from __future__ import annotations

import argparse
import json

from sqlalchemy import select

from src.app.config import Settings
from src.app.db import Database
from src.app.envelope import EnvelopeCryptoService
from src.app.key_management import (
    AwsKmsKeyProvider,
    GcpKmsKeyProvider,
    LocalAesKeyProvider,
    VaultTransitKeyProvider,
)
from src.app.models import ChatSession, User
from src.app.security import CryptoService


def build_service(settings: Settings) -> EnvelopeCryptoService:
    keyring = dict(settings.master_encryption_keys)
    if settings.master_encryption_key:
        keyring.setdefault(1, settings.master_encryption_key)
    active = settings.active_key_version or (max(keyring) if keyring else 1)
    legacy = CryptoService(keyring=keyring, active_key_version=active) if keyring else None
    if settings.key_provider == "local":
        provider = LocalAesKeyProvider.from_base64_keyring(
            keyring,
            active_version=active,
        )
    elif settings.key_provider == "vault":
        provider = VaultTransitKeyProvider(
            address=settings.vault_addr,
            token_file=settings.vault_token_file,
            key_name=settings.vault_transit_key,
            mount=settings.vault_transit_mount,
            namespace=settings.vault_namespace,
            allow_insecure_http=settings.vault_allow_insecure_http,
        )
    elif settings.key_provider == "aws-kms":
        provider = AwsKmsKeyProvider(
            key_id=settings.aws_kms_key_id,
            region=settings.aws_region,
        )
    else:
        provider = GcpKmsKeyProvider(key_name=settings.gcp_kms_key_name)
    return EnvelopeCryptoService(provider, legacy_crypto=legacy, cache_ttl_seconds=0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Rewrap SCAP DEKs under the active KEK")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()
    if args.limit < 0:
        parser.error("--limit cannot be negative")
    settings = Settings.from_env()
    database = Database(settings.database_url)
    database.assert_schema_ready()
    service = build_service(settings)
    with database.session_factory() as db:
        session_stmt = select(ChatSession).where(ChatSession.wrapped_dek.is_not(None))
        user_stmt = select(User).where(User.secret_wrapped_dek.is_not(None))
        if args.limit:
            session_stmt = session_stmt.limit(args.limit)
            user_stmt = user_stmt.limit(args.limit)
        sessions = list(db.scalars(session_stmt))
        users = list(db.scalars(user_stmt))
        session_keys = sum(len(item.key_epochs) for item in sessions)
        if not args.dry_run:
            for chat_session in sessions:
                service.rewrap_session_keys(db, chat_session)
            user_keys = sum(1 for user in users if service.rewrap_user_key(user))
            db.commit()
        else:
            user_keys = len(users)
    print(
        json.dumps(
            {
                "dry_run": args.dry_run,
                "sessions": len(sessions),
                "conversation_deks": session_keys,
                "account_deks": user_keys,
                "provider": settings.key_provider,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
