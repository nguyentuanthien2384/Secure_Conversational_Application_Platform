"""Quarantine a restored PostgreSQL snapshot before any public traffic resumes.

Run as a database owner in an isolated maintenance container. No application
secret, plaintext conversation, or external provider credential is required.
This does not infer account/device changes that happened after the snapshot;
an operator must reconcile them before explicitly activating reviewed users.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import time

from sqlalchemy import delete, func, select, update
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from src.app.config import database_url_with_file_password
from src.app.db import Database, utcnow
from src.app.models import (
    AccountRecoveryCode,
    AuthSession,
    E2eeDeviceChallenge,
    E2eePreKey,
    MfaRecoveryCode,
    User,
    WebAuthnChallenge,
)

MAX_TOKEN_VERSION = (1 << 31) - 1  # PostgreSQL users.token_version is INTEGER.


def quarantine(db: Session) -> dict[str, int]:
    """Invalidate restored bearer/factor proofs and lock every account atomically."""
    now = utcnow()
    users = list(db.scalars(select(User).order_by(User.id).with_for_update()))
    for user in users:
        version = user.token_version
        if not isinstance(version, int) or not 0 <= version < MAX_TOKEN_VERSION:
            raise ValueError("Restored token version cannot safely be advanced.")
        user.is_active = False
        # A random jump avoids matching stateless MFA challenges issued after
        # the snapshot. A plain +1 can recreate exactly such a later version.
        user.token_version = version + 1 + secrets.randbelow(MAX_TOKEN_VERSION - version)
        user.mfa_last_counter = max(user.mfa_last_counter, int(time.time()) // 30 + 1)
    counts = {"users_quarantined": len(users)}
    for model, field, label in (
        (AuthSession, AuthSession.revoked_at, "sessions_revoked"),
        (MfaRecoveryCode, MfaRecoveryCode.used_at, "mfa_recovery_codes_consumed"),
        (AccountRecoveryCode, AccountRecoveryCode.consumed_at, "account_recovery_codes_consumed"),
        (E2eePreKey, E2eePreKey.consumed_at, "e2ee_prekeys_retired"),
    ):
        values = {field.key: func.coalesce(field, now)}
        if model is AuthSession:
            values["last_step_up_at"] = None
        counts[label] = db.execute(
            update(model).values(**values).execution_options(synchronize_session=False)
        ).rowcount
    counts["challenges_removed"] = sum(
        db.execute(delete(model).execution_options(synchronize_session=False)).rowcount
        for model in (WebAuthnChallenge, E2eeDeviceChallenge)
    )
    db.commit()
    return counts


def activate_reviewed_users(db: Session, names: list[str]) -> dict[str, int]:
    if (not names or len(names) != len(set(names))
            or any(not isinstance(name, str) or not 1 <= len(name) <= 64 for name in names)):
        raise ValueError("Name each reviewed account once (1-64 characters).")
    users = list(db.scalars(select(User).where(User.username.in_(names)).with_for_update()))
    if len(users) != len(names):
        raise ValueError("A reviewed account does not exist in this snapshot.")
    for user in users:
        user.is_active = True
    db.commit()
    return {"reviewed_users_activated": len(users)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("quarantine")
    activate = commands.add_parser("activate-reviewed-user")
    activate.add_argument("username", nargs="+")
    args = parser.parse_args()
    url = database_url_with_file_password(os.getenv("DATABASE_URL", "").strip())
    parsed = make_url(url)
    if parsed.get_backend_name() != "postgresql" or parsed.username in {"scap_app", "scap_auditor"}:
        parser.error("Use an isolated PostgreSQL owner maintenance connection.")
    database = Database(url)
    try:
        database.assert_schema_ready()
        with database.session_factory() as db:
            result = (quarantine(db) if args.operation == "quarantine"
                      else activate_reviewed_users(db, args.username))
    finally:
        database.engine.dispose()
    print(json.dumps({"status": args.operation, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
