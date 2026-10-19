#!/usr/bin/env python3
"""Give existing accounts on a production VPS one new PRIVATE password.

``seed_vps_accounts.py`` only creates missing demo accounts and never changes an
existing one. This operator-only command sets one password, typed interactively
(never in argv/environment), for the existing demo accounts (demo.user, demo.mod,
demo.boss, lab.*) or, with ``--all-users``, for every account in the database.
Each account is unlocked, signed out everywhere and gets its own sealed
``admin.password_reset`` audit event. MFA and the active/inactive state are kept.
Run inside the app container, e.g. ``bash deploy/vps-compose.sh run --rm
--no-deps app /app/.venv/bin/python scripts/reset_vps_passwords.py``.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pydantic import ValidationError  # noqa: E402
from sqlalchemy import select, update  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402
from sqlalchemy.exc import SQLAlchemyError  # noqa: E402

from scripts.create_admin import AdminProvisioningError, _profile_check  # noqa: E402
from src.app.audit_chain import (  # noqa: E402
    append_lock,
    derive_audit_key,
    seal_event,
    verify_chain,
)
from src.app.config import Settings  # noqa: E402
from src.app.db import Database, utcnow  # noqa: E402
from src.app.demo_seed import ALL_DEMO_USERS, DEMO_PASSPHRASE  # noqa: E402
from src.app.models import AuditEvent, AuthSession, User  # noqa: E402
from src.app.schemas import RegisterRequest  # noqa: E402
from src.app.security import (  # noqa: E402
    PasswordBreachCheckUnavailable,
    PasswordService,
    PwnedPasswordChecker,
)
from src.app.siem import configure_siem_logging, emit_security_event  # noqa: E402


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # An accidental --password/value must not be echoed by argparse.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid arguments. Only --all-users is accepted; the password is typed.\n")


def target_usernames(database: Database, *, all_users: bool = False) -> list[str]:
    """Existing accounts the reset would change, in a stable order."""
    query = select(User.username).order_by(User.username)
    if not all_users:
        query = query.where(User.username.in_([username for username, _ in ALL_DEMO_USERS]))
    try:
        with database.session_factory() as db:
            return list(db.scalars(query))
    except SQLAlchemyError:
        raise AdminProvisioningError("Cannot access the migrated database; nothing was changed.") from None


def _check_password(settings: Settings, password: str) -> None:
    if password == DEMO_PASSPHRASE:
        raise AdminProvisioningError(
            "That is the public demo password from the README; choose a private one."
        )
    if not password.isascii():
        # A Vietnamese input method left on in the terminal turns letters such
        # as "ss" or "oo" into accented characters (or broken bytes) unseen.
        raise AdminProvisioningError(
            "Use only unaccented ASCII characters; switch the Vietnamese input method off."
        )
    try:
        RegisterRequest(username=ALL_DEMO_USERS[0][0], password=password)
    except ValidationError:
        # ValidationError includes input values by default, including passwords.
        raise AdminProvisioningError("Use a non-common password of 15 to 128 characters.") from None
    checker = PwnedPasswordChecker(enabled=settings.password_breach_check)
    try:
        if checker.is_compromised(password):
            raise AdminProvisioningError("That password appears in a public breach; choose another.")
    except PasswordBreachCheckUnavailable:
        raise AdminProvisioningError("Password breach screening is unavailable; try again later.") from None


def reset_vps_passwords(
    settings: Settings,
    database: Database,
    *,
    password: str,
    all_users: bool = False,
) -> list[str]:
    """Set ``password`` on the selected existing accounts; return their usernames."""
    _profile_check(settings)
    _check_password(settings, password)
    key = derive_audit_key(settings.secret_key)
    try:
        with database.session_factory() as db:
            if not verify_chain(db, key).intact:
                raise AdminProvisioningError(
                    "The existing audit chain is not intact; investigate before resetting passwords."
                )
    except SQLAlchemyError:
        raise AdminProvisioningError("Cannot access the migrated database; nothing was changed.") from None
    names = target_usernames(database, all_users=all_users)
    if not names:
        return []
    # Argon2 is deliberately slow: hash before taking any row or audit lock.
    passwords = PasswordService()
    hashes = {name: passwords.hash(password) for name in names}
    scope = "all_users" if all_users else "demo_accounts"
    sealed: list[tuple[int, str, dict[str, object]]] = []
    try:
        with database.session_factory() as db, db.begin():
            # Same order as the web runtime: user rows first, then the audit append.
            users = list(db.scalars(
                select(User).where(User.username.in_(names)).order_by(User.id).with_for_update()
            ))
            now = utcnow()
            db.execute(
                update(AuthSession)
                .where(AuthSession.user_id.in_([user.id for user in users]),
                       AuthSession.revoked_at.is_(None))
                .values(revoked_at=now)
                .execution_options(synchronize_session=False)
            )
            for user in users:
                user.password_hash = hashes[user.username]
                user.failed_login_attempts = 0
                user.locked_until = None
                user.mfa_failed_attempts = 0
                user.mfa_locked_until = None
                # Invalidates every bearer token, as a self-service password change does.
                user.token_version += 1
            db.flush()
            with append_lock(db):
                for user in users:
                    details: dict[str, object] = {
                        "source": "one_off_cli",
                        "scope": scope,
                        "token_version": user.token_version,
                    }
                    event = AuditEvent(
                        event_type="admin.password_reset",
                        outcome="success",
                        target_type="user",
                        target_id=user.id,
                        details_json=json.dumps(details, sort_keys=True),
                    )
                    seal_event(db, event, key)
                    db.add(event)
                    db.flush()
                    sealed.append((event.id, event.entry_hash, details))
            changed = sorted(user.username for user in users)
    except SQLAlchemyError:
        # SQL exceptions can contain a URL, password hash or UPDATE parameters.
        raise AdminProvisioningError("Database update failed; nothing was changed.") from None
    for event_id, entry_hash, details in sealed:
        emit_security_event("admin.password_reset", audit_id=event_id,
                            entry_hash=entry_hash, details=details)
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description=__doc__)
    parser.add_argument("--all-users", action="store_true",
                        help="Reset every account in the database, not only demo.* and lab.*.")
    arguments = parser.parse_args(argv)
    if not sys.stdin.isatty():
        print("Password reset requires an interactive terminal; passwords cannot be piped.", file=sys.stderr)
        return 1
    database = None
    try:
        settings = Settings.from_env()
        _profile_check(settings)
        if make_url(settings.database_url).get_backend_name() != "postgresql":
            raise AdminProvisioningError("This command requires the migrated PostgreSQL database.")
        database = Database(settings.database_url, runtime_limits=True)
        names = target_usernames(database, all_users=arguments.all_users)
        if not names:
            print("No matching accounts exist; create the demo accounts with seed_vps_accounts.py.")
            return 0
        print(f"{len(names)} accounts will get the new password and be signed out everywhere:")
        print("  " + ", ".join(names))
        missing = [username for username, _ in ALL_DEMO_USERS if username not in names]
        if missing and not arguments.all_users:
            print(f"Not created yet (run seed_vps_accounts.py afterwards): {', '.join(missing)}")
        if input("Continue? [y/N] ").strip().lower() != "y":
            print("Cancelled; nothing was changed.")
            return 1
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("New password for these accounts: ")
            confirmation = getpass.getpass("Repeat password: ")
        if password != confirmation:
            raise AdminProvisioningError("The passwords did not match; nothing was changed.")
        configure_siem_logging(settings.siem_json_logs)
        changed = reset_vps_passwords(settings, database, password=password,
                                      all_users=arguments.all_users)
        print(f"New password set for {len(changed)} accounts: {', '.join(changed)}.")
        print("Their failed-login locks were cleared; accounts with MFA still need their code.")
        return 0
    except AdminProvisioningError as exc:
        print(f"Password reset refused: {exc}", file=sys.stderr)
    except (EOFError, KeyboardInterrupt):
        print("Password reset cancelled.", file=sys.stderr)
    except (getpass.GetPassWarning, OSError, RuntimeError, ValueError, SQLAlchemyError):
        # Keep arbitrary configuration/connection exception text out of output.
        print("Password reset failed. Check the production configuration and database access.", file=sys.stderr)
    finally:
        if database is not None:
            database.engine.dispose()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
