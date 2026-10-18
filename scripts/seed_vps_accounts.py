#!/usr/bin/env python3
"""Recreate the familiar demo accounts on a production VPS with a PRIVATE password.

Production refuses SEED_DEMO_DATA because the README publishes the demo
password. This operator-only command creates the same usernames, roles and
encrypted sample conversations (demo.user, demo.mod, demo.boss, lab.*) with
one password typed interactively, never in argv/environment, and records a
sealed audit event. Existing accounts are left untouched. Run inside the app
container, e.g. ``bash deploy/vps-compose.sh run --rm --no-deps app
/app/.venv/bin/python scripts/seed_vps_accounts.py``.
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
from sqlalchemy import select  # noqa: E402
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
from src.app.db import Database  # noqa: E402
from src.app.demo_seed import ALL_DEMO_USERS, DEMO_PASSPHRASE, seed_demo_data  # noqa: E402
from src.app.models import AuditEvent, User  # noqa: E402
from src.app.schemas import RegisterRequest  # noqa: E402
from src.app.security import (  # noqa: E402
    CryptoService,
    PasswordBreachCheckUnavailable,
    PasswordService,
    PwnedPasswordChecker,
)
from src.app.siem import configure_siem_logging, emit_security_event  # noqa: E402


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # An accidental --password/value must not be echoed by argparse.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid arguments. Only --with-sample-alerts is accepted; the password is typed.\n")


def seed_vps_accounts(
    settings: Settings,
    database: Database,
    *,
    password: str,
    sample_alerts: bool = False,
    log=print,
) -> list[str]:
    """Create missing demo accounts with ``password``; return the new usernames."""
    _profile_check(settings)
    if password == DEMO_PASSPHRASE:
        raise AdminProvisioningError(
            "That is the public demo password from the README; choose a private one."
        )
    try:
        RegisterRequest(username=ALL_DEMO_USERS[0][0], password=password)
    except ValidationError:
        # ValidationError includes input values by default, including passwords.
        raise AdminProvisioningError("Use a non-common password of 15 to 128 characters.") from None
    names = [username for username, _ in ALL_DEMO_USERS]
    key = derive_audit_key(settings.secret_key)
    try:
        with database.session_factory() as db:
            existing = set(db.scalars(select(User.username).where(User.username.in_(names))))
            if not verify_chain(db, key).intact:
                raise AdminProvisioningError(
                    "The existing audit chain is not intact; investigate before provisioning."
                )
    except SQLAlchemyError:
        raise AdminProvisioningError("Cannot access the migrated database; nothing was changed.") from None
    created = [username for username in names if username not in existing]
    if not created:
        return []
    checker = PwnedPasswordChecker(enabled=settings.password_breach_check)
    try:
        if checker.is_compromised(password):
            raise AdminProvisioningError("That password appears in a public breach; choose another.")
    except PasswordBreachCheckUnavailable:
        raise AdminProvisioningError("Password breach screening is unavailable; try again later.") from None
    crypto = CryptoService(
        settings.master_encryption_key,
        keyring=dict(settings.master_encryption_keys) or None,
        active_key_version=settings.active_key_version,
    )
    try:
        seed_demo_data(database, PasswordService(), crypto, audit_key=key,
                       passphrase=password, sample_alerts=sample_alerts,
                       secure_retention_days=settings.secure_retention_days,
                       confidential_retention_days=settings.confidential_retention_days,
                       log=log)
        roles = dict(ALL_DEMO_USERS)
        details = {
            "source": "one_off_cli",
            "accounts": len(created),
            "admins": sum(roles[name] == "admin" for name in created),
            "sample_alerts": sample_alerts,
        }
        with database.session_factory() as db, db.begin():
            with append_lock(db):
                event = AuditEvent(
                    event_type="admin.demo_accounts_create",
                    outcome="success",
                    details_json=json.dumps(details, sort_keys=True),
                )
                seal_event(db, event, key)
                db.add(event)
                db.flush()
                event_id, entry_hash = event.id, event.entry_hash
    except SQLAlchemyError:
        # SQL exceptions can contain a URL, password hash or INSERT parameters.
        raise AdminProvisioningError("Database provisioning failed; check the app logs.") from None
    emit_security_event("admin.demo_accounts_create", audit_id=event_id,
                        entry_hash=entry_hash, details=details)
    return created


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description=__doc__)
    parser.add_argument("--with-sample-alerts", action="store_true",
                        help="Also add synthetic attack/audit events for the IDS dashboard.")
    arguments = parser.parse_args(argv)
    if not sys.stdin.isatty():
        print("Account creation requires an interactive terminal; passwords cannot be piped.", file=sys.stderr)
        return 1
    database = None
    try:
        settings = Settings.from_env()
        _profile_check(settings)
        if make_url(settings.database_url).get_backend_name() != "postgresql":
            raise AdminProvisioningError("This command requires the migrated PostgreSQL database.")
        print("Creates demo.user, demo.mod, demo.boss (admin) and lab.* with ONE private password.")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Password for all demo accounts: ")
            confirmation = getpass.getpass("Repeat password: ")
        if password != confirmation:
            raise AdminProvisioningError("The passwords did not match; nothing was created.")
        database = Database(settings.database_url, runtime_limits=True)
        configure_siem_logging(settings.siem_json_logs)
        created = seed_vps_accounts(settings, database, password=password,
                                    sample_alerts=arguments.with_sample_alerts)
        if created:
            print(f"Created {len(created)} accounts: {', '.join(created)}.")
            print("Sign in as demo.boss and enroll MFA: it is an administrator.")
        else:
            print("All demo accounts already exist; nothing was changed.")
        return 0
    except AdminProvisioningError as exc:
        print(f"Account creation refused: {exc}", file=sys.stderr)
    except (EOFError, KeyboardInterrupt):
        print("Account creation cancelled.", file=sys.stderr)
    except (getpass.GetPassWarning, OSError, RuntimeError, ValueError, SQLAlchemyError):
        # Keep arbitrary configuration/connection exception text out of output.
        print("Account creation failed. Check the production configuration and database access.", file=sys.stderr)
    finally:
        if database is not None:
            database.engine.dispose()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
