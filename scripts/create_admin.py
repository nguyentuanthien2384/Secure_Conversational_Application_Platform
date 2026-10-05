#!/usr/bin/env python3
"""Create a new administrator once, from an interactive production container.

The standard VPS profile keeps public demo accounts and bootstrap passwords
disabled. This operator-only command never starts the web server, migrates a
schema, changes an existing account, or accepts a password in argv/environment.
High-security deployments must use their audited provisioning/WORM workflow.
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

from src.app.audit_chain import (  # noqa: E402
    append_lock,
    derive_audit_key,
    seal_event,
    verify_chain,
)
from src.app.config import Settings  # noqa: E402
from src.app.db import Database  # noqa: E402
from src.app.models import AuditEvent, User  # noqa: E402
from src.app.schemas import RegisterRequest  # noqa: E402
from src.app.security import (  # noqa: E402
    PasswordBreachCheckUnavailable,
    PasswordService,
    PwnedPasswordChecker,
)
from src.app.siem import configure_siem_logging, emit_security_event  # noqa: E402


class AdminProvisioningError(RuntimeError):
    """A fixed, credential-free operator diagnostic."""


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # An accidental --password/value must not be echoed by argparse.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid arguments. Provide only --username NAME; passwords are entered interactively.\n")


def _profile_check(settings: Settings) -> None:
    if settings.environment != "production" or settings.security_profile != "standard":
        raise AdminProvisioningError("This command requires the standard production profile.")
    if not settings.audit_chain_enabled:
        raise AdminProvisioningError("Administrator provisioning requires the audit chain.")
    if len(settings.secret_key) < 32 or settings.secret_key == "development-only-change-me":
        raise AdminProvisioningError("Administrator provisioning requires a production app secret.")


def create_administrator(
    settings: Settings,
    database: Database,
    *,
    username: str,
    password: str,
) -> str:
    """Create a new admin and its sealed audit event in the same transaction.

The caller owns the database lifetime. Keeping it explicit also lets tests use
an isolated database without loading environment settings or the web app.
"""
    _profile_check(settings)
    try:
        payload = RegisterRequest(username=username, password=password)
    except ValidationError:
        # ValidationError includes input values by default, including passwords.
        raise AdminProvisioningError(
            "Use a valid username and a non-common password of 15 to 128 characters."
        ) from None
    try:
        with database.session_factory() as db:
            if db.scalar(select(User.id).where(User.username == payload.username)) is not None:
                raise AdminProvisioningError("That username already exists; no account was changed.")
    except SQLAlchemyError:
        raise AdminProvisioningError(
            "Cannot access the migrated database; no account was changed."
        ) from None

    checker = PwnedPasswordChecker(enabled=settings.password_breach_check)
    try:
        compromised = checker.is_compromised(payload.password)
    except PasswordBreachCheckUnavailable:
        raise AdminProvisioningError("Password breach screening is unavailable; try again later.") from None
    if compromised:
        raise AdminProvisioningError("That password appears in a public breach; choose another.")
    password_hash = PasswordService().hash(payload.password)
    key = derive_audit_key(settings.secret_key)
    try:
        with database.session_factory() as db, db.begin():
            with append_lock(db):
                # Recheck inside the transaction; the unique constraint also
                # rejects a concurrent insertion by another provisioning tool.
                if db.scalar(select(User.id).where(User.username == payload.username)) is not None:
                    raise AdminProvisioningError("That username already exists; no account was changed.")
                if not verify_chain(db, key).intact:
                    raise AdminProvisioningError(
                        "The existing audit chain is not intact; investigate before provisioning."
                    )
                user = User(username=payload.username, password_hash=password_hash, role="admin")
                db.add(user)
                db.flush()
                event = AuditEvent(
                    event_type="admin.bootstrap_create",
                    target_type="user",
                    target_id=user.id,
                    outcome="success",
                    details_json=json.dumps({"role": "admin", "source": "one_off_cli"}, sort_keys=True),
                )
                seal_event(db, event, key)
                db.add(event)
                db.flush()
                user_id, event_id, entry_hash = user.id, event.id, event.entry_hash
    except SQLAlchemyError:
        # SQL exceptions can contain a URL, password hash or INSERT parameters.
        raise AdminProvisioningError(
            "Database provisioning failed; no new administrator was committed."
        ) from None
    emit_security_event(
        "admin.bootstrap_create",
        target_type="user",
        target_id=user_id,
        audit_id=event_id,
        entry_hash=entry_hash,
        details={"role": "admin", "source": "one_off_cli"},
    )
    return user_id


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True, help="A NEW administrator username.")
    arguments = parser.parse_args(argv)
    if not sys.stdin.isatty():
        print("Admin creation requires an interactive terminal; passwords cannot be piped.", file=sys.stderr)
        return 1
    database = None
    try:
        # Load the container's configured production environment only after the
        # TTY check. This command is not part of local preparation/preflight.
        settings = Settings.from_env()
        _profile_check(settings)
        if make_url(settings.database_url).get_backend_name() != "postgresql":
            raise AdminProvisioningError("This command requires the migrated PostgreSQL database.")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("New administrator password: ")
            confirmation = getpass.getpass("Repeat password: ")
        if password != confirmation:
            raise AdminProvisioningError("The passwords did not match; no account was created.")
        database = Database(settings.database_url, runtime_limits=True)
        configure_siem_logging(settings.siem_json_logs)
        create_administrator(settings, database, username=arguments.username, password=password)
        print("Administrator created. Sign in and enroll MFA before administrative use.")
        return 0
    except AdminProvisioningError as exc:
        print(f"Admin creation refused: {exc}", file=sys.stderr)
    except (EOFError, KeyboardInterrupt):
        print("Admin creation cancelled.", file=sys.stderr)
    except (getpass.GetPassWarning, OSError, RuntimeError, ValueError, SQLAlchemyError):
        # Keep arbitrary configuration/connection exception text out of output.
        print("Admin creation failed. Check the production configuration and private database access.", file=sys.stderr)
    finally:
        if database is not None:
            database.engine.dispose()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
