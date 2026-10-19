#!/usr/bin/env python3
"""Create a new administrator once, from an interactive production container.

The standard VPS profile keeps public demo accounts and bootstrap passwords
disabled. This operator-only command never starts the web server, migrates a
schema, changes an existing account, or accepts a password in argv/environment.

In the high-security profile the command also follows the WORM workflow: it
refuses while the external sink is unreachable or an existing checkpoint no
longer matches the chain, and after the commit it anchors the sealed
``admin.bootstrap_create`` event before reporting success. Delivery happens
after the commit (never before: an anchor for a rolled-back event would look
like tampering), so a sink failure at that point exits with code 3 and leaves
the running application's readiness/maintenance loop to retry.
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
from src.app.audit_checkpoint import (  # noqa: E402
    AuditCheckpointError,
    AuditCheckpointIntegrityError,
    AuditCheckpointService,
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


class AdminAnchorPending(RuntimeError):
    """The administrator was committed, but its WORM checkpoint was not delivered."""

    def __init__(self, user_id: str) -> None:
        super().__init__(
            "Administrator created and its audit event sealed, but the WORM checkpoint "
            "was not delivered. The application retries automatically; use the account "
            "only after /api/admin/audit/verify reports high_assurance_intact=true."
        )
        self.user_id = user_id


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # An accidental --password/value must not be echoed by argparse.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid arguments. Provide only --username NAME; passwords are entered interactively.\n")


def _profile_check(settings: Settings, *, allow_high: bool = False) -> None:
    # Standard-only by default: scripts/seed_vps_accounts.py reuses this check
    # and must never seed demo accounts into a high-security deployment.
    profiles = {"standard", "high"} if allow_high else {"standard"}
    if settings.environment != "production" or settings.security_profile not in profiles:
        raise AdminProvisioningError(
            "This command requires a standard or high production profile."
            if allow_high
            else "This command requires the standard production profile."
        )
    if not settings.audit_chain_enabled:
        raise AdminProvisioningError("Administrator provisioning requires the audit chain.")
    if len(settings.secret_key) < 32 or settings.secret_key == "development-only-change-me":
        raise AdminProvisioningError("Administrator provisioning requires a production app secret.")
    if settings.security_profile == "high" and not settings.audit_worm_endpoint:
        raise AdminProvisioningError("High-security provisioning requires the external audit WORM sink.")


def checkpoint_service_for(settings: Settings) -> AuditCheckpointService | None:
    """Build the same checkpoint service the web application uses, or None."""
    if settings.security_profile != "high":
        return None
    return AuditCheckpointService(
        settings.secret_key,
        interval=settings.audit_checkpoint_interval,
        endpoint=settings.audit_worm_endpoint,
        token_file=settings.audit_worm_token_file,
        max_unanchored_events=settings.audit_max_unanchored_events,
        probe_interval_seconds=settings.audit_worm_probe_interval_seconds,
    )


def _require_anchored_history(database: Database, checkpoint_service: AuditCheckpointService) -> None:
    """Refuse before writing unless the existing tail is intact and deliverable."""
    try:
        with database.session_factory() as db:
            # A fresh service has never succeeded, so this also replays the
            # latest checkpoint once: an idle but unreachable sink is caught.
            verification = checkpoint_service.ensure_latest_anchored(db, probe_external=True)
    except AuditCheckpointIntegrityError:
        raise AdminProvisioningError(
            "The existing audit checkpoint does not match the audit chain; investigate before provisioning."
        ) from None
    except AuditCheckpointError:
        raise AdminProvisioningError(
            "The audit WORM sink is unavailable; no account was changed."
        ) from None
    except SQLAlchemyError:
        raise AdminProvisioningError(
            "Cannot access the migrated database; no account was changed."
        ) from None
    if verification.latest_event_id is not None and not verification.fully_anchored:
        raise AdminProvisioningError(
            "The existing audit tail is not fully anchored; no account was changed."
        )


def create_administrator(
    settings: Settings,
    database: Database,
    *,
    username: str,
    password: str,
    checkpoint_service: AuditCheckpointService | None = None,
) -> str:
    """Create a new admin and its sealed audit event in the same transaction.

The caller owns the database lifetime. Keeping it explicit also lets tests use
an isolated database without loading environment settings or the web app.
The high profile additionally needs ``checkpoint_service`` with a remote sink;
see the module docstring for the anchoring order and :class:`AdminAnchorPending`.
"""
    _profile_check(settings, allow_high=True)
    high = settings.security_profile == "high"
    if high and (checkpoint_service is None or not checkpoint_service.endpoint):
        raise AdminProvisioningError("High-security provisioning requires the external audit WORM sink.")
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
    if high:
        _require_anchored_history(database, checkpoint_service)

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
            # Take the username/index lock before the audit advisory lock,
            # matching account creation through the API. Otherwise concurrent
            # provisioning of one username can invert those two locks.
            if db.scalar(select(User.id).where(User.username == payload.username)) is not None:
                raise AdminProvisioningError("That username already exists; no account was changed.")
            user = User(username=payload.username, password_hash=password_hash, role="admin")
            db.add(user)
            db.flush()
            with append_lock(db):
                # A broken chain still rolls back the uncommitted account.
                if not verify_chain(db, key).intact:
                    raise AdminProvisioningError(
                        "The existing audit chain is not intact; investigate before provisioning."
                    )
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
    if high:
        try:
            with database.session_factory() as db:
                checkpoint = checkpoint_service.anchor(db)
                anchored = (
                    checkpoint is not None
                    and checkpoint.last_event_id >= event_id
                    and checkpoint.delivered_at is not None
                )
        except (AuditCheckpointError, SQLAlchemyError):
            anchored = False
        if not anchored:
            emit_security_event(
                "audit.checkpoint.delivery_failed",
                outcome="failure",
                audit_id=event_id,
                entry_hash=entry_hash,
            )
            raise AdminAnchorPending(user_id)
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
        _profile_check(settings, allow_high=True)
        if make_url(settings.database_url).get_backend_name() != "postgresql":
            raise AdminProvisioningError("This command requires the migrated PostgreSQL database.")
        # Validate the WORM endpoint/token mount before asking for a password.
        checkpoint_service = checkpoint_service_for(settings)
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("New administrator password: ")
            confirmation = getpass.getpass("Repeat password: ")
        if password != confirmation:
            raise AdminProvisioningError("The passwords did not match; no account was created.")
        database = Database(settings.database_url, runtime_limits=True)
        configure_siem_logging(settings.siem_json_logs)
        create_administrator(
            settings,
            database,
            username=arguments.username,
            password=password,
            checkpoint_service=checkpoint_service,
        )
        if checkpoint_service is not None:
            print("Administrator created; its audit event is anchored in the WORM sink.")
        else:
            print("Administrator created.")
        print("Sign in and enroll MFA before administrative use.")
        return 0
    except AdminAnchorPending as exc:
        print(str(exc), file=sys.stderr)
        return 3
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
