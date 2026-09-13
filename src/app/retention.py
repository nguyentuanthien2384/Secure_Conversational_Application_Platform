"""Retention enforcement and cryptographic erasure for conversation data."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from src.app.db import utcnow
from src.app.models import (
    AuthSession,
    ChatSession,
    E2eeDeviceChallenge,
    E2eeEnvelope,
    E2eePreKey,
    RevokedToken,
    SecureMessage,
)


@dataclass(frozen=True)
class RetentionResult:
    expired_sessions: int = 0
    retention_deadlines_backfilled: int = 0
    encrypted_messages: int = 0
    e2ee_envelopes: int = 0
    wrapped_deks_destroyed: int = 0
    expired_challenges: int = 0
    expired_tokens: int = 0
    expired_auth_sessions: int = 0
    stale_prekeys: int = 0
    dry_run: bool = False

    def as_dict(self) -> dict[str, int | bool]:
        return asdict(self)


def _retention_deadline(
    chat_session: ChatSession,
    *,
    now: datetime,
    secure_retention_days: int,
    confidential_retention_days: int,
) -> datetime:
    """Derive a legacy row's deadline from creation time, never migration time.

    Any unexpected/unknown mode receives the shorter confidential period. This
    keeps a partially migrated or manually corrupted row on the fail-closed
    side of the policy.
    """
    retention_days = (
        secure_retention_days
        if chat_session.security_mode == "secure"
        else confidential_retention_days
    )
    return (chat_session.created_at or now) + timedelta(days=retention_days)


def _backfill_retention_deadlines(
    db: Session,
    *,
    now: datetime,
    secure_retention_days: int,
    confidential_retention_days: int,
    batch_size: int,
) -> int:
    """Backfill every legacy NULL deadline in bounded-memory batches.

    A keyset cursor makes the operation portable across SQLite and PostgreSQL
    and idempotent when a deployment or scheduled sweep is repeated.
    """
    backfilled = 0
    last_id: str | None = None
    while True:
        statement = (
            select(ChatSession)
            .where(ChatSession.retention_expires_at.is_(None))
            .order_by(ChatSession.id.asc())
            .limit(batch_size)
        )
        if last_id is not None:
            statement = statement.where(ChatSession.id > last_id)
        rows = list(db.scalars(statement))
        if not rows:
            break
        for row in rows:
            row.retention_expires_at = _retention_deadline(
                row,
                now=now,
                secure_retention_days=secure_retention_days,
                confidential_retention_days=confidential_retention_days,
            )
        db.flush()
        backfilled += len(rows)
        last_id = rows[-1].id
    return backfilled


def enforce_retention(
    db: Session,
    *,
    now: datetime | None = None,
    dry_run: bool = False,
    batch_size: int = 500,
    secure_retention_days: int = 90,
    confidential_retention_days: int = 7,
) -> RetentionResult:
    """Delete expired conversations plus short-lived security artifacts.

    Removing a session also removes every wrapped conversation DEK. The
    ciphertext is therefore cryptographically unreadable from a data-only
    remnant. Backup lifecycle must be no longer than the declared retention
    period; this function cannot erase an independent database backup.
    """
    if batch_size < 1 or batch_size > 5_000:
        raise ValueError("Retention batch_size must be between 1 and 5000.")
    if secure_retention_days < 1 or confidential_retention_days < 1:
        raise ValueError("Retention periods must be positive integers.")
    now = now or utcnow()

    # Older SCAP releases added this column as nullable, leaving existing rows
    # without an enforceable deadline. Derive the deadline from ``created_at``
    # (not from today's migration date) so an upgrade cannot silently extend
    # retention. A dry run computes the same policy without changing the rows.
    if dry_run:
        retention_deadlines_backfilled = int(
            db.scalar(
                select(func.count())
                .select_from(ChatSession)
                .where(ChatSession.retention_expires_at.is_(None))
            )
            or 0
        )
        legacy_expired = and_(
            ChatSession.retention_expires_at.is_(None),
            or_(
                and_(
                    ChatSession.security_mode == "secure",
                    ChatSession.created_at
                    <= now - timedelta(days=secure_retention_days),
                ),
                and_(
                    or_(
                        ChatSession.security_mode != "secure",
                        ChatSession.security_mode.is_(None),
                    ),
                    ChatSession.created_at
                    <= now - timedelta(days=confidential_retention_days),
                ),
            ),
        )
        expired_clause = or_(
            ChatSession.retention_expires_at <= now,
            legacy_expired,
        )
    else:
        retention_deadlines_backfilled = _backfill_retention_deadlines(
            db,
            now=now,
            secure_retention_days=secure_retention_days,
            confidential_retention_days=confidential_retention_days,
            batch_size=batch_size,
        )
        # The NULL arm catches a corrupt/concurrently inserted legacy row after
        # the backfill pass. Such a row has no provable retention permission and
        # is therefore erased instead of being retained indefinitely.
        expired_clause = or_(
            ChatSession.retention_expires_at.is_(None),
            ChatSession.retention_expires_at <= now,
        )

    sessions = list(
        db.scalars(
            select(ChatSession)
            .where(expired_clause)
            .order_by(ChatSession.retention_expires_at.asc(), ChatSession.id.asc())
            .limit(batch_size)
        )
    )
    session_ids = [item.id for item in sessions]
    encrypted_messages = 0
    e2ee_envelopes = 0
    wrapped_deks = 0
    if session_ids:
        encrypted_messages = int(
            db.scalar(
                select(func.count())
                .select_from(SecureMessage)
                .where(SecureMessage.session_id.in_(session_ids))
            )
            or 0
        )
        e2ee_envelopes = int(
            db.scalar(
                select(func.count())
                .select_from(E2eeEnvelope)
                .where(E2eeEnvelope.session_id.in_(session_ids))
            )
            or 0
        )
        wrapped_deks = sum(len(item.key_epochs) for item in sessions)

    expired_challenges = list(
        db.scalars(
            select(E2eeDeviceChallenge)
            .where(E2eeDeviceChallenge.expires_at <= now)
            .limit(batch_size)
        )
    )
    expired_tokens = list(
        db.scalars(
            select(RevokedToken).where(RevokedToken.expires_at <= now).limit(batch_size)
        )
    )
    # IP address and user-agent are useful only while a bearer session can still
    # be revoked or inspected. The immutable audit trail keeps the security
    # event; the operational session row should not become a shadow PII archive.
    expired_auth_sessions = list(
        db.scalars(
            select(AuthSession)
            .where(AuthSession.expires_at <= now)
            .order_by(AuthSession.expires_at.asc())
            .limit(batch_size)
        )
    )
    # Consumed public prekeys need no long-term retention. A 24-hour grace
    # period is deliberately omitted: delivery protocols already copied the
    # public key into the requesting client before this state was committed.
    stale_prekeys = list(
        db.scalars(
            select(E2eePreKey)
            .where(E2eePreKey.consumed_at.is_not(None))
            .limit(batch_size)
        )
    )
    if not dry_run:
        for item in sessions:
            db.delete(item)
        for item in expired_challenges:
            db.delete(item)
        for item in expired_tokens:
            db.delete(item)
        for item in expired_auth_sessions:
            db.delete(item)
        for item in stale_prekeys:
            db.delete(item)
        db.commit()
    return RetentionResult(
        expired_sessions=len(sessions),
        retention_deadlines_backfilled=retention_deadlines_backfilled,
        encrypted_messages=encrypted_messages,
        e2ee_envelopes=e2ee_envelopes,
        wrapped_deks_destroyed=wrapped_deks,
        expired_challenges=len(expired_challenges),
        expired_tokens=len(expired_tokens),
        expired_auth_sessions=len(expired_auth_sessions),
        stale_prekeys=len(stale_prekeys),
        dry_run=dry_run,
    )
