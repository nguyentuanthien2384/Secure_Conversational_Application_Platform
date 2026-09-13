"""Retention enforcement and cryptographic erasure for conversation data."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.app.db import utcnow
from src.app.models import (
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
    encrypted_messages: int = 0
    e2ee_envelopes: int = 0
    wrapped_deks_destroyed: int = 0
    expired_challenges: int = 0
    expired_tokens: int = 0
    stale_prekeys: int = 0
    dry_run: bool = False

    def as_dict(self) -> dict[str, int | bool]:
        return asdict(self)


def enforce_retention(
    db: Session,
    *,
    now: datetime | None = None,
    dry_run: bool = False,
    batch_size: int = 500,
) -> RetentionResult:
    """Delete expired conversations plus short-lived security artifacts.

    Removing a session also removes every wrapped conversation DEK. The
    ciphertext is therefore cryptographically unreadable from a data-only
    remnant. Backup lifecycle must be no longer than the declared retention
    period; this function cannot erase an independent database backup.
    """
    if batch_size < 1 or batch_size > 5_000:
        raise ValueError("Retention batch_size must be between 1 and 5000.")
    now = now or utcnow()
    sessions = list(
        db.scalars(
            select(ChatSession)
            .where(
                ChatSession.retention_expires_at.is_not(None),
                ChatSession.retention_expires_at <= now,
            )
            .order_by(ChatSession.retention_expires_at.asc())
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
        for item in stale_prekeys:
            db.delete(item)
        db.commit()
    return RetentionResult(
        expired_sessions=len(sessions),
        encrypted_messages=encrypted_messages,
        e2ee_envelopes=e2ee_envelopes,
        wrapped_deks_destroyed=wrapped_deks,
        expired_challenges=len(expired_challenges),
        expired_tokens=len(expired_tokens),
        stale_prekeys=len(stale_prekeys),
        dry_run=dry_run,
    )

