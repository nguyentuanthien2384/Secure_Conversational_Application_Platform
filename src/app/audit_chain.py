"""Tamper-evident audit trail (Bài 1 §A.A.A/Accounting, Bài 4 §Audit, Bài 8).

An audit table that an attacker with database access can silently edit is
evidence of nothing. The classic control is a *hash chain*: every entry commits
to the entry before it, so deleting or rewriting a row breaks every hash that
follows and the tampering becomes detectable.

Implementation:

    entry_hash = HMAC-SHA256( audit_hmac_key, prev_hash || canonical(entry) )

The HMAC key is derived from ``APP_SECRET_KEY`` with a separate label, so it is
distinct from the JWT signing key (key separation). Because the key is *not*
stored in the database, an attacker who only has SQL access cannot recompute a
valid chain after editing a row — they can delete, but not forge.

Limits worth stating in the report (honest scope):
- The key lives in the same process, so full host compromise still allows
  forgery. Real deployments ship each entry to append-only/WORM storage or a
  remote SIEM, which this project does via ``siem.py``.
- Serialisation of appends is enforced with a mutex plus a row lock, which is
  correct for a single instance; multi-writer Postgres should use the advisory
  lock shown in ``append_event``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.app.models import AuditEvent

GENESIS_HASH = "0" * 64
_LOCK = threading.Lock()
_ADVISORY_LOCK_ID = 0x5343_4150  # "SCAP"


def derive_audit_key(secret_key: str) -> bytes:
    """Derive the audit HMAC key from the app secret with domain separation."""
    return hashlib.sha256(("secure-chat:audit-chain:v1:" + secret_key).encode("utf-8")).digest()


def canonical_entry(
    *,
    actor_id: str | None,
    event_type: str,
    target_type: str | None,
    target_id: str | None,
    outcome: str,
    ip_address: str | None,
    user_agent: str | None,
    request_id: str | None,
    details_json: str,
    created_at: str,
) -> str:
    """Deterministic serialisation of the fields covered by the signature.

    Sorted keys and a fixed separator matter: if two nodes serialise the same
    entry differently, verification fails for reasons that are not tampering.
    """
    return json.dumps(
        {
            "actor_id": actor_id,
            "event_type": event_type,
            "target_type": target_type,
            "target_id": target_id,
            "outcome": outcome,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "request_id": request_id,
            "details_json": details_json,
            "created_at": created_at,
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def compute_hash(key: bytes, prev_hash: str, canonical: str) -> str:
    return hmac.new(key, (prev_hash + "|" + canonical).encode("utf-8"), hashlib.sha256).hexdigest()


def canonical_datetime(value: datetime | None) -> str:
    """Normalize database-specific datetime forms to one signed UTC form.

    SQLite drops timezone metadata while PostgreSQL preserves it. Signing the
    raw ``isoformat`` value would therefore make an intact row fail verification
    after a SQLite round trip.
    """
    if value is None:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def entry_canonical(event: AuditEvent) -> str:
    return canonical_entry(
        actor_id=event.actor_id,
        event_type=event.event_type,
        target_type=event.target_type,
        target_id=event.target_id,
        outcome=event.outcome,
        ip_address=event.ip_address,
        user_agent=event.user_agent,
        request_id=event.request_id,
        details_json=event.details_json,
        created_at=canonical_datetime(event.created_at),
    )


def _last_hash(db: Session, before_id: int | None = None) -> str:
    """Hash of the entry immediately preceding ``before_id``.

    ``before_id`` remains available for repair/migration utilities. Normal
    application writes call this before the new row is inserted.
    """
    stmt = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)
    if before_id is not None:
        stmt = (
            select(AuditEvent)
            .where(AuditEvent.id < before_id)
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
    last = db.scalar(stmt)
    if last is None:
        return GENESIS_HASH
    # A NULL entry_hash means a pre-upgrade row; ``verify_chain`` restarts the
    # chain at those, so sealing must restart there too or the two disagree.
    return last.entry_hash or GENESIS_HASH


def seal_event(db: Session, event: AuditEvent, key: bytes) -> AuditEvent:
    """Seal a new event before it is inserted.

    Hashing before ``INSERT`` is intentional. The production runtime role has
    append-only access to ``audit_events`` and therefore cannot issue the
    post-insert ``UPDATE`` that an earlier implementation required.
    """
    if event.id is not None:
        raise ValueError("seal_event chỉ nhận bản ghi audit mới, chưa được INSERT.")
    if event.created_at is None:
        event.created_at = datetime.now(timezone.utc)
    prev = _last_hash(db)
    event.prev_hash = prev
    event.entry_hash = compute_hash(key, prev, entry_canonical(event))
    return event


def append_lock(db: Session):
    """Serialise appends. Postgres gets a transaction-scoped advisory lock."""
    dialect = db.get_bind().dialect.name if db.get_bind() is not None else ""
    if dialect == "postgresql":
        from sqlalchemy import text

        db.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": _ADVISORY_LOCK_ID})
        return _NullContext()
    return _LOCK


class _NullContext:
    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


@dataclass(frozen=True)
class ChainVerification:
    """Result of walking the whole chain."""

    total: int
    verified: int
    intact: bool
    first_broken_id: int | None = None
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "total_events": self.total,
            "verified_events": self.verified,
            "chain_intact": self.intact,
            "first_broken_id": self.first_broken_id,
            "reason": self.reason,
        }


def verify_chain(db: Session, key: bytes, *, limit: int | None = None) -> ChainVerification:
    """Recompute every link and report the first entry that does not match.

    A mismatch means one of: a row was edited, a row was deleted from the middle,
    rows were reordered, or the HMAC key changed. All four are worth an alert.
    """
    # A long-lived SQLAlchemy session can otherwise return stale identity-map
    # objects after an out-of-band SQL edit, producing a false "intact" result.
    db.expire_all()
    stmt = (
        select(AuditEvent).execution_options(populate_existing=True).order_by(AuditEvent.id.asc())
    )
    if limit is not None:
        stmt = stmt.limit(limit)
    prev = GENESIS_HASH
    total = 0
    verified = 0
    for event in db.scalars(stmt):
        total += 1
        if event.entry_hash is None:
            # Pre-upgrade rows have no hash; treat them as the chain start.
            prev = GENESIS_HASH
            continue
        if event.prev_hash != prev:
            return ChainVerification(total, verified, False, event.id, "prev_hash_mismatch")
        expected = compute_hash(key, prev, entry_canonical(event))
        if not hmac.compare_digest(expected, event.entry_hash):
            return ChainVerification(total, verified, False, event.id, "entry_hash_mismatch")
        verified += 1
        prev = event.entry_hash
    return ChainVerification(total, verified, True)
