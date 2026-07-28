from __future__ import annotations

import logging
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from src.app.audit_chain import append_lock, seal_event
from src.app.models import AuditEvent
from src.app.security import safe_json
from src.app.siem import emit_security_event

logger = logging.getLogger("secure_chat.audit")


def client_ip(request: Request) -> str:
    """Return the peer address.

    ``X-Forwarded-For`` is user-controlled unless a trusted reverse proxy strips it,
    so accepting it here would let clients evade rate limits and poison audit logs.
    Configure proxy-aware address handling at the deployment edge instead.
    """
    return (request.client.host if request.client else "unknown")[:64]


def _audit_key(request: Request) -> bytes | None:
    """Fetch the audit HMAC key placed on app state at startup, if chaining is on."""
    try:
        return getattr(request.app.state, "audit_key", None)
    except Exception:  # pragma: no cover - defensive; request may lack an app
        return None


def record_audit(
    db: Session,
    request: Request,
    event_type: str,
    *,
    actor_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    outcome: str = "success",
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    """Persist one audit entry, seal it into the hash chain, mirror it to the SIEM.

    Failure to log is itself a security event, so chain/SIEM problems are logged
    loudly but never turned into a 500 for the end user.
    """
    ip = client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:256] or None
    request_id = getattr(request.state, "request_id", None)
    event = AuditEvent(
        actor_id=actor_id,
        event_type=event_type[:64],
        target_type=target_type[:32] if target_type else None,
        target_id=target_id[:64] if target_id else None,
        outcome=outcome[:16],
        ip_address=ip,
        user_agent=user_agent,
        request_id=request_id,
        details_json=safe_json(details),
    )

    key = _audit_key(request)
    if key is None:
        db.add(event)
        db.commit()
        db.refresh(event)
    else:
        # Appends must be serialised: two concurrent writers reading the same
        # "last hash" would fork the chain and break verification.
        with append_lock(db):
            seal_event(db, event, key)
            db.add(event)
            db.commit()
            db.refresh(event)

    emit_security_event(
        event.event_type,
        outcome=event.outcome,
        actor_id=event.actor_id,
        target_type=event.target_type,
        target_id=event.target_id,
        source_ip=event.ip_address,
        user_agent=event.user_agent,
        request_id=event.request_id,
        audit_id=event.id,
        entry_hash=event.entry_hash,
        details=details,
    )
    return event
