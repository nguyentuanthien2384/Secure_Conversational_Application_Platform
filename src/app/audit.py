from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import re
import time
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from src.app.audit_chain import append_lock, seal_event
from src.app.dlp import DLPScanner
from src.app.models import AuditEvent
from src.app.security import safe_json
from src.app.siem import emit_security_event

logger = logging.getLogger("secure_chat.audit")
_METADATA_DLP = DLPScanner()


def safe_user_agent(value: str) -> str | None:
    """Keep useful client metadata while removing common secrets and PII."""
    sanitized, _ = _METADATA_DLP.redact(value[:512])
    sanitized = sanitized.replace("\r", " ").replace("\n", " ").strip()[:256]
    return sanitized or None


# The Gradio UI runs in this process and calls the REST API over loopback, so
# without help every browser would share the UI's own address: one attacker
# could exhaust the per-IP login budget or trip an IDS block for all users.
# The UI therefore vouches for the browser it is serving with these headers.
UI_CLIENT_IP_HEADER = "X-SCAP-UI-Client-IP"
UI_CLIENT_UA_HEADER = "X-SCAP-UI-Client-UA"
UI_CLIENT_TS_HEADER = "X-SCAP-UI-Client-TS"
UI_CLIENT_PROOF_HEADER = "X-SCAP-UI-Client-Proof"
UI_CLIENT_MAX_SKEW_SECONDS = 60
_HEADER_UNSAFE = re.compile(r"[^\x20-\x7e]")
_UNSET = object()


def derive_ui_client_context_key(secret_key: str) -> bytes:
    """Derive the UI forwarding key from the app secret with domain separation.

    Every worker derives the same key, so the UI may reach any worker, while the
    label keeps it distinct from the JWT signing and audit-chain keys.
    """
    return hashlib.sha256(
        ("secure-chat:ui-client-context:v1:" + secret_key).encode("utf-8")
    ).digest()


def _ui_client_context_mac(key: bytes, timestamp: str, ip: str, user_agent: str) -> str:
    message = "\n".join(("v1", timestamp, ip, user_agent)).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def sign_ui_client_context(
    key: bytes, ip: str, user_agent: str, *, now: float | None = None
) -> dict[str, str]:
    """Return headers attributing an internal API call to the browser's address.

    Returns nothing for a malformed address so a broken context degrades to the
    loopback peer instead of inventing an identity.
    """
    try:
        ip = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return {}
    # HTTP header values must stay printable ASCII on the internal hop.
    user_agent = _HEADER_UNSAFE.sub("?", user_agent or "")[:512]
    timestamp = str(int(time.time() if now is None else now))
    return {
        UI_CLIENT_IP_HEADER: ip,
        UI_CLIENT_UA_HEADER: user_agent,
        UI_CLIENT_TS_HEADER: timestamp,
        UI_CLIENT_PROOF_HEADER: _ui_client_context_mac(key, timestamp, ip, user_agent),
    }


def _verified_ui_client_context(request: Request) -> tuple[str, str] | None:
    headers = request.headers
    proof = headers.get(UI_CLIENT_PROOF_HEADER)
    if not proof:
        return None
    try:
        key = getattr(request.app.state, "ui_client_context_key", None)
    except Exception:  # pragma: no cover - defensive; request may lack an app
        return None
    if not key:
        return None
    ip = headers.get(UI_CLIENT_IP_HEADER, "")
    user_agent = headers.get(UI_CLIENT_UA_HEADER, "")
    timestamp = headers.get(UI_CLIENT_TS_HEADER, "")
    if not timestamp.isdigit() or len(timestamp) > 12:
        return None
    if abs(time.time() - int(timestamp)) > UI_CLIENT_MAX_SKEW_SECONDS:
        return None
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    expected = _ui_client_context_mac(key, timestamp, ip, user_agent)
    if not hmac.compare_digest(proof.encode("ascii", "replace"), expected.encode("ascii")):
        return None
    return ip, user_agent


def trusted_ui_client_context(request: Request) -> tuple[str, str] | None:
    """Return the browser (ip, user-agent) the in-process UI vouched for, if any.

    Middleware and handlers share one ASGI scope, so the decision is cached:
    a long handler cannot see a different source than the IDS saw on entry.
    """
    cached = getattr(request.state, "scap_ui_client_context", _UNSET)
    if cached is _UNSET:
        cached = _verified_ui_client_context(request)
        request.state.scap_ui_client_context = cached
    return cached


def client_ip(request: Request) -> str:
    """Return the peer address, or the browser address vouched for by the UI.

    ``X-Forwarded-For`` is user-controlled unless a trusted reverse proxy strips it,
    so accepting it here would let clients evade rate limits and poison audit logs.
    Configure proxy-aware address handling at the deployment edge instead. The
    UI headers are different: they are accepted only with a fresh HMAC proof
    under a key that never leaves the server.
    """
    context = trusted_ui_client_context(request)
    if context is not None:
        return context[0][:64]
    return (request.client.host if request.client else "unknown")[:64]


def client_user_agent(request: Request) -> str:
    """Return the caller's User-Agent, preferring the browser behind the UI."""
    context = trusted_ui_client_context(request)
    if context is not None:
        return context[1]
    return request.headers.get("user-agent", "")


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
    user_agent = safe_user_agent(client_user_agent(request))
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
    checkpoint_service = getattr(request.app.state, "audit_checkpoint_service", None)
    if checkpoint_service is not None:
        try:
            checkpoint_service.maybe_anchor(db, event)
        except Exception:  # noqa: BLE001 - audit anchoring must not break requests
            logger.exception("Could not anchor the audit chain to the configured WORM sink.")
            emit_security_event(
                "audit.checkpoint.delivery_failed",
                outcome="failure",
                audit_id=event.id,
                entry_hash=event.entry_hash,
                request_id=request_id,
            )
    return event
