"""Passkeys (WebAuthn / FIDO2): phishing-resistant, passwordless sign-in.

The browser's authenticator signs a server challenge together with the page
origin, so a credential created for this site cannot be replayed by a look-alike
domain — the property that makes passkeys resist phishing, unlike passwords and
TOTP codes. Verification (CBOR, COSE keys, signatures) is delegated to the
maintained ``py_webauthn`` library; this module adds the server-side policy:

* user verification (PIN/biometric) is required, so a passkey sign-in counts
  as two factors and needs no TOTP afterwards;
* every challenge is random, short-lived and consumed atomically before any
  verification, so a ceremony can be attempted only once;
* only the origins and RP ID configured for this deployment are accepted;
* a sign counter that goes backwards signals a cloned authenticator.

Only public keys and counters are stored; private keys never leave the device.
"""

from __future__ import annotations

import json
import secrets
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select, update
from sqlalchemy.orm import Session
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from src.app.models import WebAuthnChallenge, WebAuthnCredential

CHALLENGE_SECONDS = 180
MAX_PASSKEYS_PER_USER = 10
MAX_CREDENTIAL_JSON_BYTES = 16_384
_TRANSPORTS = {item.value for item in AuthenticatorTransport}


class PasskeyError(ValueError):
    """A ceremony failed; ``reason`` is a fixed code safe for audit details."""

    def __init__(self, reason: str, user_id: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        # Set once the credential is known, so failures reach the owner's log.
        self.user_id = user_id


def validate_webauthn_config(rp_id: str, origins: tuple[str, ...]) -> None:
    """Fail at startup instead of at the first ceremony.

    The RP ID must be a domain (browsers reject IP addresses) and every origin
    must be that domain or a subdomain, over HTTPS except for ``localhost``.
    """
    if not rp_id or rp_id != rp_id.strip().lower() or "/" in rp_id or ":" in rp_id:
        raise RuntimeError("WEBAUTHN_RP_ID phải là tên miền chữ thường, không có scheme/port.")
    if all(part.isdigit() for part in rp_id.split(".")):
        raise RuntimeError("WEBAUTHN_RP_ID không được là địa chỉ IP (trình duyệt sẽ từ chối).")
    if not origins:
        raise RuntimeError("WEBAUTHN_ORIGINS cần ít nhất một origin.")
    for origin in origins:
        parts = urlsplit(origin)
        host = parts.hostname or ""
        if parts.scheme not in {"https", "http"} or parts.path not in {"", "/"} or not host:
            raise RuntimeError(f"WEBAUTHN_ORIGINS không hợp lệ: {origin!r}.")
        if host != rp_id and not host.endswith("." + rp_id):
            raise RuntimeError(f"Origin {origin!r} không thuộc RP ID {rp_id!r}.")
        if parts.scheme == "http" and host != "localhost":
            raise RuntimeError("Passkey qua HTTP chỉ được phép với localhost.")


def clean_passkey_name(value: str | None, fallback: str) -> str:
    text = unicodedata.normalize("NFC", (value or "").strip())
    text = "".join(ch for ch in text if unicodedata.category(ch)[0] != "C")
    return (text or fallback)[:64]


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _parse_credential(credential: Any) -> dict[str, Any]:
    if isinstance(credential, str):
        if len(credential.encode("utf-8")) > MAX_CREDENTIAL_JSON_BYTES:
            raise PasskeyError("credential_too_large")
        try:
            credential = json.loads(credential)
        except ValueError as exc:
            raise PasskeyError("malformed_credential") from exc
    if not isinstance(credential, dict):
        raise PasskeyError("malformed_credential")
    if len(json.dumps(credential)) > MAX_CREDENTIAL_JSON_BYTES:
        raise PasskeyError("credential_too_large")
    return credential


@dataclass(frozen=True)
class CeremonyOptions:
    challenge_id: str
    public_key: dict[str, Any]


class PasskeyService:
    def __init__(self, rp_id: str, rp_name: str, origins: tuple[str, ...]) -> None:
        validate_webauthn_config(rp_id, origins)
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origins = list(origins)

    # ── challenges ──────────────────────────────────────────────────────────

    def _new_challenge(self, db: Session, purpose: str, user_id: str | None, now: datetime) -> tuple[str, bytes]:
        challenge = secrets.token_bytes(32)
        row = WebAuthnChallenge(
            user_id=user_id,
            purpose=purpose,
            challenge=bytes_to_base64url(challenge),
            expires_at=now + timedelta(seconds=CHALLENGE_SECONDS),
        )
        db.add(row)
        db.flush()
        return row.id, challenge

    def _consume_challenge(
        self, db: Session, challenge_id: str, purpose: str, user_id: str | None, now: datetime
    ) -> bytes:
        row = db.get(WebAuthnChallenge, challenge_id) if isinstance(challenge_id, str) else None
        if row is None or row.purpose != purpose or row.user_id != user_id:
            raise PasskeyError("unknown_challenge")
        consumed = db.execute(
            update(WebAuthnChallenge)
            .where(
                WebAuthnChallenge.id == challenge_id,
                WebAuthnChallenge.consumed_at.is_(None),
                WebAuthnChallenge.expires_at > now,
            )
            .values(consumed_at=now)
            .execution_options(synchronize_session=False)
        )
        if consumed.rowcount != 1:
            raise PasskeyError("challenge_expired_or_used")
        return base64url_to_bytes(row.challenge)

    # ── registration ────────────────────────────────────────────────────────

    def registration_options(
        self, db: Session, *, user_id: str, username: str, now: datetime
    ) -> CeremonyOptions:
        existing = list(db.scalars(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user_id)))
        if len(existing) >= MAX_PASSKEYS_PER_USER:
            raise PasskeyError("too_many_passkeys")
        challenge_id, challenge = self._new_challenge(db, "register", user_id, now)
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            # The user handle is the opaque account UUID, not a name or email.
            user_id=user_id.encode("ascii"),
            user_name=username,
            user_display_name=username,
            challenge=challenge,
            timeout=CHALLENGE_SECONDS * 1000,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(item.credential_id))
                for item in existing
            ],
        )
        return CeremonyOptions(challenge_id, json.loads(options_to_json(options)))

    def verify_registration(
        self,
        db: Session,
        *,
        user_id: str,
        challenge_id: str,
        credential: Any,
        name: str,
        now: datetime,
    ) -> WebAuthnCredential:
        challenge = self._consume_challenge(db, challenge_id, "register", user_id, now)
        payload = _parse_credential(credential)
        try:
            verified = verify_registration_response(
                credential=payload,
                expected_challenge=challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origins,
                require_user_verification=True,
            )
        except (WebAuthnException, ValueError, KeyError, TypeError) as exc:
            raise PasskeyError("registration_rejected") from exc
        credential_id = bytes_to_base64url(verified.credential_id)
        if db.scalar(
            select(WebAuthnCredential.id).where(WebAuthnCredential.credential_id == credential_id)
        ):
            raise PasskeyError("credential_already_registered")
        transports = payload.get("response", {}).get("transports") or []
        row = WebAuthnCredential(
            user_id=user_id,
            credential_id=credential_id,
            public_key=bytes_to_base64url(verified.credential_public_key),
            sign_count=verified.sign_count,
            transports=",".join(
                item for item in transports if isinstance(item, str) and item in _TRANSPORTS
            )[:128],
            aaguid=str(verified.aaguid)[:36],
            name=name,
            backed_up=bool(verified.credential_backed_up),
            created_at=now,
        )
        db.add(row)
        db.flush()
        return row

    # ── authentication ──────────────────────────────────────────────────────

    def authentication_options(self, db: Session, *, now: datetime) -> CeremonyOptions:
        """Usernameless: the browser offers this site's discoverable passkeys.

        No account name is requested, so the options never reveal whether an
        account or passkey exists.
        """
        challenge_id, challenge = self._new_challenge(db, "authenticate", None, now)
        options = generate_authentication_options(
            rp_id=self.rp_id,
            challenge=challenge,
            timeout=CHALLENGE_SECONDS * 1000,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return CeremonyOptions(challenge_id, json.loads(options_to_json(options)))

    def verify_authentication(
        self, db: Session, *, challenge_id: str, credential: Any, now: datetime
    ) -> WebAuthnCredential:
        challenge = self._consume_challenge(db, challenge_id, "authenticate", None, now)
        payload = _parse_credential(credential)
        raw_id = payload.get("rawId") or payload.get("id")
        if not isinstance(raw_id, str) or len(raw_id) > 1400:
            raise PasskeyError("malformed_credential")
        stored = db.scalar(select(WebAuthnCredential).where(WebAuthnCredential.credential_id == raw_id))
        if stored is None:
            raise PasskeyError("unknown_credential")
        user_handle = payload.get("response", {}).get("userHandle")
        if user_handle:
            try:
                handle_matches = base64url_to_bytes(user_handle) == stored.user_id.encode("ascii")
            except (ValueError, TypeError):
                handle_matches = False
            if not handle_matches:
                raise PasskeyError("user_handle_mismatch", stored.user_id)
        try:
            verified = verify_authentication_response(
                credential=payload,
                expected_challenge=challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origins,
                credential_public_key=base64url_to_bytes(stored.public_key),
                credential_current_sign_count=stored.sign_count,
                require_user_verification=True,
            )
        except (WebAuthnException, ValueError, KeyError, TypeError) as exc:
            # py_webauthn rejects a counter that did not increase; that is the
            # standard signal of a cloned authenticator.
            reason = "sign_count_regression" if "sign count" in str(exc).lower() else "assertion_rejected"
            raise PasskeyError(reason, stored.user_id) from exc
        stored.sign_count = verified.new_sign_count
        stored.backed_up = bool(verified.credential_backed_up)
        stored.last_used_at = now
        return stored


def passkey_view(row: WebAuthnCredential) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "created_at": _as_utc(row.created_at),
        "last_used_at": _as_utc(row.last_used_at) if row.last_used_at else None,
        "backed_up": row.backed_up,
        "transports": [item for item in row.transports.split(",") if item],
    }
