"""Per-conversation envelope encryption with canonical, message-bound AAD."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.app.db import utcnow
from src.app.key_management import KeyProvider, KeyProviderError
from src.app.models import ChatSession, SecureMessage, SessionKeyEpoch, User
from src.app.security import CryptoService

ENVELOPE_SCHEME = "envelope-v1"
LEGACY_SCHEME = "legacy-v1"
CRYPTO_SUITE = "AES-256-GCM"


class EnvelopeEncryptionError(RuntimeError):
    """Safe error for storage/provider failures; never includes key material."""


def canonical_message_aad(
    *,
    owner_id: str,
    session_id: str,
    message_uuid: str,
    message_index: int,
    role: str,
    crypto_epoch: int,
) -> bytes:
    document = {
        "format": "scap-message-aad-v1",
        "tenant_id": "default",
        "owner_id": owner_id,
        "session_id": session_id,
        "message_id": message_uuid,
        "message_index": message_index,
        "role": role,
        "crypto_epoch": crypto_epoch,
    }
    return json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_secret_aad(*, user_id: str, field: str, crypto_epoch: int) -> bytes:
    document = {
        "format": "scap-user-secret-aad-v1",
        "tenant_id": "default",
        "user_id": user_id,
        "field": field,
        "crypto_epoch": crypto_epoch,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def session_key_context(session: ChatSession, epoch: int) -> dict[str, str]:
    return {
        "tenant_id": "default",
        "owner_id": session.owner_id,
        "session_id": session.id,
        "crypto_epoch": str(epoch),
    }


def user_key_context(user: User, epoch: int) -> dict[str, str]:
    return {
        "tenant_id": "default",
        "user_id": user.id,
        "purpose": "account-secrets",
        "crypto_epoch": str(epoch),
    }


def _decode(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise EnvelopeEncryptionError(f"{label} is not valid base64.") from exc


@dataclass
class _CachedDek:
    value: bytearray
    expires_at: float

    def clear(self) -> None:
        for index in range(len(self.value)):
            self.value[index] = 0


class EnvelopeCryptoService:
    """Encrypt messages with short-lived, provider-unwrapped per-session DEKs."""

    def __init__(
        self,
        provider: KeyProvider,
        *,
        legacy_crypto: CryptoService | None = None,
        cache_ttl_seconds: int = 60,
        max_cache_entries: int = 512,
    ) -> None:
        if cache_ttl_seconds < 0 or max_cache_entries < 1:
            raise ValueError("DEK cache settings are invalid.")
        self.provider = provider
        self.legacy_crypto = legacy_crypto
        self.cache_ttl_seconds = cache_ttl_seconds
        self.max_cache_entries = max_cache_entries
        self._cache: dict[str, _CachedDek] = {}
        self._cache_lock = threading.RLock()

    @staticmethod
    def _session_cache_key(session_id: str, epoch: int, wrapped_dek: str) -> str:
        # The wrapped value is not secret and differentiates a rewrapped epoch.
        wrapped_digest = hashlib.sha256(wrapped_dek.encode("utf-8")).hexdigest()
        return f"session:{session_id}:{epoch}:{wrapped_digest}"

    @staticmethod
    def _user_cache_key(user_id: str, epoch: int, wrapped_dek: str) -> str:
        wrapped_digest = hashlib.sha256(wrapped_dek.encode("utf-8")).hexdigest()
        return f"user:{user_id}:{epoch}:{wrapped_digest}"

    def _cache_get(self, key: str) -> bytes | None:
        now = time.monotonic()
        with self._cache_lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if entry.expires_at <= now:
                entry.clear()
                self._cache.pop(key, None)
                return None
            return bytes(entry.value)

    def _cache_put(self, key: str, dek: bytes) -> None:
        if self.cache_ttl_seconds == 0:
            return
        with self._cache_lock:
            if len(self._cache) >= self.max_cache_entries:
                victim_key = min(self._cache, key=lambda item: self._cache[item].expires_at)
                self._cache.pop(victim_key).clear()
            previous = self._cache.pop(key, None)
            if previous is not None:
                previous.clear()
            self._cache[key] = _CachedDek(
                value=bytearray(dek),
                expires_at=time.monotonic() + self.cache_ttl_seconds,
            )

    def clear_cache(self) -> None:
        with self._cache_lock:
            for entry in self._cache.values():
                entry.clear()
            self._cache.clear()

    def ensure_session_key(self, db: Session, session: ChatSession) -> SessionKeyEpoch:
        if session.security_mode == "private_e2ee":
            raise EnvelopeEncryptionError("Private E2EE sessions cannot have server-side DEKs.")
        if session.current_crypto_epoch > 0:
            existing = db.scalar(
                select(SessionKeyEpoch).where(
                    SessionKeyEpoch.session_id == session.id,
                    SessionKeyEpoch.epoch == session.current_crypto_epoch,
                )
            )
            if existing is not None:
                return existing

        epoch = max(session.current_crypto_epoch, 0) + 1
        try:
            generated = self.provider.generate_wrapped_dek(
                context=session_key_context(session, epoch)
            )
        except (KeyProviderError, ValueError) as exc:
            raise EnvelopeEncryptionError("Unable to create a protected conversation key.") from exc
        row = SessionKeyEpoch(
            session_id=session.id,
            epoch=epoch,
            wrapped_dek=generated.wrapped_dek,
            kek_uri=generated.kek_uri,
            kek_version=generated.kek_version,
            crypto_suite=CRYPTO_SUITE,
        )
        db.add(row)
        session.current_crypto_epoch = epoch
        session.crypto_suite = CRYPTO_SUITE
        session.wrapped_dek = generated.wrapped_dek
        session.kek_uri = generated.kek_uri
        session.kek_version = generated.kek_version
        self._cache_put(
            self._session_cache_key(session.id, epoch, generated.wrapped_dek),
            generated.plaintext_dek,
        )
        db.flush()
        return row

    def _epoch_row(self, db: Session, session: ChatSession, epoch: int) -> SessionKeyEpoch:
        row = db.scalar(
            select(SessionKeyEpoch).where(
                SessionKeyEpoch.session_id == session.id,
                SessionKeyEpoch.epoch == epoch,
            )
        )
        if row is None:
            raise EnvelopeEncryptionError("Conversation key epoch is unavailable.")
        return row

    def _session_dek(self, db: Session, session: ChatSession, epoch: int) -> bytes:
        epoch_row = self._epoch_row(db, session, epoch)
        cache_key = self._session_cache_key(session.id, epoch, epoch_row.wrapped_dek)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        try:
            dek = self.provider.unwrap_dek(
                epoch_row.wrapped_dek,
                context=session_key_context(session, epoch),
                kek_uri=epoch_row.kek_uri,
                kek_version=epoch_row.kek_version,
            )
        except (KeyProviderError, ValueError) as exc:
            raise EnvelopeEncryptionError("Unable to unwrap the conversation key.") from exc
        if len(dek) != 32:
            raise EnvelopeEncryptionError("Key provider returned an invalid conversation key.")
        self._cache_put(cache_key, dek)
        return dek

    @staticmethod
    def next_message_index(db: Session, session_id: str) -> int:
        current = db.scalar(
            select(func.max(SecureMessage.message_index)).where(
                SecureMessage.session_id == session_id
            )
        )
        return int(current or 0) + 1

    def encrypt_message(
        self,
        db: Session,
        session: ChatSession,
        *,
        plaintext: str,
        role: str,
        message_uuid: str,
        message_index: int,
    ) -> tuple[str, str, int]:
        epoch_row = self.ensure_session_key(db, session)
        dek = self._session_dek(db, session, epoch_row.epoch)
        nonce = secrets.token_bytes(12)
        aad = canonical_message_aad(
            owner_id=session.owner_id,
            session_id=session.id,
            message_uuid=message_uuid,
            message_index=message_index,
            role=role,
            crypto_epoch=epoch_row.epoch,
        )
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), aad)
        return (
            base64.urlsafe_b64encode(ciphertext).decode("ascii"),
            base64.urlsafe_b64encode(nonce).decode("ascii"),
            epoch_row.epoch,
        )

    def decrypt_message(self, db: Session, session: ChatSession, row: SecureMessage) -> str:
        if row.encryption_scheme != ENVELOPE_SCHEME:
            if self.legacy_crypto is None:
                raise EnvelopeEncryptionError("Legacy key material is unavailable.")
            return self.legacy_crypto.decrypt(
                row.ciphertext,
                row.nonce,
                row.session_id,
                row.role,
                row.key_version,
            )
        dek = self._session_dek(db, session, row.crypto_epoch)
        aad = canonical_message_aad(
            owner_id=session.owner_id,
            session_id=row.session_id,
            message_uuid=row.message_uuid,
            message_index=row.message_index,
            role=row.role,
            crypto_epoch=row.crypto_epoch,
        )
        try:
            plaintext = AESGCM(dek).decrypt(
                _decode(row.nonce, "Message nonce"),
                _decode(row.ciphertext, "Message ciphertext"),
                aad,
            )
            return plaintext.decode("utf-8")
        except (InvalidTag, ValueError, UnicodeDecodeError) as exc:
            raise EnvelopeEncryptionError("Encrypted message authentication failed.") from exc

    def migrate_legacy_message(
        self,
        db: Session,
        session: ChatSession,
        row: SecureMessage,
    ) -> bool:
        """Rewrite one legacy row with a conversation DEK and message-bound AAD."""
        if row.encryption_scheme == ENVELOPE_SCHEME:
            return False
        if self.legacy_crypto is None:
            raise EnvelopeEncryptionError("Legacy key material is unavailable for migration.")
        plaintext = self.legacy_crypto.decrypt(
            row.ciphertext,
            row.nonce,
            row.session_id,
            row.role,
            row.key_version,
        )
        try:
            ciphertext, nonce, epoch = self.encrypt_message(
                db,
                session,
                plaintext=plaintext,
                role=row.role,
                message_uuid=row.message_uuid,
                message_index=row.message_index,
            )
            row.ciphertext = ciphertext
            row.nonce = nonce
            row.key_version = epoch
            row.crypto_epoch = epoch
            row.encryption_scheme = ENVELOPE_SCHEME
        finally:
            del plaintext
        return True

    def rotate_session_dek(self, db: Session, session: ChatSession) -> SessionKeyEpoch:
        if session.current_crypto_epoch > 0:
            current = self._epoch_row(db, session, session.current_crypto_epoch)
            current.retired_at = utcnow()
        epoch = session.current_crypto_epoch + 1
        try:
            generated = self.provider.generate_wrapped_dek(
                context=session_key_context(session, epoch)
            )
        except (KeyProviderError, ValueError) as exc:
            raise EnvelopeEncryptionError("Unable to rotate the conversation key.") from exc
        row = SessionKeyEpoch(
            session_id=session.id,
            epoch=epoch,
            wrapped_dek=generated.wrapped_dek,
            kek_uri=generated.kek_uri,
            kek_version=generated.kek_version,
            crypto_suite=CRYPTO_SUITE,
        )
        db.add(row)
        session.current_crypto_epoch = epoch
        session.crypto_suite = CRYPTO_SUITE
        session.wrapped_dek = generated.wrapped_dek
        session.kek_uri = generated.kek_uri
        session.kek_version = generated.kek_version
        self._cache_put(
            self._session_cache_key(session.id, epoch, generated.wrapped_dek),
            generated.plaintext_dek,
        )
        db.flush()
        return row

    def rewrap_session_keys(self, db: Session, session: ChatSession) -> int:
        rows = list(
            db.scalars(
                select(SessionKeyEpoch)
                .where(SessionKeyEpoch.session_id == session.id)
                .order_by(SessionKeyEpoch.epoch)
            )
        )
        for row in rows:
            try:
                wrapped = self.provider.rewrap_dek(
                    row.wrapped_dek,
                    context=session_key_context(session, row.epoch),
                    kek_uri=row.kek_uri,
                    kek_version=row.kek_version,
                )
            except (KeyProviderError, ValueError) as exc:
                raise EnvelopeEncryptionError("Unable to rewrap a conversation key.") from exc
            row.wrapped_dek = wrapped.wrapped_dek
            row.kek_uri = wrapped.kek_uri
            row.kek_version = wrapped.kek_version
            if row.epoch == session.current_crypto_epoch:
                session.wrapped_dek = wrapped.wrapped_dek
                session.kek_uri = wrapped.kek_uri
                session.kek_version = wrapped.kek_version
        self.clear_cache()
        return len(rows)

    def _user_dek(self, user: User) -> bytes:
        if (
            not user.secret_wrapped_dek
            or not user.secret_kek_uri
            or not user.secret_kek_version
            or user.secret_crypto_epoch <= 0
        ):
            raise EnvelopeEncryptionError("Protected account key metadata is unavailable.")
        cache_key = self._user_cache_key(user.id, user.secret_crypto_epoch, user.secret_wrapped_dek)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        try:
            dek = self.provider.unwrap_dek(
                user.secret_wrapped_dek,
                context=user_key_context(user, user.secret_crypto_epoch),
                kek_uri=user.secret_kek_uri,
                kek_version=user.secret_kek_version,
            )
        except (KeyProviderError, ValueError) as exc:
            raise EnvelopeEncryptionError("Unable to unwrap the account secret key.") from exc
        self._cache_put(cache_key, dek)
        return dek

    def ensure_user_key(self, user: User) -> None:
        if user.secret_wrapped_dek:
            return
        epoch = 1
        try:
            generated = self.provider.generate_wrapped_dek(context=user_key_context(user, epoch))
        except (KeyProviderError, ValueError) as exc:
            raise EnvelopeEncryptionError("Unable to create a protected account key.") from exc
        user.secret_crypto_epoch = epoch
        user.secret_wrapped_dek = generated.wrapped_dek
        user.secret_kek_uri = generated.kek_uri
        user.secret_kek_version = generated.kek_version
        self._cache_put(
            self._user_cache_key(user.id, epoch, generated.wrapped_dek),
            generated.plaintext_dek,
        )

    def rewrap_user_key(self, user: User) -> bool:
        """Rewrap one account-secret DEK without exposing or rewriting secrets."""
        if (
            not user.secret_wrapped_dek
            or not user.secret_kek_uri
            or not user.secret_kek_version
            or user.secret_crypto_epoch <= 0
        ):
            return False
        try:
            wrapped = self.provider.rewrap_dek(
                user.secret_wrapped_dek,
                context=user_key_context(user, user.secret_crypto_epoch),
                kek_uri=user.secret_kek_uri,
                kek_version=user.secret_kek_version,
            )
        except (KeyProviderError, ValueError) as exc:
            raise EnvelopeEncryptionError("Unable to rewrap an account key.") from exc
        user.secret_wrapped_dek = wrapped.wrapped_dek
        user.secret_kek_uri = wrapped.kek_uri
        user.secret_kek_version = wrapped.kek_version
        self.clear_cache()
        return True

    def encrypt_user_secret(self, user: User, *, plaintext: str, field: str) -> tuple[str, str]:
        self.ensure_user_key(user)
        dek = self._user_dek(user)
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(dek).encrypt(
            nonce,
            plaintext.encode("utf-8"),
            canonical_secret_aad(
                user_id=user.id,
                field=field,
                crypto_epoch=user.secret_crypto_epoch,
            ),
        )
        return (
            base64.urlsafe_b64encode(ciphertext).decode("ascii"),
            base64.urlsafe_b64encode(nonce).decode("ascii"),
        )

    def decrypt_user_secret(
        self,
        user: User,
        *,
        ciphertext_b64: str,
        nonce_b64: str,
        field: str,
    ) -> str:
        # Historic records without envelope metadata remain readable only while
        # an explicitly configured legacy key is available.
        if not user.secret_wrapped_dek:
            if self.legacy_crypto is None:
                raise EnvelopeEncryptionError("Legacy account key material is unavailable.")
            return self.legacy_crypto.decrypt_secret(
                ciphertext_b64,
                nonce_b64,
                context=field,
            )
        dek = self._user_dek(user)
        try:
            plaintext = AESGCM(dek).decrypt(
                _decode(nonce_b64, "Secret nonce"),
                _decode(ciphertext_b64, "Secret ciphertext"),
                canonical_secret_aad(
                    user_id=user.id,
                    field=field,
                    crypto_epoch=user.secret_crypto_epoch,
                ),
            )
            return plaintext.decode("utf-8")
        except (InvalidTag, ValueError, UnicodeDecodeError) as exc:
            raise EnvelopeEncryptionError(
                "Encrypted account secret authentication failed."
            ) from exc
