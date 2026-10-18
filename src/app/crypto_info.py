"""Construct an owner-visible crypto summary from public metadata and counts.

This module deliberately has no database, provider or cryptographic service
dependency. Looking at a format label is not authentication of the ciphertext.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from src.app.schemas import CryptoMessageCounts, SessionCryptoInfoResponse

PUBLIC_KEY_PROVIDERS = frozenset({"local", "vault", "aws-kms", "gcp-kms"})
ENVELOPE_AAD_FIELDS = (
    "format",
    "tenant_id",
    "owner_id",
    "session_id",
    "message_id",
    "message_index",
    "role",
    "crypto_epoch",
)
LEGACY_AAD_FIELDS = ("session_id", "role", "key_version")


@dataclass(frozen=True)
class CryptoRecordCounts:
    server_total: int = 0
    envelope: int = 0
    legacy: int = 0
    e2ee_total: int = 0
    double_ratchet: int = 0
    mls: int = 0

    def validate(self) -> None:
        values = (
            self.server_total,
            self.envelope,
            self.legacy,
            self.e2ee_total,
            self.double_ratchet,
            self.mls,
        )
        if any(type(value) is not int or value < 0 for value in values):
            raise ValueError("Invalid ciphertext record counts.")
        if self.envelope + self.legacy > self.server_total:
            raise ValueError("Invalid ciphertext record counts.")
        if self.double_ratchet + self.mls > self.e2ee_total:
            raise ValueError("Invalid ciphertext record counts.")


def build_crypto_info(
    *,
    session_id: str,
    security_mode: str,
    current_crypto_epoch: int,
    key_provider: str,
    counts: CryptoRecordCounts,
) -> SessionCryptoInfoResponse:
    """Describe supported formats, never return user/database/provider secrets.

    Counts refer to persisted records: one E2EE application message can have
    separate envelopes for different recipients. Unknown formats remain a
    separate count and must not be presented as verified AES or E2EE records.
    """
    if key_provider not in PUBLIC_KEY_PROVIDERS:
        raise ValueError("Unsupported key provider type.")
    if security_mode not in {"secure", "confidential", "private_e2ee"}:
        raise ValueError("Unsupported conversation security mode.")
    counts.validate()
    private = security_mode == "private_e2ee"
    known_e2ee = counts.double_ratchet + counts.mls
    unknown = (
        counts.server_total - counts.envelope - counts.legacy
        + counts.e2ee_total - known_e2ee
    )
    notes = [
        "metadata_only_integrity_not_verified",
        "counts_are_stored_records",
        "client_verifies_e2ee_ciphertexts" if private
        else "server_can_decrypt_authorized_messages",
    ]
    if counts.legacy:
        notes.append("legacy_messages_have_reduced_aad_binding")
    if unknown:
        notes.append("unsupported_storage_format_present")
    if (private and counts.server_total) or (not private and counts.e2ee_total):
        notes.append("unexpected_ciphertext_storage_for_session_mode")
    return SessionCryptoInfoResponse(
        session_id=session_id,
        security_mode=cast(Literal["secure", "confidential", "private_e2ee"], security_mode),
        algorithm="client-controlled-e2ee" if private else "AES-256-GCM",
        key_bits=None if private else 256,
        nonce_bits=None if private else 96,
        tag_bits=None if private else 128,
        current_crypto_epoch=current_crypto_epoch,
        key_provider=None if private else cast(
            Literal["local", "vault", "aws-kms", "gcp-kms"], key_provider
        ),
        message_counts=CryptoMessageCounts(
            total=counts.server_total + counts.e2ee_total,
            envelope=counts.envelope,
            legacy=counts.legacy,
            e2ee=known_e2ee,
            unknown=unknown,
        ),
        e2ee_protocol_counts={
            "double-ratchet": counts.double_ratchet,
            "mls-rfc9420": counts.mls,
        },
        aad_fields=[] if private else list(ENVELOPE_AAD_FIELDS),
        legacy_aad_fields=list(LEGACY_AAD_FIELDS) if counts.legacy else [],
        notes=notes,
    )
