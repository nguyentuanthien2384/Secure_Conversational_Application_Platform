"""Reject malformed storage records before trying historic decryption paths."""

from __future__ import annotations

import base64
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select

from src.app.db import Database
from src.app.envelope import (
    ENVELOPE_SCHEME,
    LEGACY_SCHEME,
    EnvelopeCryptoService,
    EnvelopeEncryptionError,
    canonical_message_aad,
    canonical_secret_aad,
)
from src.app.key_management import LocalAesKeyProvider
from src.app.models import ChatSession, SecureMessage, SessionKeyEpoch, User
from src.app.security import CryptoService


@pytest.fixture()
def legacy():
    return CryptoService(base64.urlsafe_b64encode(b"L" * 32).decode("ascii"))


@pytest.fixture()
def stored_message(tmp_path, legacy):
    database = Database(f"sqlite:///{tmp_path / 'storage-validation.db'}")
    database.create_all()
    crypto = EnvelopeCryptoService(
        LocalAesKeyProvider({"1": b"K" * 32}, active_version="1"), legacy_crypto=legacy
    )
    try:
        with database.session_factory() as db:
            db.add(User(id="storage-owner", username="storage.owner", password_hash="test-only"))
            db.flush()
            session = ChatSession(id="original-session", owner_id="storage-owner", title="Original")
            other = ChatSession(id="different-session", owner_id="storage-owner", title="Other")
            db.add_all([session, other])
            db.flush()
            ciphertext, nonce, version = legacy.encrypt("historic text", session.id, "user")
            row = SecureMessage(
                session_id=session.id,
                role="user",
                message_uuid="historic-message",
                message_index=1,
                ciphertext=ciphertext,
                nonce=nonce,
                key_version=version,
                crypto_epoch=0,
                encryption_scheme=LEGACY_SCHEME,
            )
            db.add(row)
            db.flush()
            yield db, crypto, session, other, row
    finally:
        crypto.clear_cache()
        database.engine.dispose()


@pytest.mark.parametrize("operation", ["decrypt", "migrate"])
@pytest.mark.parametrize("scheme", ["envelope-v2", "legacy-v2", "", "LEGACY-V1"])
def test_unknown_schemes_never_fall_back_to_valid_legacy_ciphertext(
    stored_message, monkeypatch, operation, scheme
):
    db, crypto, session, _, row = stored_message
    row.encryption_scheme = scheme
    decrypt = Mock(side_effect=AssertionError("Unknown scheme reached legacy decryption"))
    monkeypatch.setattr(crypto.legacy_crypto, "decrypt", decrypt)
    original = (row.ciphertext, row.nonce, row.crypto_epoch)

    with pytest.raises(EnvelopeEncryptionError, match="scheme is unsupported"):
        if operation == "decrypt":
            crypto.decrypt_message(db, session, row)
        else:
            crypto.migrate_legacy_message(db, session, row)

    decrypt.assert_not_called()
    assert (row.ciphertext, row.nonce, row.crypto_epoch) == original
    assert db.scalar(select(SessionKeyEpoch)) is None


@pytest.mark.parametrize("operation", ["decrypt", "migrate"])
@pytest.mark.parametrize("scheme", [LEGACY_SCHEME, ENVELOPE_SCHEME])
def test_cross_session_rows_are_rejected_before_any_key_or_plaintext_access(
    stored_message, monkeypatch, operation, scheme
):
    db, crypto, _, other, row = stored_message
    row.encryption_scheme = scheme
    unwrap = Mock(side_effect=AssertionError("Wrong session reached a key operation"))
    decrypt = Mock(side_effect=AssertionError("Wrong session reached legacy decryption"))
    monkeypatch.setattr(crypto.provider, "unwrap_dek", unwrap)
    monkeypatch.setattr(crypto.legacy_crypto, "decrypt", decrypt)

    with pytest.raises(EnvelopeEncryptionError, match="supplied conversation"):
        if operation == "decrypt":
            crypto.decrypt_message(db, other, row)
        else:
            crypto.migrate_legacy_message(db, other, row)

    unwrap.assert_not_called()
    decrypt.assert_not_called()
    assert db.scalar(select(SessionKeyEpoch)) is None


def test_valid_historic_message_still_migrates_and_decrypts(stored_message):
    db, crypto, session, _, row = stored_message
    assert crypto.decrypt_message(db, session, row) == "historic text"
    assert crypto.migrate_legacy_message(db, session, row) is True
    assert row.encryption_scheme == ENVELOPE_SCHEME
    assert crypto.decrypt_message(db, session, row) == "historic text"
    assert crypto.migrate_legacy_message(db, session, row) is False


@pytest.mark.parametrize("operation", ["message", "account_secret"])
@pytest.mark.parametrize("field", ["ciphertext", "nonce"])
@pytest.mark.parametrize("extra", ["!", "\n", " ", "\x00"])
def test_legacy_base64_rejects_ignored_characters(legacy, operation, field, extra):
    if operation == "message":
        ciphertext, nonce, version = legacy.encrypt("authentic content", "session", "user")
    else:
        ciphertext, nonce = legacy.encrypt_secret("authentic content", "mfa:owner")
    if field == "ciphertext":
        ciphertext = ciphertext[:4] + extra + ciphertext[4:]
    else:
        nonce = nonce[:4] + extra + nonce[4:]

    with pytest.raises(ValueError, match="đã bị thay đổi"):
        if operation == "message":
            legacy.decrypt(ciphertext, nonce, "session", "user", version)
        else:
            legacy.decrypt_secret(ciphertext, nonce, "mfa:owner")


@pytest.mark.parametrize("operation", ["message", "account_secret"])
@pytest.mark.parametrize("nonce_length", [8, 16])
def test_legacy_rejects_authenticated_records_outside_its_96_bit_nonce_format(
    legacy, operation, nonce_length
):
    # These have valid GCM tags; accepting them would silently extend SCAP's
    # persisted format even though every original writer used 12-byte nonces.
    nonce = b"N" * nonce_length
    aad = (
        legacy._aad("session", "user", legacy.key_version)
        if operation == "message"
        else legacy._field_aad("mfa:owner", legacy.key_version)
    )
    ciphertext = base64.urlsafe_b64encode(
        legacy.aesgcm.encrypt(nonce, b"authenticated but unsupported nonce", aad)
    ).decode("ascii")
    encoded_nonce = base64.urlsafe_b64encode(nonce).decode("ascii")

    with pytest.raises(ValueError, match="đã bị thay đổi"):
        if operation == "message":
            legacy.decrypt(ciphertext, encoded_nonce, "session", "user", legacy.key_version)
        else:
            legacy.decrypt_secret(ciphertext, encoded_nonce, "mfa:owner")


@pytest.fixture(params=["message", "account_secret"])
def envelope_payload(stored_message, request):
    db, crypto, session, _, row = stored_message
    if request.param == "message":
        row.ciphertext, row.nonce, row.crypto_epoch = crypto.encrypt_message(
            db, session, plaintext="valid envelope", role=row.role,
            message_uuid=row.message_uuid, message_index=row.message_index,
        )
        row.encryption_scheme = ENVELOPE_SCHEME
        key = crypto._session_dek(db, session, row.crypto_epoch)
        aad = canonical_message_aad(
            owner_id=session.owner_id, session_id=session.id,
            message_uuid=row.message_uuid, message_index=row.message_index,
            role=row.role, crypto_epoch=row.crypto_epoch,
        )
        payload = {"ciphertext": row.ciphertext, "nonce": row.nonce}

        def decrypt():
            row.ciphertext, row.nonce = payload["ciphertext"], payload["nonce"]
            return crypto.decrypt_message(db, session, row)
    else:
        user = db.get(User, "storage-owner")
        ciphertext, nonce = crypto.encrypt_user_secret(
            user, plaintext="valid envelope", field="mfa:storage-owner"
        )
        key = crypto._user_dek(user)
        aad = canonical_secret_aad(
            user_id=user.id, field="mfa:storage-owner", crypto_epoch=user.secret_crypto_epoch
        )
        payload = {"ciphertext": ciphertext, "nonce": nonce}

        def decrypt():
            return crypto.decrypt_user_secret(
                user, ciphertext_b64=payload["ciphertext"], nonce_b64=payload["nonce"],
                field="mfa:storage-owner",
            )
    return crypto, payload, key, aad, decrypt


def test_normal_envelope_96_bit_nonce_roundtrip(envelope_payload):
    crypto, payload, _, _, decrypt = envelope_payload
    assert len(base64.urlsafe_b64decode(payload["nonce"])) == 12
    crypto.clear_cache()
    assert decrypt() == "valid envelope"


@pytest.mark.parametrize("nonce_length", [8, 16])
def test_envelope_rejects_authenticated_nonstandard_nonce_before_unwrap(
    envelope_payload, monkeypatch, nonce_length
):
    crypto, payload, key, aad, decrypt = envelope_payload
    nonce = b"N" * nonce_length
    ciphertext = AESGCM(key).encrypt(nonce, b"authentic but unsupported format", aad)
    # Establish that this is a cryptographically valid GCM record. It must
    # still fail SCAP's persisted format without reaching the key provider.
    assert AESGCM(key).decrypt(nonce, ciphertext, aad) == b"authentic but unsupported format"
    payload.update(
        nonce=base64.urlsafe_b64encode(nonce).decode("ascii"),
        ciphertext=base64.urlsafe_b64encode(ciphertext).decode("ascii"),
    )
    crypto.clear_cache()
    unwrap = Mock(side_effect=AssertionError("Malformed nonce reached the key provider"))
    monkeypatch.setattr(crypto.provider, "unwrap_dek", unwrap)

    with pytest.raises(EnvelopeEncryptionError, match="^Encrypted payload format is invalid\\.$"):
        decrypt()
    unwrap.assert_not_called()


@pytest.mark.parametrize("change", ["nonce_base64", "ciphertext_base64", "short_nonce", "short_tag"])
def test_malformed_envelope_payload_rejects_before_unwrap(envelope_payload, monkeypatch, change):
    crypto, payload, _, _, decrypt = envelope_payload
    if change == "nonce_base64":
        payload["nonce"] = "!" + payload["nonce"]
    elif change == "ciphertext_base64":
        payload["ciphertext"] = "!" + payload["ciphertext"]
    elif change == "short_nonce":
        payload["nonce"] = base64.urlsafe_b64encode(b"N" * 11).decode("ascii")
    else:
        payload["ciphertext"] = base64.urlsafe_b64encode(b"T" * 15).decode("ascii")
    crypto.clear_cache()
    unwrap = Mock(side_effect=AssertionError("Malformed payload reached the key provider"))
    monkeypatch.setattr(crypto.provider, "unwrap_dek", unwrap)

    with pytest.raises(EnvelopeEncryptionError, match="^Encrypted payload format is invalid\\.$"):
        decrypt()
    unwrap.assert_not_called()
