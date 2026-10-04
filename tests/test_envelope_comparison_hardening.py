from __future__ import annotations

from dataclasses import replace
from unittest.mock import Mock

import pytest
from sqlalchemy import select

from src.app.db import Database
from src.app.envelope import ENVELOPE_SCHEME, EnvelopeCryptoService, EnvelopeEncryptionError
from src.app.key_management import LocalAesKeyProvider
from src.app.models import ChatSession, SecureMessage, SessionKeyEpoch, User


@pytest.fixture()
def crypto():
    provider = LocalAesKeyProvider({"1": b"K" * 32}, active_version="1")
    service = EnvelopeCryptoService(provider)
    yield service
    service.clear_cache()


@pytest.fixture()
def envelope_db(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'envelope-cache.db'}")
    database.create_all()
    try:
        with database.session_factory() as db:
            yield db
    finally:
        database.engine.dispose()


def protected_conversation(db, crypto):
    db.add_all(
        [
            User(id="original-owner", username="original.owner", password_hash="test-only-hash"),
            User(id="other-owner", username="other.owner", password_hash="test-only-hash"),
        ]
    )
    db.flush()
    session = ChatSession(id="cache-conversation", owner_id="original-owner", title="Cache")
    db.add(session)
    db.flush()
    ciphertext, nonce, epoch = crypto.encrypt_message(
        db,
        session,
        plaintext="private conversation",
        role="user",
        message_uuid="cache-message",
        message_index=1,
    )
    message = SecureMessage(
        session_id=session.id,
        role="user",
        message_uuid="cache-message",
        message_index=1,
        ciphertext=ciphertext,
        nonce=nonce,
        crypto_epoch=epoch,
        encryption_scheme=ENVELOPE_SCHEME,
    )
    db.add(message)
    db.flush()
    return session, message


@pytest.mark.parametrize("changed_field", ["kek_uri", "kek_version", "owner_id"])
def test_warm_conversation_cache_does_not_bypass_metadata_authentication(
    crypto, envelope_db, changed_field
):
    session, message = protected_conversation(envelope_db, crypto)
    assert crypto.decrypt_message(envelope_db, session, message) == "private conversation"
    if changed_field == "owner_id":
        session.owner_id = "other-owner"
    else:
        epoch = envelope_db.scalar(
            select(SessionKeyEpoch).where(SessionKeyEpoch.session_id == session.id)
        )
        assert epoch is not None
        setattr(epoch, changed_field, "unrecognized-provider-metadata")
    envelope_db.commit()

    # Even a warm cache must revalidate changed key metadata/context before
    # touching message AAD; this is not a claim that changed owners could read it.
    with pytest.raises(EnvelopeEncryptionError, match="Unable to unwrap the conversation key"):
        crypto.decrypt_message(envelope_db, session, message)


@pytest.mark.parametrize("changed_field", ["secret_kek_uri", "secret_kek_version"])
def test_warm_account_cache_rejects_changed_provider_metadata(crypto, changed_field):
    user = User(id="account-owner", secret_crypto_epoch=0)
    ciphertext, nonce = crypto.encrypt_user_secret(user, plaintext="private seed", field="mfa")
    assert crypto.decrypt_user_secret(
        user, ciphertext_b64=ciphertext, nonce_b64=nonce, field="mfa"
    ) == "private seed"
    setattr(user, changed_field, "unrecognized-provider-metadata")

    with pytest.raises(EnvelopeEncryptionError, match="Unable to unwrap the account secret key"):
        crypto.decrypt_user_secret(user, ciphertext_b64=ciphertext, nonce_b64=nonce, field="mfa")


def test_unchanged_generated_and_unwrapped_keys_remain_cache_hits(crypto, envelope_db, monkeypatch):
    unwrap = Mock(wraps=crypto.provider.unwrap_dek)
    monkeypatch.setattr(crypto.provider, "unwrap_dek", unwrap)
    session, message = protected_conversation(envelope_db, crypto)
    user = User(id="account-owner", secret_crypto_epoch=0)
    ciphertext, nonce = crypto.encrypt_user_secret(user, plaintext="private seed", field="mfa")

    def read_both():
        assert crypto.decrypt_message(envelope_db, session, message) == "private conversation"
        assert crypto.decrypt_user_secret(
            user, ciphertext_b64=ciphertext, nonce_b64=nonce, field="mfa"
        ) == "private seed"

    read_both()
    read_both()
    assert unwrap.call_count == 0
    crypto.clear_cache()
    read_both()
    assert unwrap.call_count == 2
    read_both()
    assert unwrap.call_count == 2


def test_newly_rotated_conversation_key_uses_the_same_cache_identity(
    crypto, envelope_db, monkeypatch
):
    session, _ = protected_conversation(envelope_db, crypto)
    unwrap = Mock(wraps=crypto.provider.unwrap_dek)
    monkeypatch.setattr(crypto.provider, "unwrap_dek", unwrap)
    rotated = crypto.rotate_session_dek(envelope_db, session)
    _, _, epoch = crypto.encrypt_message(
        envelope_db,
        session,
        plaintext="after rotation",
        role="user",
        message_uuid="rotated-message",
        message_index=2,
    )
    assert epoch == rotated.epoch == 2
    assert unwrap.call_count == 0


@pytest.mark.parametrize("key_length", [16, 24])
@pytest.mark.parametrize("operation", ["generate", "unwrap"])
def test_account_secrets_reject_provider_keys_that_are_not_aes_256(
    crypto, monkeypatch, key_length, operation
):
    user = User(id="account-owner", secret_crypto_epoch=0)
    if operation == "generate":
        generate = crypto.provider.generate_wrapped_dek

        def invalid_generate(*, context):
            return replace(generate(context=context), plaintext_dek=b"X" * key_length)

        monkeypatch.setattr(crypto.provider, "generate_wrapped_dek", invalid_generate)
        with pytest.raises(EnvelopeEncryptionError, match="invalid DEK length"):
            crypto.encrypt_user_secret(user, plaintext="private seed", field="mfa")
    else:
        ciphertext, nonce = crypto.encrypt_user_secret(user, plaintext="private seed", field="mfa")
        crypto.clear_cache()
        monkeypatch.setattr(crypto.provider, "unwrap_dek", Mock(return_value=b"X" * key_length))
        with pytest.raises(EnvelopeEncryptionError, match="invalid DEK length"):
            crypto.decrypt_user_secret(user, ciphertext_b64=ciphertext, nonce_b64=nonce, field="mfa")
