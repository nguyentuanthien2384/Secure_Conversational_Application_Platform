"""Legacy rotation must never mistake envelope epochs for KEK versions."""

from __future__ import annotations

import base64
import sys
from dataclasses import replace

import pytest
from sqlalchemy import select

from scripts import rotate_encryption_key as rotation
from scripts.rewrap_deks import build_service
from src.app.envelope import LEGACY_SCHEME
from src.app.models import ChatSession, SecureMessage, SessionKeyEpoch, User
from src.app.security import CryptoService
from tests.conftest import register_and_login


def rotated_settings(settings):
    return replace(settings, master_encryption_keys={
        1: settings.master_encryption_key,
        2: base64.urlsafe_b64encode(b"R" * 32).decode(),
    }, active_key_version=2)


def make_session(client, app):
    token = register_and_login(client, "legacy.rotation")
    response = client.post("/api/sessions", headers={"Authorization": f"Bearer {token}"},
                           json={"title": "Rotation review"})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_rotation_refuses_old_wrapped_dek_even_for_an_empty_conversation(
    client, app, settings, monkeypatch, capsys,
):
    session_id = make_session(client, app)
    updated = rotated_settings(settings)
    monkeypatch.setattr(rotation.Settings, "from_env", lambda: updated)
    monkeypatch.setattr(sys, "argv", ["rotation", "--to-version", "2"])
    assert rotation.main() == 1
    output = capsys.readouterr()
    assert "python -m scripts.rewrap_deks" in output.err
    assert "có thể gỡ" not in output.out
    with app.state.database.session_factory() as db:
        assert db.get(ChatSession, session_id).kek_version == "1"


@pytest.mark.parametrize("dependency", ["historical_epoch", "account_without_totp", "null_session_uri"])
def test_dependency_scan_covers_historical_account_and_incomplete_metadata(
    client, app, settings, dependency,
):
    session_id = make_session(client, app)
    service = build_service(rotated_settings(settings))
    with app.state.database.session_factory() as db:
        chat = db.get(ChatSession, session_id)
        if dependency == "historical_epoch":
            app.state.envelope_crypto_service.rotate_session_dek(db, chat)
            service.rewrap_session_keys(db, chat)
            old = db.scalar(select(SessionKeyEpoch).where(SessionKeyEpoch.session_id == chat.id,
                                                           SessionKeyEpoch.epoch == 1))
            old.kek_version = "1"
        else:
            service.rewrap_session_keys(db, chat)
            if dependency == "account_without_totp":
                user = db.get(User, chat.owner_id)
                app.state.envelope_crypto_service.ensure_user_key(user)
                assert user.mfa_secret_ciphertext is None
            else:
                chat.kek_uri = None
        db.commit()
        assert rotation.unrotated_envelope_dependencies(db, 2) > 0


def test_rewrap_then_legacy_rotation_preserves_envelope_ciphertext_and_supports_only_new_key(
    client, app, settings,
):
    session_id = make_session(client, app)
    updated = rotated_settings(settings)
    legacy = CryptoService(keyring=updated.master_encryption_keys, active_key_version=2)
    old = CryptoService(settings.master_encryption_key)
    service = build_service(updated)
    with app.state.database.session_factory() as db:
        chat = db.get(ChatSession, session_id)
        envelope = app.state.chat_service.store_message(db, chat.id, "user", "envelope text")
        original_ciphertext = envelope.ciphertext
        ciphertext, nonce, version = old.encrypt("legacy text", chat.id, "user")
        previous = SecureMessage(session_id=chat.id, role="user", message_index=2,
                                  ciphertext=ciphertext, nonce=nonce, key_version=version,
                                  encryption_scheme=LEGACY_SCHEME)
        db.add(previous)
        user = db.get(User, chat.owner_id)
        user.mfa_secret_ciphertext, user.mfa_secret_nonce = (
            app.state.envelope_crypto_service.encrypt_user_secret(
                user, plaintext="totp seed", field=f"mfa:{user.id}",
            )
        )
        db.commit()
        service.rewrap_session_keys(db, chat)
        service.rewrap_user_key(user)
        db.commit()
        assert rotation.unrotated_envelope_dependencies(db, 2) == 0
        assert rotation.rotate_messages(db, legacy, 2, 200, False) == (1, 0)
        assert rotation.rotate_mfa_secrets(db, legacy, False) == (0, 0)
        assert envelope.ciphertext == original_ciphertext
        only_new = replace(updated, master_encryption_key="",
                           master_encryption_keys={2: updated.master_encryption_keys[2]})
        fresh = build_service(only_new)
        assert fresh.decrypt_message(db, chat, envelope) == "envelope text"
        assert fresh.decrypt_message(db, chat, previous) == "legacy text"
        assert fresh.decrypt_user_secret(user, ciphertext_b64=user.mfa_secret_ciphertext,
                                         nonce_b64=user.mfa_secret_nonce,
                                         field=f"mfa:{user.id}") == "totp seed"


def test_legacy_rotation_rejects_an_unbounded_or_zero_batch(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["rotation", "--batch", "0"])
    with pytest.raises(SystemExit) as error:
        rotation.main()
    assert error.value.code == 2
