from __future__ import annotations

import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from src.app.envelope import ENVELOPE_SCHEME, EnvelopeEncryptionError
from src.app.models import (
    AuditCheckpoint,
    AuditEvent,
    AuthSession,
    ChatSession,
    SecureMessage,
    SessionKeyEpoch,
    User,
)
from src.app.retention import enforce_retention
from tests.conftest import register_and_login


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_message_bound_aad_rejects_same_role_ciphertext_swap(client: TestClient, app):
    token = register_and_login(client, "aad-swap")
    session_id = client.post("/api/sessions", headers=auth(token), json={"title": "AAD"}).json()[
        "id"
    ]
    with app.state.database.session_factory() as db:
        first = app.state.chat_service.store_message(db, session_id, "user", "first secret")
        second = app.state.chat_service.store_message(db, session_id, "user", "second secret")
        first.ciphertext, second.ciphertext = second.ciphertext, first.ciphertext
        first.nonce, second.nonce = second.nonce, first.nonce
        db.commit()
        chat_session = db.get(ChatSession, session_id)
        assert chat_session is not None
        with pytest.raises(EnvelopeEncryptionError, match="authentication failed"):
            app.state.chat_service.list_messages(db, chat_session)


def test_conversations_have_distinct_wrapped_deks_and_rewrap_without_reencrypt(
    client: TestClient, app
):
    token = register_and_login(client, "dek-isolation")
    first_id = client.post("/api/sessions", headers=auth(token), json={"title": "One"}).json()["id"]
    second_id = client.post("/api/sessions", headers=auth(token), json={"title": "Two"}).json()[
        "id"
    ]
    with app.state.database.session_factory() as db:
        first = db.get(ChatSession, first_id)
        second = db.get(ChatSession, second_id)
        assert first is not None and second is not None
        assert first.wrapped_dek and second.wrapped_dek
        assert first.wrapped_dek != second.wrapped_dek
        message = app.state.chat_service.store_message(db, first.id, "user", "rewrap me")
        old_ciphertext = message.ciphertext
        old_wrapped = first.wrapped_dek
        count = app.state.envelope_crypto_service.rewrap_session_keys(db, first)
        db.commit()
        assert count == 1
        assert first.wrapped_dek != old_wrapped
        assert message.ciphertext == old_ciphertext
        assert app.state.envelope_crypto_service.decrypt_message(db, first, message) == "rewrap me"


def test_manual_audit_checkpoint_detects_checkpoint_tampering(client: TestClient, app):
    token = register_and_login(client, "anchor-admin")
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "anchor-admin"))
        assert user is not None
        user.role = "admin"
        db.commit()

    checkpoint = client.post("/api/admin/audit/checkpoint", headers=auth(token))
    assert checkpoint.status_code == 200, checkpoint.text
    with app.state.database.session_factory() as db:
        row = db.get(AuditCheckpoint, checkpoint.json()["checkpoint_id"])
        assert row is not None
        row.root_hash = "f" * 64
        db.commit()

    verification = client.get("/api/admin/audit/verify", headers=auth(token))
    assert verification.status_code == 200
    assert verification.json()["chain_intact"] is True
    assert verification.json()["checkpoint_intact"] is False
    assert verification.json()["high_assurance_intact"] is False


def test_retention_deletes_ciphertext_and_wrapped_dek(client: TestClient, app):
    token = register_and_login(client, "retention-user")
    session_id = client.post(
        "/api/sessions", headers=auth(token), json={"title": "Expired"}
    ).json()["id"]
    client.post(
        f"/api/sessions/{session_id}/messages",
        headers=auth(token),
        json={"content": "ephemeral"},
    )
    with app.state.database.session_factory() as db:
        chat_session = db.get(ChatSession, session_id)
        assert chat_session is not None
        chat_session.retention_expires_at = chat_session.created_at - timedelta(seconds=1)
        db.commit()
        result = enforce_retention(db)
        assert result.expired_sessions == 1
        assert result.encrypted_messages == 2
        assert result.wrapped_deks_destroyed == 1
        assert db.get(ChatSession, session_id) is None
        assert not list(
            db.scalars(select(SecureMessage).where(SecureMessage.session_id == session_id))
        )
        assert not list(
            db.scalars(select(SessionKeyEpoch).where(SessionKeyEpoch.session_id == session_id))
        )


def test_expired_session_is_hidden_and_purged_on_direct_access(client: TestClient, app):
    token = register_and_login(client, "retention-on-access")
    session_id = client.post(
        "/api/sessions", headers=auth(token), json={"title": "Short lived"}
    ).json()["id"]
    with app.state.database.session_factory() as db:
        chat_session = db.get(ChatSession, session_id)
        assert chat_session is not None
        chat_session.retention_expires_at = chat_session.created_at - timedelta(seconds=1)
        db.commit()

    listed = client.get("/api/sessions", headers=auth(token))
    assert listed.status_code == 200
    assert session_id not in {item["id"] for item in listed.json()}
    assert client.get(f"/api/sessions/{session_id}", headers=auth(token)).status_code == 404

    with app.state.database.session_factory() as db:
        assert db.get(ChatSession, session_id) is None


def test_retention_prunes_expired_login_session_metadata(client: TestClient, app):
    register_and_login(client, "expired-auth-metadata")
    with app.state.database.session_factory() as db:
        auth_session = db.scalar(select(AuthSession))
        assert auth_session is not None
        auth_session.expires_at = auth_session.issued_at - timedelta(seconds=1)
        jti = auth_session.jti
        db.commit()

        result = enforce_retention(db)
        assert result.expired_auth_sessions == 1
        assert db.get(AuthSession, jti) is None


def test_new_messages_use_envelope_scheme(client: TestClient, app):
    token = register_and_login(client, "envelope-row")
    session_id = client.post(
        "/api/sessions", headers=auth(token), json={"title": "Envelope"}
    ).json()["id"]
    client.post(
        f"/api/sessions/{session_id}/messages",
        headers=auth(token),
        json={"content": "encrypted"},
    )
    with app.state.database.session_factory() as db:
        rows = list(db.scalars(select(SecureMessage).where(SecureMessage.session_id == session_id)))
        assert rows and all(row.encryption_scheme == ENVELOPE_SCHEME for row in rows)


def test_sensitive_values_are_rejected_from_plaintext_session_metadata(client: TestClient, app):
    token = register_and_login(client, "metadata-dlp")
    rejected = client.post(
        "/api/sessions",
        headers=auth(token),
        json={"title": "Liên hệ alice@example.com"},
    )
    assert rejected.status_code == 422
    assert rejected.json()["detail"]["code"] == "sensitive_metadata"

    created = client.post("/api/sessions", headers=auth(token), json={"title": "Safe title"})
    session_id = created.json()["id"]
    renamed = client.patch(
        f"/api/sessions/{session_id}",
        headers=auth(token),
        json={"title": "Another safe title"},
    )
    assert renamed.status_code == 200
    with app.state.database.session_factory() as db:
        event = db.scalar(
            select(AuditEvent)
            .where(AuditEvent.event_type == "chat.session.rename")
            .order_by(AuditEvent.id.desc())
        )
        assert event is not None
        details = json.loads(event.details_json)
        assert details == {"title_length": len("Another safe title")}
        assert "Another safe title" not in event.details_json


def test_consent_can_be_renewed_after_policy_version_changes(client: TestClient, app, settings):
    token = register_and_login(client, "renew-consent")
    first = client.patch(
        "/api/auth/ai-consent",
        headers=auth(token),
        json={"ai_data_consent": True},
    )
    assert first.status_code == 200
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "renew-consent"))
        assert user is not None
        user.ai_consent_version = "obsolete-policy"
        old_timestamp = user.ai_consent_at
        db.commit()

    renewed = client.patch(
        "/api/auth/ai-consent",
        headers=auth(token),
        json={"ai_data_consent": True},
    )
    assert renewed.status_code == 200
    assert renewed.json()["ai_consent_version"] == settings.ai_consent_version
    assert renewed.json()["ai_consent_at"] != old_timestamp.isoformat()


def test_sqlite_enforces_declared_foreign_keys(app):
    with app.state.database.engine.connect() as connection:
        assert connection.scalar(text("PRAGMA foreign_keys")) == 1
