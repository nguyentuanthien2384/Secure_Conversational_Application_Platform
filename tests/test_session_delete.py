"""Permanent conversation deletion in isolated application test databases."""

from __future__ import annotations

from sqlalchemy import func, select

from src.app.models import (
    AuditEvent,
    ChatSession,
    ConversationMember,
    E2eeDevice,
    E2eeEnvelope,
    E2eePreKey,
    SecureMessage,
    SessionKeyEpoch,
    User,
)
from tests.conftest import register_and_login


def _create_session(client, headers, **payload):
    response = client.post("/api/sessions", headers=headers, json=payload)
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_delete_removes_messages_all_key_epochs_and_invalidates_export(client, app):
    token = register_and_login(client, "delete-encrypted-history")
    headers = {"Authorization": f"Bearer {token}"}
    deleted_id = _create_session(client, headers, title="Remove this conversation")
    preserved_id = _create_session(client, headers, title="Keep this conversation")
    removed_text = "Only the removed conversation contains this phrase"
    kept_text = "The preserved conversation is still accessible"

    for session_id, content in ((deleted_id, removed_text), (preserved_id, kept_text)):
        sent = client.post(
            f"/api/sessions/{session_id}/messages", headers=headers, json={"content": content}
        )
        assert sent.status_code == 201, sent.text

    crypto = app.state.envelope_crypto_service
    with app.state.database.session_factory() as db:
        row = db.get(ChatSession, deleted_id)
        crypto.rotate_session_dek(db, row)
        app.state.chat_service.store_message(db, deleted_id, "user", "Another encrypted epoch")
        db.commit()
        assert db.scalar(
            select(func.count()).select_from(SessionKeyEpoch).where(
                SessionKeyEpoch.session_id == deleted_id
            )
        ) == 2
    cached_key_buffers = [entry.value for entry in crypto._cache.values()]
    assert cached_key_buffers and any(any(buffer) for buffer in cached_key_buffers)

    ticket = client.post(f"/api/sessions/{deleted_id}/export-ticket", headers=headers)
    assert ticket.status_code == 200, ticket.text
    response = client.delete(f"/api/sessions/{deleted_id}", headers=headers)
    assert response.status_code == 204, response.text
    assert not crypto._cache
    assert all(not any(buffer) for buffer in cached_key_buffers)

    with app.state.database.session_factory() as db:
        assert db.get(ChatSession, deleted_id) is None
        for model in (SecureMessage, SessionKeyEpoch, ConversationMember, E2eeEnvelope):
            assert db.scalar(
                select(func.count()).select_from(model).where(model.session_id == deleted_id)
            ) == 0
        assert db.get(ChatSession, preserved_id) is not None
        audit = db.scalar(select(AuditEvent).where(
            AuditEvent.event_type == "chat.session.delete", AuditEvent.target_id == deleted_id
        ))
        assert audit is not None and audit.outcome == "success"
        assert removed_text not in audit.details_json

    for path in (
        f"/api/sessions/{deleted_id}",
        f"/api/sessions/{deleted_id}/messages",
        f"/api/sessions/{deleted_id}/ciphertexts",
        f"/api/sessions/{deleted_id}/export",
        ticket.json()["download_url"],
    ):
        assert client.get(path, headers=headers).status_code == 404
    remaining = client.get("/api/sessions", headers=headers)
    assert remaining.status_code == 200
    assert [row["id"] for row in remaining.json()] == [preserved_id]
    messages = client.get(f"/api/sessions/{preserved_id}/messages", headers=headers)
    assert messages.status_code == 200
    assert messages.json()[0]["content"] == kept_text


def test_delete_private_conversation_cascades_members_and_opaque_envelopes(client, app):
    token = register_and_login(client, "delete-private-owner")
    register_and_login(client, "delete-private-member")
    headers = {"Authorization": f"Bearer {token}"}
    session_id = _create_session(
        client, headers, title="Remove private conversation", security_mode="private_e2ee",
        data_classification="e2ee_private",
    )
    with app.state.database.session_factory() as db:
        owner = db.scalar(select(User).where(User.username == "delete-private-owner"))
        member = db.scalar(select(User).where(User.username == "delete-private-member"))
        # Seed opaque public-device/ciphertext fixtures directly: this test
        # exercises deletion and FK cascades, not the device proof protocol.
        device = E2eeDevice(
            user_id=owner.id, display_name="Synthetic device", identity_key_b64="aWRlbnRpdHk=",
            signed_prekey_b64="cHJla2V5", signed_prekey_signature_b64="c2lnbmF0dXJl",
            fingerprint="synthetic-delete-device", trust_state="trusted",
        )
        db.add(device)
        db.flush()
        device_id = device.id
        prekey = E2eePreKey(device_id=device_id, key_id="synthetic", public_key_b64="cHJla2V5")
        db.add(prekey)
        db.add(ConversationMember(session_id=session_id, user_id=member.id, joined_epoch=1))
        db.add(E2eeEnvelope(
            session_id=session_id, sender_user_id=owner.id, sender_device_id=device_id,
            protocol="double-ratchet-v1", client_message_id="synthetic-message",
            replay_key="synthetic-replay-key", header_b64="aGVhZGVy", ciphertext_b64="Y2lwaGVy",
        ))
        db.commit()
        prekey_id = prekey.id
        assert db.scalar(select(func.count()).select_from(ConversationMember).where(
            ConversationMember.session_id == session_id
        )) == 2
        assert db.scalar(select(func.count()).select_from(E2eeEnvelope).where(
            E2eeEnvelope.session_id == session_id
        )) == 1

    response = client.delete(f"/api/sessions/{session_id}", headers=headers)
    assert response.status_code == 204, response.text
    with app.state.database.session_factory() as db:
        assert db.get(ChatSession, session_id) is None
        for model in (ConversationMember, E2eeEnvelope):
            assert db.scalar(
                select(func.count()).select_from(model).where(model.session_id == session_id)
            ) == 0
        # Public device keys belong to the account and remain usable for its
        # other conversations; only this conversation's content is deleted.
        assert db.get(E2eeDevice, device_id) is not None
        assert db.get(E2eePreKey, prekey_id) is not None

