from __future__ import annotations

import json
import uuid
from dataclasses import replace
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, select

from src.app.crypto_info import (
    ENVELOPE_AAD_FIELDS,
    LEGACY_AAD_FIELDS,
    CryptoRecordCounts,
    build_crypto_info,
)
from src.app.db import utcnow
from src.app.e2ee import PROTOCOL_DOUBLE_RATCHET, PROTOCOL_MLS
from src.app.main import create_app
from src.app.models import AuthSession, ChatSession, E2eeDevice, E2eeEnvelope, SecureMessage, User
from tests.conftest import register_and_login


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_session(client: TestClient, token: str, mode: str = "secure") -> str:
    response = client.post(
        "/api/sessions",
        headers=auth(token),
        json={"title": "Crypto info", "security_mode": mode},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def add_server_record(db, session_id: str, scheme: str, index: int) -> None:
    # Invalid/opaque bytes are deliberate: metadata must never deserialize or
    # authenticate payloads and must not advertise a successful verification.
    db.add(SecureMessage(
        session_id=session_id,
        role="user",
        message_uuid=str(uuid.uuid4()),
        message_index=index,
        ciphertext="ciphertext-must-not-be-returned",
        nonce="nonce-must-not-be-returned",
        key_version=4321,
        crypto_epoch=1,
        encryption_scheme=scheme,
    ))


def add_e2ee_records(db, session: ChatSession, protocols: list[str]) -> None:
    device_id = str(uuid.uuid4())
    db.add(E2eeDevice(
        id=device_id,
        user_id=session.owner_id,
        display_name="Metadata test device",
        identity_key_b64="public-material-not-requested",
        signed_prekey_b64="prekey-not-requested",
        signed_prekey_signature_b64="signature-not-requested",
        fingerprint=str(uuid.uuid4()),
        trust_state="trusted",
    ))
    db.flush()
    for protocol in protocols:
        db.add(E2eeEnvelope(
            session_id=session.id,
            sender_user_id=session.owner_id,
            sender_device_id=device_id,
            recipient_device_id=None,
            protocol=protocol,
            client_message_id=str(uuid.uuid4()),
            replay_key=str(uuid.uuid4()),
            header_b64="opaque-header-must-not-be-returned",
            ciphertext_b64="opaque-e2ee-ciphertext-must-not-be-returned",
            group_epoch=session.current_crypto_epoch,
        ))


@pytest.mark.parametrize("provider", ["local", "vault", "aws-kms", "gcp-kms"])
def test_summary_accepts_only_public_provider_names(provider):
    result = build_crypto_info(
        session_id="session-id",
        security_mode="secure",
        current_crypto_epoch=3,
        key_provider=provider,
        counts=CryptoRecordCounts(),
    )
    assert result.key_provider == provider
    assert (result.key_bits, result.nonce_bits, result.tag_bits) == (256, 96, 128)
    assert result.integrity_verification == "not_performed"


def test_summary_rejects_unknown_provider_without_echoing_sensitive_value():
    secret = "arn:aws:kms:region:account:key/private-deployment-key"
    with pytest.raises(ValueError) as error:
        build_crypto_info(
            session_id="session-id",
            security_mode="secure",
            current_crypto_epoch=1,
            key_provider=secret,
            counts=CryptoRecordCounts(),
        )
    assert secret not in str(error.value)


@pytest.mark.parametrize(
    "counts",
    [
        CryptoRecordCounts(server_total=-1),
        CryptoRecordCounts(server_total=True),
        CryptoRecordCounts(server_total=1, envelope=2),
        CryptoRecordCounts(server_total=1, envelope=1, legacy=1),
        CryptoRecordCounts(e2ee_total=1, double_ratchet=1, mls=1),
    ],
)
def test_summary_rejects_invalid_count_invariants(counts):
    with pytest.raises(ValueError, match="record counts"):
        build_crypto_info(
            session_id="session-id",
            security_mode="secure",
            current_crypto_epoch=1,
            key_provider="local",
            counts=counts,
        )


@pytest.mark.parametrize("mode", ["secure", "confidential"])
def test_owner_gets_public_metadata_with_exact_mixed_counts_without_decryption(
    client, app, monkeypatch, mode
):
    token = register_and_login(client, "metadata-owner")
    session_id = create_session(client, token, mode)
    with app.state.database.session_factory() as db:
        session = db.get(ChatSession, session_id)
        assert session is not None
        wrapped_dek = session.wrapped_dek
        assert wrapped_dek
        session.kek_uri = "private-kms-uri-do-not-return"
        session.kek_version = "private-kek-version-do-not-return"
        add_server_record(db, session_id, "envelope-v1", 1)
        add_server_record(db, session_id, "legacy-v1", 2)
        add_server_record(db, session_id, "unknown-secret-label", 3)
        db.commit()

    def unexpected_crypto(*args, **kwargs):
        raise AssertionError("Crypto metadata must not unwrap or decrypt")

    monkeypatch.setattr(app.state.key_provider, "unwrap_dek", unexpected_crypto)
    monkeypatch.setattr(app.state.envelope_crypto_service, "decrypt_message", unexpected_crypto)
    monkeypatch.setattr(app.state.crypto_service, "decrypt", unexpected_crypto)
    queries: list[str] = []

    def capture_sql(_connection, _cursor, statement, _parameters, _context, _executemany):
        queries.append(statement)

    engine = app.state.database.engine
    event.listen(engine, "before_cursor_execute", capture_sql)
    try:
        response = client.get(f"/api/sessions/{session_id}/crypto-info", headers=auth(token))
    finally:
        event.remove(engine, "before_cursor_execute", capture_sql)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["session_id"] == session_id
    assert body["security_mode"] == mode
    assert body["algorithm"] == "AES-256-GCM"
    assert body["message_counts"] == {
        "total": 3, "envelope": 1, "legacy": 1, "e2ee": 0, "unknown": 1,
    }
    assert body["current_crypto_epoch"] == 1
    assert body["key_provider"] == "local"
    assert body["aad_fields"] == list(ENVELOPE_AAD_FIELDS)
    assert body["legacy_aad_fields"] == list(LEGACY_AAD_FIELDS)
    assert body["integrity_verification"] == "not_performed"
    assert "legacy_messages_have_reduced_aad_binding" in body["notes"]
    assert "unsupported_storage_format_present" in body["notes"]
    assert response.headers["cache-control"] == "no-store"
    for secret in (
        wrapped_dek,
        "private-kms-uri-do-not-return",
        "private-kek-version-do-not-return",
        "ciphertext-must-not-be-returned",
        "nonce-must-not-be-returned",
        "unknown-secret-label",
    ):
        assert secret not in response.text
    message_queries = [statement for statement in queries if "secure_messages" in statement]
    assert len(message_queries) == 1
    assert "count(" in message_queries[0].lower()
    assert "secure_messages.ciphertext" not in message_queries[0]
    assert "secure_messages.nonce" not in message_queries[0]


@pytest.mark.parametrize("other_role", ["user", "admin"])
def test_crypto_metadata_is_owner_only_even_for_admin(client, app, other_role):
    owner = register_and_login(client, "metadata-owner")
    other = register_and_login(client, "metadata-other")
    session_id = create_session(client, owner)
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "metadata-other"))
        assert user is not None
        user.role = other_role
        db.commit()
    foreign = client.get(f"/api/sessions/{session_id}/crypto-info", headers=auth(other))
    absent = client.get(f"/api/sessions/{uuid.uuid4()}/crypto-info", headers=auth(other))
    assert foreign.status_code == absent.status_code == 404
    assert foreign.json() == absent.json()


def test_private_metadata_reports_actual_protocol_records_without_server_key_claims(client, app):
    token = register_and_login(client, "metadata-e2ee")
    session_id = create_session(client, token, "private_e2ee")
    with app.state.database.session_factory() as db:
        session = db.get(ChatSession, session_id)
        assert session is not None
        add_e2ee_records(db, session, [PROTOCOL_MLS, PROTOCOL_MLS, PROTOCOL_DOUBLE_RATCHET, "other"])
        add_server_record(db, session_id, "envelope-v1", 1)
        db.commit()
    response = client.get(f"/api/sessions/{session_id}/crypto-info", headers=auth(token))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["algorithm"] == "client-controlled-e2ee"
    assert body["key_provider"] is None
    assert body["key_bits"] is body["nonce_bits"] is body["tag_bits"] is None
    assert body["aad_fields"] == body["legacy_aad_fields"] == []
    assert body["message_counts"] == {
        "total": 5, "envelope": 1, "legacy": 0, "e2ee": 3, "unknown": 1,
    }
    assert body["e2ee_protocol_counts"] == {"double-ratchet": 1, "mls-rfc9420": 2}
    assert body["integrity_verification"] == "not_performed"
    assert "client_verifies_e2ee_ciphertexts" in body["notes"]
    assert "unexpected_ciphertext_storage_for_session_mode" in body["notes"]
    assert "server_can_decrypt_authorized_messages" not in body["notes"]
    assert "opaque-" not in json.dumps(body)


def test_e2ee_membership_does_not_grant_owner_metadata_access(client):
    owner = register_and_login(client, "metadata-group-owner")
    member = register_and_login(client, "metadata-group-member")
    session_id = create_session(client, owner, "private_e2ee")
    joined = client.post(
        f"/api/sessions/{session_id}/e2ee/members",
        headers=auth(owner),
        json={"username": "metadata-group-member"},
    )
    assert joined.status_code == 201, joined.text
    response = client.get(f"/api/sessions/{session_id}/crypto-info", headers=auth(member))
    assert response.status_code == 404


@pytest.mark.parametrize("denial", ["missing", "revoked", "expired", "suspended"])
def test_crypto_metadata_requires_active_login(client, app, denial):
    token = register_and_login(client, "metadata-auth-state")
    session_id = create_session(client, token)
    if denial == "revoked":
        assert client.post("/api/auth/logout", headers=auth(token)).status_code == 204
    elif denial in {"expired", "suspended"}:
        with app.state.database.session_factory() as db:
            user = db.scalar(select(User).where(User.username == "metadata-auth-state"))
            assert user is not None
            if denial == "suspended":
                user.is_active = False
            else:
                login = db.scalar(select(AuthSession).where(AuthSession.user_id == user.id))
                assert login is not None
                login.expires_at = utcnow() - timedelta(minutes=1)
            db.commit()
    response = client.get(
        f"/api/sessions/{session_id}/crypto-info",
        headers={} if denial == "missing" else auth(token),
    )
    assert response.status_code == 401
    assert "message_counts" not in response.json()


def test_expired_conversation_hides_and_purges_crypto_metadata(client, app):
    token = register_and_login(client, "metadata-retention")
    session_id = create_session(client, token)
    with app.state.database.session_factory() as db:
        session = db.get(ChatSession, session_id)
        assert session is not None
        session.retention_expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    response = client.get(f"/api/sessions/{session_id}/crypto-info", headers=auth(token))
    assert response.status_code == 404
    with app.state.database.session_factory() as db:
        assert db.get(ChatSession, session_id) is None


def test_high_profile_sensitive_metadata_requires_mfa(settings):
    high_app = create_app(replace(settings, security_profile="high"))
    with TestClient(high_app) as client:
        token = register_and_login(client, "metadata-high-profile")
        session_id = create_session(client, token)
        with high_app.state.database.session_factory() as db:
            session = db.get(ChatSession, session_id)
            assert session is not None
            session.security_mode = "confidential"
            session.data_classification = "confidential"
            db.commit()
        response = client.get(f"/api/sessions/{session_id}/crypto-info", headers=auth(token))
        assert response.status_code == 403
        assert "message_counts" not in response.json()
