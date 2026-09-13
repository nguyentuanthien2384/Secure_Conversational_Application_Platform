from __future__ import annotations

import os
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from src.app.e2ee import (
    PROTOCOL_DOUBLE_RATCHET,
    build_device_possession_message,
    encode_base64url,
)
from tests.conftest import register_and_login


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def register_device(
    client: TestClient,
    token: str,
    *,
    prekey_count: int = 1,
) -> tuple[str, Ed25519PrivateKey]:
    account_id = client.get("/api/auth/me", headers=auth(token)).json()["id"]
    challenge = client.post("/api/e2ee/devices/challenge", headers=auth(token))
    assert challenge.status_code == 200, challenge.text
    challenge_data = challenge.json()
    device_id = str(uuid.uuid4())
    private_key = Ed25519PrivateKey.generate()
    public_key = encode_base64url(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    signed_prekey_raw = os.urandom(32)
    signed_prekey = encode_base64url(signed_prekey_raw)
    possession = build_device_possession_message(
        account_id=account_id,
        device_id=device_id,
        identity_public_key_b64=public_key,
        challenge_b64=challenge_data["challenge"],
    )
    response = client.post(
        "/api/e2ee/devices",
        headers=auth(token),
        json={
            "challenge_id": challenge_data["id"],
            "challenge": challenge_data["challenge"],
            "device_id": device_id,
            "display_name": "Test device",
            "identity_key": public_key,
            "possession_signature": encode_base64url(private_key.sign(possession)),
            "signed_prekey": signed_prekey,
            "signed_prekey_signature": encode_base64url(
                private_key.sign(signed_prekey_raw)
            ),
            "one_time_prekeys": [
                encode_base64url(os.urandom(32)) for _ in range(prekey_count)
            ],
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["trust_state"] == "trusted"
    return device_id, private_key


def test_private_e2ee_routes_are_ciphertext_only_and_replay_safe(client: TestClient):
    alice_token = register_and_login(client, "e2ee-alice")
    bob_token = register_and_login(client, "e2ee-bob")
    alice_device, _ = register_device(client, alice_token)
    bob_device, _ = register_device(client, bob_token)

    created = client.post(
        "/api/sessions",
        headers=auth(alice_token),
        json={"title": "E2EE", "security_mode": "private_e2ee"},
    )
    assert created.status_code == 201, created.text
    session_id = created.json()["id"]
    added = client.post(
        f"/api/sessions/{session_id}/e2ee/members",
        headers=auth(alice_token),
        json={"username": "e2ee-bob"},
    )
    assert added.status_code == 201, added.text
    epoch = added.json()["epoch"]

    plaintext_attempt = client.post(
        f"/api/sessions/{session_id}/messages",
        headers=auth(alice_token),
        json={"content": "server must never receive this in E2EE mode"},
    )
    assert plaintext_attempt.status_code == 403

    payload = {
        "version": 1,
        "protocol": PROTOCOL_DOUBLE_RATCHET,
        "recipient": bob_device,
        "recipient_device_id": bob_device,
        "epoch": epoch,
        "client_message_id": "msg-0001",
        "sender_device_id": alice_device,
        "message_kind": "application",
        "header": encode_base64url(os.urandom(48)),
        "ciphertext": encode_base64url(os.urandom(96)),
    }
    sent = client.post(
        f"/api/sessions/{session_id}/e2ee/envelopes",
        headers=auth(alice_token),
        json=payload,
    )
    assert sent.status_code == 201, sent.text
    replay = client.post(
        f"/api/sessions/{session_id}/e2ee/envelopes",
        headers=auth(alice_token),
        json={**payload, "ciphertext": encode_base64url(os.urandom(96))},
    )
    assert replay.status_code == 409

    received = client.get(
        f"/api/sessions/{session_id}/e2ee/envelopes",
        headers=auth(bob_token),
        params={"recipient_device_id": bob_device},
    )
    assert received.status_code == 200, received.text
    assert len(received.json()) == 1
    assert received.json()[0]["ciphertext"] == payload["ciphertext"]


def test_one_time_prekey_is_consumed_once(client: TestClient):
    owner_token = register_and_login(client, "prekey-owner")
    requester_token = register_and_login(client, "prekey-requester")
    device_id, _ = register_device(client, owner_token, prekey_count=1)

    first = client.get(
        "/api/e2ee/users/prekey-owner/prekey-bundle",
        headers=auth(requester_token),
        params={"device_id": device_id},
    )
    second = client.get(
        "/api/e2ee/users/prekey-owner/prekey-bundle",
        headers=auth(requester_token),
        params={"device_id": device_id},
    )
    assert first.status_code == second.status_code == 200
    assert first.json()["one_time_prekey"] is not None
    assert second.json()["one_time_prekey"] is None


def test_export_ticket_streams_and_is_single_use(client: TestClient):
    token = register_and_login(client, "stream-export")
    session_id = client.post(
        "/api/sessions", headers=auth(token), json={"title": "Streamed"}
    ).json()["id"]
    client.post(
        f"/api/sessions/{session_id}/messages",
        headers=auth(token),
        json={"content": "plaintext only in memory"},
    )
    ticket = client.post(
        f"/api/sessions/{session_id}/export-ticket",
        headers=auth(token),
    )
    assert ticket.status_code == 200, ticket.text
    path = ticket.json()["download_url"]
    first = client.get(path)
    second = client.get(path)
    assert first.status_code == 200
    assert first.json()["messages"][0]["content"] == "plaintext only in memory"
    assert "attachment" in first.headers["content-disposition"]
    assert second.status_code == 410

