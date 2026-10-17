"""Real Olm client round trips, authenticated context, persistence and retry."""

from __future__ import annotations

import copy
import json
from contextlib import ExitStack

import pytest
from sqlalchemy import select

pytest.importorskip("vodozemac", reason="Install the e2ee-client extra to test the standalone client")

from clients.e2ee_client import ClientError, EncryptedVault, PrivateClient, checked_server
from src.app.e2ee import decode_base64_strict, encode_base64url
from src.app.models import E2eeEnvelope, SecureMessage
from tests.conftest import register_and_login

VAULT_PASSWORD = "Client vault phrase 2026!"
SERVER = "http://127.0.0.1:8000"


@pytest.fixture
def pair(client, tmp_path):
    with ExitStack() as stack:
        alice_vault = stack.enter_context(EncryptedVault(tmp_path / "alice", VAULT_PASSWORD))
        bob_vault = stack.enter_context(EncryptedVault(tmp_path / "bob", VAULT_PASSWORD))
        alice = PrivateClient(client, register_and_login(client, "private.alice"), alice_vault, server=SERVER)
        bob = PrivateClient(client, register_and_login(client, "private.bob"), bob_vault, server=SERVER)
        alice.register_device()
        bob.register_device()
        alice.pin_peer("private.bob", bob.fingerprint, bob.device_id)
        bob.pin_peer("private.alice", alice.fingerprint, alice.device_id)
        conversation = alice.new_conversation("private.bob")
        yield alice, bob, conversation


def test_real_double_ratchet_round_trip_only_stores_ciphertext(pair, app):
    alice, bob, conversation = pair
    alice.send(conversation, bob.device_id, "Recruiter example from Alice")
    assert bob.receive(conversation) == [{"sender_device": alice.device_id, "text": "Recruiter example from Alice"}]
    bob.send(conversation, alice.device_id, "Reply from Bob")
    assert alice.receive(conversation) == [{"sender_device": bob.device_id, "text": "Reply from Bob"}]
    assert alice.receive(conversation) == []
    with app.state.database.session_factory() as db:
        envelopes = list(db.scalars(select(E2eeEnvelope)))
        assert len(envelopes) == 2
        assert list(db.scalars(select(SecureMessage))) == []
        stored = json.dumps([{"header": row.header_b64, "ciphertext": row.ciphertext_b64} for row in envelopes])
        assert "Recruiter example" not in stored and "Reply from Bob" not in stored


def test_tampered_ciphertext_and_context_do_not_advance_receiver_ratchet(pair, app):
    alice, bob, conversation = pair
    alice.send(conversation, bob.device_id, "Authenticated context")
    with app.state.database.session_factory() as db:
        row = db.scalar(select(E2eeEnvelope))
        original = {"id": row.id, "sender_device_id": row.sender_device_id,
                    "recipient_device_id": row.recipient_device_id, "protocol": row.protocol,
                    "header": row.header_b64, "ciphertext": row.ciphertext_b64,
                    "group_epoch": row.group_epoch, "client_message_id": row.client_message_id}
    before = copy.deepcopy(bob.vault.state)
    changed = {**original, "client_message_id": "changed-context"}
    with pytest.raises(ClientError, match="routing context"):
        bob.decrypt(conversation, changed)
    assert bob.vault.state == before
    ciphertext = bytearray(decode_base64_strict(original["ciphertext"], field="ciphertext"))
    ciphertext[-1] ^= 1
    changed = {**original, "ciphertext": encode_base64url(bytes(ciphertext))}
    with pytest.raises((ValueError, ClientError)):
        bob.decrypt(conversation, changed)
    assert bob.vault.state == before
    assert bob.decrypt(conversation, original) == "Authenticated context"
    with pytest.raises((ValueError, ClientError)):
        bob.decrypt(conversation, original)


def test_fingerprint_mismatch_and_unknown_sender_fail_closed(pair):
    alice, bob, conversation = pair
    with pytest.raises(ClientError, match="Fingerprint mismatch"):
        alice.pin_peer("private.bob", "0" * 64, bob.device_id)
    alice.send(conversation, bob.device_id, "Verified sender only")
    bob.vault.state["peers"].clear()
    with pytest.raises(ClientError, match="Unverified sender"):
        bob.receive(conversation)
    assert conversation not in bob.vault.state["cursors"]


def test_outbox_survives_lost_response_and_retry_does_not_duplicate(pair, monkeypatch, app):
    alice, bob, conversation = pair
    original = alice.api.post

    def lost_response(path, **kwargs):
        response = original(path, **kwargs)
        assert response.status_code == 201
        raise OSError("simulated response loss")

    with monkeypatch.context() as patch:
        patch.setattr(alice.api, "post", lost_response)
        with pytest.raises(OSError):
            alice.send(conversation, bob.device_id, "Retry once")
    assert alice.vault.state["outbox"]
    assert alice.flush() == {"delivered": True, "duplicate_acknowledged": True}
    with app.state.database.session_factory() as db:
        assert len(list(db.scalars(select(E2eeEnvelope)))) == 1
    assert bob.receive(conversation)[0]["text"] == "Retry once"


def test_vault_reload_resumes_ratchet_and_cursor(pair, client):
    alice, bob, conversation = pair
    alice.send(conversation, bob.device_id, "Before restart")
    assert bob.receive(conversation)[0]["text"] == "Before restart"
    directory, token, device = bob.vault.directory, bob.token, bob.device_id
    bob.vault.__exit__(None, None, None)
    with EncryptedVault(directory, VAULT_PASSWORD) as vault:
        resumed = PrivateClient(client, token, vault, server=SERVER)
        assert resumed.device_id == device
        assert resumed.receive(conversation) == []
        resumed.send(conversation, alice.device_id, "After restart")
        assert alice.receive(conversation)[0]["text"] == "After restart"


def test_device_registration_retry_uses_existing_identity(pair):
    alice, _bob, _conversation = pair
    assert alice.register_device()["id"] == alice.device_id


def test_second_device_requires_existing_device_approval(pair, client, tmp_path):
    alice, _bob, _conversation = pair
    with EncryptedVault(tmp_path / "second-device", VAULT_PASSWORD) as vault:
        second = PrivateClient(client, alice.token, vault, server=SERVER)
        offer = second.registration_offer()
        approval = alice.approve(offer)
        assert second.register_device(approval=approval)["trust_state"] == "trusted"


def test_refill_uploads_matching_private_prekeys(pair):
    _alice, bob, _conversation = pair
    result = bob.refill(10)
    assert result is not None
    assert bob.account.one_time_keys == {}


def test_vault_is_encrypted_rejects_wrong_password_and_blocks_concurrent_writer(tmp_path):
    directory = tmp_path / "profile"
    with EncryptedVault(directory, VAULT_PASSWORD) as vault:
        vault.state["private_test"] = "not-on-disk-as-plaintext"
        vault.save()
        encrypted = vault.path.read_bytes()
        assert b"not-on-disk-as-plaintext" not in encrypted
        with pytest.raises(ClientError, match="already open"):
            with EncryptedVault(directory, VAULT_PASSWORD):
                pass
    with pytest.raises(ClientError, match="Cannot unlock"):
        with EncryptedVault(directory, "Wrong vault password phrase"):
            pass
    assert (directory / "client.scapclient").read_bytes() == encrypted
    with EncryptedVault(directory, VAULT_PASSWORD) as vault:
        assert vault.state["private_test"] == "not-on-disk-as-plaintext"


@pytest.mark.parametrize("server", ["http://example.com", "https://user:password@example.com", "https://example.com/?token=secret"])
def test_client_rejects_unsafe_server_origins(server):
    with pytest.raises(ClientError):
        checked_server(server)


def test_profile_cannot_be_rebound_to_another_account(pair, client):
    alice, bob, _conversation = pair
    with pytest.raises(ClientError, match="different server or account"):
        PrivateClient(client, alice.token, bob.vault, server=SERVER)
