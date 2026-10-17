"""Actual RFC 9420 group operations through the independently built native helper.

Build clients/mls_native, then set SCAP_TEST_MLS_NATIVE=1. No fake cryptographic
provider is substituted; tests run the app boundary and OpenMLS together.
"""
from __future__ import annotations

import copy
import json
import os
import uuid
from contextlib import ExitStack

import httpx
import pytest
from sqlalchemy import select

pytest.importorskip("vodozemac")

from clients import mls_client
from clients.e2ee_client import ClientError, EncryptedVault, PrivateClient
from clients.mls_client import SCHEMA, MlsClient
from src.app.e2ee import canonical_json_bytes, decode_base64_strict, encode_base64url
from src.app.models import E2eeEnvelope, SecureMessage
from tests.conftest import register_and_login

pytestmark = pytest.mark.skipif(os.environ.get("SCAP_TEST_MLS_NATIVE") != "1", reason="Opt in to native Docker MLS tests")
PASSWORD = "MLS vault phrase for local tests!"
ORIGIN = "http://127.0.0.1:8000"


@pytest.fixture
def group(client, tmp_path):
    with ExitStack() as stack:
        people = []
        for name in ("mls.alice", "mls.bob", "mls.charlie"):
            vault = stack.enter_context(EncryptedVault(tmp_path / name, PASSWORD))
            person = PrivateClient(client, register_and_login(client, name), vault, server=ORIGIN)
            person.register_device()
            people.append(person)
        for person in people:
            for peer in people:
                if peer is not person:
                    person.pin_peer(peer.me["username"], peer.fingerprint, peer.device_id)
        clients = [MlsClient(person) for person in people]
        for member in clients:
            for peer in clients:
                if peer is not member:
                    member.pin_offer(peer.offer())
        alice, bob, charlie = clients
        conversation = alice.create()
        alice.change_member(conversation, bob.client.device_id)
        bob.receive(conversation, owner_device=alice.client.device_id)
        alice.change_member(conversation, charlie.client.device_id)
        bob.receive(conversation)
        charlie.receive(conversation, owner_device=alice.client.device_id)
        yield alice, bob, charlie, conversation


def test_three_members_decrypt_and_removed_member_cannot_read_next_epoch(group, app):
    alice, bob, charlie, conversation = group
    alice.send(conversation, "Three members at epoch three")
    assert bob.receive(conversation)[0]["text"] == "Three members at epoch three"
    assert charlie.receive(conversation)[0]["text"] == "Three members at epoch three"
    bob.send(conversation, "Bob's RFC 9420 reply")
    assert alice.receive(conversation)[0]["text"] == "Bob's RFC 9420 reply"
    assert charlie.receive(conversation)[0]["text"] == "Bob's RFC 9420 reply"
    removed_state = copy.deepcopy(charlie.data["native"])
    alice.change_member(conversation, charlie.client.device_id, remove=True)
    bob.receive(conversation)
    alice.send(conversation, "Only Alice and Bob have this epoch")
    assert bob.receive(conversation)[0]["text"] == "Only Alice and Bob have this epoch"
    with pytest.raises(ClientError, match="HTTP 404|HTTP 403"):
        charlie.receive(conversation)
    with app.state.database.session_factory() as db:
        rows = list(db.scalars(select(E2eeEnvelope)))
        latest = next(row for row in reversed(rows) if row.message_kind == "application")
        assert not list(db.scalars(select(SecureMessage)))
        assert "Only Alice" not in json.dumps([r.ciphertext_b64 for r in rows])
    # Even a bypassed delivery service cannot give the removed member secrets
    # of the new epoch. This uses the member's complete pre-removal private state.
    with pytest.raises(ClientError, match="operation rejected"):
        charlie.native.call(op="receive", device_id=charlie.client.device_id, state=removed_state,
                            group_id=conversation, message=latest.ciphertext_b64)


def test_native_tamper_replay_and_context_do_not_commit_state(group, app):
    alice, bob, _charlie, conversation = group
    alice.send(conversation, "Authenticated application context")
    with app.state.database.session_factory() as db:
        row = db.scalar(select(E2eeEnvelope).where(E2eeEnvelope.message_kind == "application"))
        document = {"id": row.id, "created_at": row.created_at.isoformat(), "protocol": row.protocol,
            "sender_device_id": row.sender_device_id, "recipient_device_id": row.recipient_device_id,
            "message_kind": row.message_kind, "group_epoch": row.group_epoch,
            "client_message_id": row.client_message_id, "header": row.header_b64, "ciphertext": row.ciphertext_b64}
    before = copy.deepcopy(bob.data)
    altered = {**document, "client_message_id": "forged-context"}
    routing = bob._routing(conversation)
    with pytest.raises(ClientError, match="context"):
        bob._receive_one(conversation, altered, alice.client.device_id, routing)
    assert bob.data == before
    ciphertext = bytearray(decode_base64_strict(document["ciphertext"], field="ciphertext"))
    ciphertext[-1] ^= 1
    with pytest.raises(ClientError, match="operation rejected"):
        bob._receive_one(conversation, {**document, "ciphertext": encode_base64url(bytes(ciphertext))},
                         alice.client.device_id, routing)
    assert bob.data == before
    assert bob._receive_one(conversation, document, alice.client.device_id, routing)["text"] == "Authenticated application context"
    acknowledged = copy.deepcopy(bob.data)
    with pytest.raises(ClientError, match="operation rejected|replayed"):
        bob._receive_one(conversation, document, alice.client.device_id, routing)
    assert bob.data == acknowledged


def test_membership_and_application_outbox_retry_survive_response_loss(group, monkeypatch, app):
    alice, bob, charlie, conversation = group
    original = alice.client.api.request
    lost = False

    def lose_one(method, path, **kwargs):
        nonlocal lost
        response = original(method, path, **kwargs)
        if method == "POST" and path.endswith("/e2ee/envelopes") and not lost:
            lost = True
            assert response.status_code == 201
            raise OSError("response lost after persisted ciphertext")
        return response

    with monkeypatch.context() as patch:
        patch.setattr(alice.client.api, "request", lose_one)
        with pytest.raises(OSError):
            alice.send(conversation, "Retry exact group ciphertext")
    assert alice.data["outbox"]
    assert alice.flush() == {"delivered": True}
    assert bob.receive(conversation)[0]["text"] == "Retry exact group ciphertext"
    with app.state.database.session_factory() as db:
        assert len(list(db.scalars(select(E2eeEnvelope).where(E2eeEnvelope.message_kind == "application")))) == 1
    # Losing the membership HTTP response is also recoverable: the exact target
    # account, action and epoch must be acknowledged before publishing a commit.
    def lose_remove(method, path, **kwargs):
        response = original(method, path, **kwargs)
        if method == "DELETE" and "/e2ee/members/" in path:
            assert response.status_code == 204
            raise OSError("membership response lost")
        return response

    with monkeypatch.context() as patch:
        patch.setattr(alice.client.api, "request", lose_remove)
        with pytest.raises(OSError):
            alice.change_member(conversation, charlie.client.device_id, remove=True)
    alice.flush()
    bob.receive(conversation)
    assert bob.data["groups"][conversation]["epoch"] == 4

    def malformed_duplicate(method, path, **kwargs):
        if method == "POST" and path.endswith("/e2ee/envelopes"):
            return httpx.Response(409, json=[])
        return original(method, path, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(alice.client.api, "request", malformed_duplicate)
        with pytest.raises(ClientError, match="remains pending"):
            alice.send(conversation, "Malformed duplicate verdict must preserve outbox")
    assert alice.data["outbox"]
    alice.flush()
    assert bob.receive(conversation)[0]["text"] == "Malformed duplicate verdict must preserve outbox"


def test_profile_reload_resumes_mls_native_ratchet_and_cursor(group, client):
    alice, bob, _charlie, conversation = group
    alice.send(conversation, "Persist native MLS state")
    assert bob.receive(conversation)[0]["text"] == "Persist native MLS state"
    private = bob.client
    directory, token = private.vault.directory, private.token
    encrypted = private.vault.path.read_bytes()
    assert b"private" not in encrypted and b"Persist native" not in encrypted
    private.vault.__exit__(None, None, None)
    with EncryptedVault(directory, PASSWORD) as vault:
        resumed = MlsClient(PrivateClient(client, token, vault, server=ORIGIN))
        assert resumed.receive(conversation) == []
        resumed.send(conversation, "MLS after restart")
        assert alice.receive(conversation)[0]["text"] == "MLS after restart"
        assert resumed.receive(conversation) == []
        assert conversation not in resumed.data["own"]
        for index in range(2):
            resumed.send(conversation, f"Pruned acknowledgement {index}")
            assert alice.receive(conversation)[0]["text"] == f"Pruned acknowledgement {index}"
            assert resumed.receive(conversation) == []
            assert conversation not in resumed.data["own"]
    with EncryptedVault(directory, PASSWORD) as vault:
        reopened = MlsClient(PrivateClient(client, token, vault, server=ORIGIN))
        assert conversation not in reopened.data["own"]
        assert reopened.receive(conversation) == []


def test_signed_key_package_offer_cannot_be_changed_or_substituted(group):
    alice, bob, charlie, _conversation = group
    offered = bob.offer()
    with pytest.raises(ClientError, match="signature"):
        alice.pin_offer({**offered, "key_package": charlie.offer()["key_package"]})
    with pytest.raises(ClientError, match="fingerprint"):
        alice.pin_offer({**offered, "account_id": charlie.client.me["id"]})
    before = copy.deepcopy(alice.data)
    unpinned = charlie.client.device_id
    del alice.data["pins"][unpinned]
    with pytest.raises(ClientError, match="unverified"):
        alice._roster({"members": [{"device_id": unpinned, "signing_key": charlie.data["signing_key"]}]})
    alice.data.update(before)


def test_partial_receive_batch_returns_verified_plaintext_before_bad_ciphertext(group, app):
    alice, bob, _charlie, conversation = group
    alice.send(conversation, "First valid group message")
    alice.send(conversation, "Second group message after repair")
    with app.state.database.session_factory() as db:
        rows = list(db.scalars(select(E2eeEnvelope).where(E2eeEnvelope.message_kind == "application")
                               .order_by(E2eeEnvelope.created_at, E2eeEnvelope.id)))
        broken_id, original = rows[1].id, rows[1].ciphertext_b64
        ciphertext = bytearray(decode_base64_strict(original, field="ciphertext"))
        ciphertext[-1] ^= 1
        rows[1].ciphertext_b64 = encode_base64url(bytes(ciphertext))
        db.commit()
    assert bob.receive(conversation) == [{"sender_device": alice.client.device_id, "text": "First valid group message"}]
    assert bob.last_receive_error
    with app.state.database.session_factory() as db:
        db.get(E2eeEnvelope, broken_id).ciphertext_b64 = original
        db.commit()
    assert bob.receive(conversation)[0]["text"] == "Second group message after repair"
    assert bob.last_receive_error is None


def test_nonowner_commit_and_concurrent_relay_membership_fail_closed(group):
    alice, bob, charlie, conversation = group
    # A genuine RFC 9420 member can create a valid commit. The application's
    # owner policy still rejects it before adopting any new cryptographic state.
    message_id, epoch = "nonowner-commit", 3
    context = canonical_json_bytes(bob._context(conversation, epoch, message_id, "commit"), schema=SCHEMA)
    result = bob._native("remove", group_id=conversation, target_device=charlie.client.device_id,
                         aad=encode_base64url(context))
    forged = bob._envelope(conversation, epoch, "commit", result["commit"], message_id)
    bob.client.request("POST", f"/api/sessions/{conversation}/e2ee/envelopes", json=forged)
    before = copy.deepcopy(alice.data)
    with pytest.raises(ClientError, match="pinned owner"):
        alice.receive(conversation)
    # Known self-sent commits may be acknowledged first; native secrets and
    # accepted group epoch must remain unchanged on the forbidden next commit.
    assert alice.data["native"] == before["native"]
    assert alice.data["groups"] == before["groups"]
    alice.client.request("DELETE", f"/api/sessions/{conversation}/e2ee/members/{charlie.client.me['username']}")
    native_before = copy.deepcopy(alice.data["native"])
    with pytest.raises(ClientError, match="epoch"):
        alice.send(conversation, "Cannot silently skip a membership epoch")
    assert alice.data["native"] == native_before and alice.data["outbox"] is None


@pytest.mark.parametrize("failure", ["http_page", "persistence"])
def test_earlier_plaintext_is_returned_when_next_page_or_save_fails(group, monkeypatch, client, failure):
    alice, bob, _charlie, conversation = group
    alice.send(conversation, "Durable first message")
    alice.send(conversation, "Second message survives retry")
    monkeypatch.setattr(mls_client, "RECEIVE_PAGE_SIZE", 1)
    original = bob.client.request if failure == "http_page" else bob.client.vault._write
    count = 0

    def fail_second(*args, **kwargs):
        nonlocal count
        count += 1
        failure_count = 3 if failure == "http_page" else 2
        if count == failure_count:
            if failure == "http_page":
                raise httpx.ConnectError("synthetic disconnected next page")
            raise OSError("synthetic disk failure after first saved message")
        return original(*args, **kwargs)

    with monkeypatch.context() as patch:
        if failure == "http_page":
            patch.setattr(bob.client, "request", fail_second)
        else:
            patch.setattr(bob.client.vault, "_write", fail_second)
        assert bob.receive(conversation) == [{"sender_device": alice.client.device_id, "text": "Durable first message"}]
    assert bob.last_receive_error
    if failure == "persistence":
        assert bob.client.requires_restart
        with pytest.raises(ClientError, match="close and reopen"):
            bob.send(conversation, "Cannot continue an unsaved native ratchet")
        directory, token = bob.client.vault.directory, bob.client.token
        bob.client.vault.__exit__(None, None, None)
        with EncryptedVault(directory, PASSWORD) as vault:
            resumed = MlsClient(PrivateClient(client, token, vault, server=ORIGIN))
            assert resumed.receive(conversation)[0]["text"] == "Second message survives retry"
    else:
        assert bob.receive(conversation)[0]["text"] == "Second message survives retry"


def test_valid_welcome_from_nonowner_cannot_be_relabelled_as_owner(group):
    alice, bob, charlie, _existing = group
    conversation = alice.create("Owner authentication regression")
    charlie.refresh_offer()
    # A pinned nonowner creates an MLS fork with the real session ID and the
    # real public credentials. The verified Welcome signer must identify it.
    rogue = bob.native.call(op="create", device_id=bob.client.device_id,
        state={"signer": bob.data["native"]["signer"], "storage": []}, group_id=conversation)
    rogue = bob.native.call(op="add", device_id=bob.client.device_id, state=rogue["state"],
        group_id=conversation, key_package=alice.offer()["key_package"])
    rogue = bob.native.call(op="add", device_id=bob.client.device_id, state=rogue["state"],
        group_id=conversation, key_package=charlie.offer()["key_package"])
    envelope = alice._envelope(conversation, 3, "welcome", rogue["welcome"], str(uuid.uuid4()), charlie.client.device_id)
    row = {**envelope, "id": str(uuid.uuid4()), "created_at": "2026-10-17T12:00:00Z", "group_epoch": 3}
    before = copy.deepcopy(charlie.data)
    with pytest.raises(ClientError, match="not signed by the pinned group owner"):
        charlie._receive_one(conversation, row, alice.client.device_id,
                             {"epoch": 3, "owner_id": alice.client.me["id"]})
    assert charlie.data == before
