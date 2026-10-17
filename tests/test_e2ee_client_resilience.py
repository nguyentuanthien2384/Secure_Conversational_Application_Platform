"""Crash locks, partial receive delivery and fail-closed local ratchet writes."""

from __future__ import annotations

import copy
import json
import queue
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

pytest.importorskip("vodozemac", reason="Install the standalone E2EE client extra")

from clients import e2ee_client, private_chat
from clients.e2ee_client import ClientError, ClientPersistenceError, EncryptedVault, PrivateClient
from src.app.db import utcnow
from src.app.e2ee import decode_base64_strict, encode_base64url, safety_fingerprint
from src.app.models import E2eePreKey
from tests import test_e2ee_client as client_fixtures

SERVER, VAULT_PASSWORD, pair = client_fixtures.SERVER, client_fixtures.VAULT_PASSWORD, client_fixtures.pair


def _envelopes(client, conversation):
    return client.request("GET", f"/api/sessions/{conversation}/e2ee/envelopes", params={
        "recipient_device_id": client.device_id, "limit": 100,
    })


def test_partial_receive_returns_durable_plaintext_before_bad_ciphertext(pair, monkeypatch):
    alice, bob, conversation = pair
    alice.send(conversation, bob.device_id, "First delivered message")
    alice.send(conversation, bob.device_id, "Second delivered message")
    envelopes = _envelopes(bob, conversation)
    assert len(envelopes) == 2
    damaged = copy.deepcopy(envelopes)
    damaged[1]["header"] = encode_base64url(b"[]")
    original = bob.request
    with monkeypatch.context() as patch:
        patch.setattr(bob, "request", lambda *args, **kwargs: damaged)
        assert bob.receive(conversation) == [{"sender_device": alice.device_id, "text": "First delivered message"}]
    assert bob.last_receive_error
    assert bob.vault.state["cursors"][conversation]["after_id"] == envelopes[0]["id"]
    assert bob.request == original
    assert bob.receive(conversation) == [{"sender_device": alice.device_id, "text": "Second delivered message"}]
    assert bob.last_receive_error is None


def test_partial_receive_returns_plaintext_if_next_page_connection_fails(pair, monkeypatch):
    alice, bob, conversation = pair
    alice.send(conversation, bob.device_id, "Retain before a connection failure")
    original = bob.request
    calls = []

    def fail_next_page(method, path, **kwargs):
        calls.append(kwargs["params"])
        if len(calls) == 2:
            raise httpx.ReadTimeout("private endpoint or response must not enter the visible error")
        return original(method, path, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(e2ee_client, "RECEIVE_PAGE_SIZE", 1)
        patch.setattr(bob, "request", fail_next_page)
        assert bob.receive(conversation) == [{"sender_device": alice.device_id,
                                              "text": "Retain before a connection failure"}]
    assert len(calls) == 2 and calls[1]["after_id"]
    assert "private endpoint" not in bob.last_receive_error
    assert bob.receive(conversation) == []


@pytest.mark.parametrize("header", [[], None, "private header", 1, True, {}, {"ratchet_id": []}])
def test_malformed_header_is_a_fixed_client_error_without_state_change(pair, header):
    alice, bob, conversation = pair
    alice.send(conversation, bob.device_id, "Authentic ciphertext")
    envelope = _envelopes(bob, conversation)[0]
    envelope["header"] = encode_base64url(json.dumps(header).encode())
    before = copy.deepcopy(bob.vault.state)
    with pytest.raises(ClientError, match="^Invalid ciphertext header\\.$"):
        bob.decrypt(conversation, envelope)
    assert bob.vault.state == before


@pytest.mark.parametrize("envelope", [[], None, "not an envelope", {}, {"sender_device_id": []}])
def test_malformed_envelope_is_a_fixed_client_error(pair, envelope):
    _alice, bob, conversation = pair
    before = copy.deepcopy(bob.vault.state)
    with pytest.raises(ClientError, match="^Invalid ciphertext envelope\\.$"):
        bob.decrypt(conversation, envelope)
    assert bob.vault.state == before


@pytest.mark.parametrize("document", [[], None, "not an object", {"payload": []}, {"payload": None},
                                      {"payload": "not an object"}, {"payload": 1}])
def test_authenticated_non_object_body_does_not_consume_receiver_prekey(pair, document):
    alice, bob, conversation = pair
    envelope = alice.prepare(conversation, bob.device_id, "Create a genuine outbound ratchet")
    active = alice.vault.state["active"][f"{conversation}:{bob.device_id}"]
    ratchet = e2ee_client.olm.Session.from_pickle(alice.vault.state["sessions"][active], alice.vault.key)
    message_type, ciphertext = ratchet.encrypt(json.dumps(document).encode()).to_parts()
    header = json.loads(decode_base64_strict(envelope["header"], field="header"))
    header["type"] = message_type
    malformed = {**envelope, "group_epoch": envelope["epoch"], "ciphertext": encode_base64url(ciphertext),
                 "header": encode_base64url(json.dumps(header).encode())}
    before = copy.deepcopy(bob.vault.state)
    account_before = bob.account
    keys_before = {key: value.to_base64() for key, value in bob.account.one_time_keys.items()}
    with pytest.raises(ClientError, match="^Invalid authenticated message\\.$"):
        bob.decrypt(conversation, malformed)
    assert bob.vault.state == before
    assert bob.account is account_before
    assert {key: value.to_base64() for key, value in bob.account.one_time_keys.items()} == keys_before


@pytest.mark.parametrize("failure", ["filesystem", "budget"])
def test_save_failure_blocks_network_and_ratchet_actions_until_restart(pair, client, monkeypatch, failure):
    alice, bob, conversation = pair
    before = alice.vault.path.read_bytes()
    with monkeypatch.context() as patch:
        if failure == "filesystem":
            def fail_replace(*args, **kwargs):
                raise OSError("private path must not enter the visible error")

            patch.setattr(e2ee_client.os, "replace", fail_replace)
        else:
            patch.setattr(e2ee_client, "MAX_VAULT_BYTES", 128)
        with pytest.raises(ClientPersistenceError, match="close and reopen") as error:
            alice.prepare(conversation, bob.device_id, "Never post this nondurable ciphertext")
        assert "private path" not in str(error.value)
    assert alice.requires_restart
    assert alice.vault.path.read_bytes() == before

    def no_http(*args, **kwargs):
        raise AssertionError("A poisoned client attempted network I/O")

    with monkeypatch.context() as patch:
        patch.setattr(alice.api, "request", no_http)
        patch.setattr(alice.api, "post", no_http)
        for action in (lambda: alice.request("GET", "/api/auth/me"), alice.flush,
                       lambda: alice.prepare(conversation, bob.device_id, "Blocked"),
                       lambda: alice.receive(conversation), alice.register_device, alice.refill):
            with pytest.raises(ClientPersistenceError, match="close and reopen"):
                action()
    directory, token = alice.vault.directory, alice.token
    alice.vault.__exit__(None, None, None)
    with EncryptedVault(directory, VAULT_PASSWORD) as vault:
        resumed = PrivateClient(client, token, vault, server=SERVER)
        assert not resumed.vault.state["outbox"]
        resumed.send(conversation, bob.device_id, "After reopening durable state")
        assert bob.receive(conversation)[0]["text"] == "After reopening durable state"


def _child_lock(profile, *, wait):
    code = """from pathlib import Path
import sys
from clients.e2ee_client import ClientError, EncryptedVault
try:
    with EncryptedVault(Path(sys.argv[1]), sys.argv[2]) as vault:
        vault.state['crash_test'] = 'durable before crash'
        vault.save()
        print('LOCKED', flush=True)
        if sys.argv[3] == 'wait':
            sys.stdin.readline()
except ClientError:
    print('DENIED', flush=True)
    raise SystemExit(2)
"""
    return [sys.executable, "-c", code, str(profile), VAULT_PASSWORD, "wait" if wait else "exit"]


def test_advisory_lock_denies_a_second_process_and_releases_after_crash(tmp_path):
    profile = tmp_path / "crash-profile"
    child = subprocess.Popen(_child_lock(profile, wait=True), cwd=Path(__file__).resolve().parents[1],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    messages = queue.Queue()
    threading.Thread(target=lambda: messages.put(child.stdout.readline().strip()), daemon=True).start()
    try:
        assert messages.get(timeout=20) == "LOCKED"
        lock_inode = (profile / "client.lock").stat().st_ino
        denied = subprocess.run(_child_lock(profile, wait=False), cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=20, check=False)
        assert denied.returncode == 2 and denied.stdout.strip() == "DENIED"
        child.kill()  # No __exit__: the OS must release the advisory lock.
        child.wait(timeout=20)
        assert (profile / "client.lock").exists()
        with EncryptedVault(profile, VAULT_PASSWORD) as vault:
            assert vault.state["crash_test"] == "durable before crash"
            assert vault.lock_path.stat().st_ino == lock_inode
        assert (profile / "client.lock").stat().st_ino == lock_inode
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=20)


def test_cli_prints_partial_messages_then_exits_if_persistence_failed(monkeypatch, capsys):
    client = SimpleNamespace(requires_restart=True, last_receive_error="fixed error",
                             receive=lambda conversation: [{"text": "Already received message"}])
    commands = iter(["receive conversation", "retry"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(commands))
    with pytest.raises(ClientPersistenceError):
        private_chat.interact(client)
    output = capsys.readouterr().out
    assert "Already received message" in output
    assert "hãy mở lại profile" in output
    assert next(commands) == "retry"


def test_refill_lost_response_recovers_durable_batch_and_keeps_private_prekeys(pair, client, app, monkeypatch):
    alice, bob, conversation = pair
    original = bob.api.request

    def committed_response_loss(method, path, **kwargs):
        response = original(method, path, **kwargs)
        if method == "POST" and path.endswith("/prekeys"):
            assert response.status_code == 200
            raise httpx.ReadTimeout("simulated response loss after commit")
        return response

    with monkeypatch.context() as patch:
        patch.setattr(bob.api, "request", committed_response_loss)
        with pytest.raises(httpx.ReadTimeout):
            bob.refill(5)
    pending = copy.deepcopy(bob.vault.state["prekey_upload"])
    assert pending["attempted"] is True and len(pending["one_time_prekeys"]) == 5
    # Exhaust only the older public inventory in this disposable database, so
    # the next outbound session must use one of the newly uploaded private keys.
    with app.state.database.session_factory() as db:
        for row in db.scalars(select(E2eePreKey).where(E2eePreKey.device_id == bob.device_id)):
            if row.public_key_b64 not in pending["one_time_prekeys"] and row.consumed_at is None:
                row.consumed_at = utcnow()
        db.commit()
    alice.pin_peer("private.bob", bob.fingerprint, bob.device_id)
    with app.state.database.session_factory() as db:
        before = {row.public_key_b64: row.consumed_at is not None for row in db.scalars(
            select(E2eePreKey).where(E2eePreKey.device_id == bob.device_id))}
    directory, token = bob.vault.directory, bob.token
    bob.vault.__exit__(None, None, None)
    with EncryptedVault(directory, VAULT_PASSWORD) as vault:
        resumed = PrivateClient(client, token, vault, server=SERVER)
        assert resumed.vault.state["prekey_upload"] == pending
        result = resumed.refill(5)
        assert result["already_uploaded"] is True and result["added"] == 0
        assert "prekey_upload" not in vault.state and resumed.account.one_time_keys == {}
        with app.state.database.session_factory() as db:
            after = {row.public_key_b64: row.consumed_at is not None for row in db.scalars(
                select(E2eePreKey).where(E2eePreKey.device_id == resumed.device_id))}
        assert before == after and len(after) == 25  # No key reactivation or duplicate insertion.
        alice.send(conversation, resumed.device_id, "The uploaded private prekey remains available")
        assert resumed.receive(conversation)[0]["text"] == "The uploaded private prekey remains available"
        assert resumed.refill(5)["added"] == 5


@pytest.mark.parametrize(("status", "body"), [
    (422, {"detail": "A different public material rejection"}),
    (422, []),
    (409, {"detail": "Thiết bị đã đạt giới hạn lưu prekey."}),
    (409, {"detail": "Challenge không hợp lệ hoặc đã sử dụng."}),
    (409, {"detail": "Không được sử dụng lại one-time prekey."}),
])
def test_refill_does_not_acknowledge_unrelated_rejections(pair, monkeypatch, status, body):
    _alice, bob, _conversation = pair
    original = bob.api.request

    def rejected_upload(method, path, **kwargs):
        if method == "POST" and path.endswith("/prekeys"):
            return httpx.Response(status, json=body)
        return original(method, path, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(bob.api, "request", rejected_upload)
        for _ in range(2):
            with pytest.raises(ClientError, match="Prekey upload remains pending"):
                bob.refill(3)
            assert len(bob.account.one_time_keys) == 3
            assert len(bob.vault.state["prekey_upload"]["one_time_prekeys"]) == 3


def test_refill_duplicate_verdict_requires_a_previously_durable_attempt(pair, monkeypatch):
    _alice, bob, _conversation = pair
    original = bob.api.request

    def unexpected_duplicate(method, path, **kwargs):
        if method == "POST" and path.endswith("/prekeys"):
            return httpx.Response(422, json={"detail": "Không được sử dụng lại one-time prekey."})
        return original(method, path, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(bob.api, "request", unexpected_duplicate)
        with pytest.raises(ClientError, match="Prekey upload remains pending"):
            bob.refill(3)
    assert len(bob.account.one_time_keys) == 3
    assert bob.vault.state["prekey_upload"]["attempted"] is True


def test_pin_stores_only_fingerprint_derived_from_the_verified_identity(pair, monkeypatch):
    alice, bob, _conversation = pair
    legitimate = alice.request("GET", "/api/e2ee/users/private.bob/prekey-bundle", params={"device_id": bob.device_id})
    legitimate["fingerprint"] = "0" * 64
    with monkeypatch.context() as patch:
        patch.setattr(alice, "request", lambda *args, **kwargs: legitimate)
        result = alice.pin_peer("private.bob", bob.fingerprint, bob.device_id)
    assert result["fingerprint"] == bob.fingerprint
    assert alice.vault.state["peers"][bob.device_id]["fingerprint"] == bob.fingerprint


def test_pin_rejects_a_different_returned_device_even_with_the_verified_key(pair, monkeypatch):
    alice, bob, _conversation = pair
    legitimate = alice.request("GET", "/api/e2ee/users/private.bob/prekey-bundle", params={"device_id": bob.device_id})
    legitimate["device_id"] = str(uuid.uuid4())
    before = copy.deepcopy(alice.vault.state)
    with monkeypatch.context() as patch:
        patch.setattr(alice, "request", lambda *args, **kwargs: legitimate)
        with pytest.raises(ClientError, match="does not match the requested device"):
            alice.pin_peer("private.bob", bob.fingerprint, bob.device_id)
    assert alice.vault.state == before


@pytest.mark.parametrize("substitute_device", [False, True])
def test_automatic_repin_uses_pinned_key_instead_of_relay_fingerprint_label(pair, monkeypatch, substitute_device):
    alice, bob, conversation = pair
    alice.send(conversation, bob.device_id, "The initial legitimate conversation")
    second = alice.new_conversation("private.bob")
    attacker = e2ee_client.olm.Account()
    attacker.generate_one_time_keys(1)
    attacker_identity = e2ee_client._public_url(attacker.ed25519_key.to_base64())
    attacker_fingerprint = safety_fingerprint(attacker_identity)
    # Also cover existing profiles written by an earlier client that stored
    # the relay's unverified label, before this version normalized it.
    alice.vault.state["peers"][bob.device_id]["fingerprint"] = attacker_fingerprint
    alice._save()
    malicious = {"device_id": str(uuid.uuid4()) if substitute_device else bob.device_id,
                 "identity_key": attacker_identity, "signed_prekey": encode_base64url(attacker.curve25519_key.to_bytes()),
                 "signed_prekey_signature": e2ee_client._public_url(attacker.sign(
                     attacker.curve25519_key.to_bytes()).to_base64()),
                 "one_time_prekey": e2ee_client._public_url(next(iter(attacker.one_time_keys.values())).to_base64()),
                 "fingerprint": attacker_fingerprint}
    original = alice.request
    before = copy.deepcopy(alice.vault.state)

    def substituted_bundle(method, path, **kwargs):
        if path.endswith("/prekey-bundle"):
            return malicious
        return original(method, path, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(alice, "request", substituted_bundle)
        with pytest.raises(ClientError, match="requested device|Fingerprint mismatch"):
            alice.prepare(second, bob.device_id, "Relay must never receive ciphertext encrypted to its keys")
    assert alice.vault.state == before
    assert not alice.vault.state["outbox"]
