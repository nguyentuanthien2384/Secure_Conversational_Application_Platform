"""Untrusted relay/peer strings cannot control the E2EE terminal display."""
from __future__ import annotations

import json
from contextlib import ExitStack
from types import SimpleNamespace

import pytest

from clients import private_chat
from clients.e2ee_client import EncryptedVault, PrivateClient
from tests.conftest import register_and_login


@pytest.mark.parametrize("control", ["\x1b", "\x7f", "\x9b", "\u202e", "\u2066", "\u200f",
                                     "\ufeff", "\ud800", "\U000e0001", "\u2028", "\u2029"])
def test_terminal_json_preserves_vietnamese_and_escapes_nonprinting_characters(control):
    text = f"Xin chào nhà tuyển dụng {control} giả mạo"
    rendered = private_chat.terminal_json({"text": text})
    assert "Xin chào nhà tuyển dụng" in rendered
    assert control not in rendered
    assert json.loads(rendered) == {"text": text}
    rendered.encode("utf-8")  # Lone surrogates must not crash the console.


@pytest.mark.parametrize("command", ["register", "offer", "peers", "new peer", "retry", "refill"])
def test_relay_metadata_is_escaped_in_terminal_commands(monkeypatch, capsys, command):
    untrusted = "Tiếng Việt \x9b2J\u202etrusted-admin"
    result = {"username": untrusted, "device_id": untrusted, "fingerprint": untrusted}
    client = SimpleNamespace(
        register_device=lambda: result, registration_offer=lambda: result,
        new_conversation=lambda username: untrusted, flush=lambda: result,
        refill=lambda count: result, vault=SimpleNamespace(state={"peers": {"peer": result}}),
    )
    commands = iter([command, "quit"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(commands))
    private_chat.interact(client)
    displayed = capsys.readouterr().out
    assert "Tiếng Việt" in displayed
    assert "\x9b" not in displayed and "\u202e" not in displayed
    assert "\\u009b" in displayed and "\\u202e" in displayed


def test_pinned_peer_message_is_decrypted_but_control_characters_are_only_displayed_as_escapes(
    client, tmp_path, monkeypatch, capsys,
):
    pytest.importorskip("vodozemac", reason="Install the standalone E2EE client extra")
    text = "Tin nhắn tiếng Việt từ peer đã xác minh. \x1b[2J\x9b2J\u202e:sender_device"
    with ExitStack() as stack:
        alice_vault = stack.enter_context(EncryptedVault(tmp_path / "alice", "Private vault phrase 2026!"))
        bob_vault = stack.enter_context(EncryptedVault(tmp_path / "bob", "Private vault phrase 2026!"))
        alice = PrivateClient(client, register_and_login(client, "terminal.alice"), alice_vault,
                              server="http://127.0.0.1:8000")
        bob = PrivateClient(client, register_and_login(client, "terminal.bob"), bob_vault,
                            server="http://127.0.0.1:8000")
        alice.register_device()
        bob.register_device()
        alice.pin_peer("terminal.bob", bob.fingerprint, bob.device_id)
        bob.pin_peer("terminal.alice", alice.fingerprint, alice.device_id)
        conversation = alice.new_conversation("terminal.bob")
        alice.send(conversation, bob.device_id, text)
        commands = iter([f"receive {conversation}", "quit"])
        monkeypatch.setattr("builtins.input", lambda prompt: next(commands))
        private_chat.interact(bob)
        displayed = capsys.readouterr().out
        messages = [json.loads(line) for line in displayed.splitlines() if line.startswith("{")]
        assert messages == [{"sender_device": alice.device_id, "text": text}]
        assert "Tin nhắn tiếng Việt từ peer đã xác minh." in displayed
        assert "\x1b" not in displayed and "\x9b" not in displayed and "\u202e" not in displayed
        assert "\\u001b" in displayed and "\\u009b" in displayed and "\\u202e" in displayed
        assert bob.receive(conversation) == []  # Display escaping does not alter the durable cursor.
