from __future__ import annotations

import inspect

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.app import e2ee
from src.app.e2ee import (
    PROTOCOL_DOUBLE_RATCHET,
    PROTOCOL_MLS,
    E2EEValidationError,
    build_device_approval_message,
    build_device_possession_message,
    canonical_json_bytes,
    decode_base64_strict,
    encode_base64url,
    make_replay_key,
    safety_fingerprint,
    validate_opaque_envelope,
    verify_device_approval,
    verify_device_possession,
)


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, encode_base64url(public_bytes)


def _sign(private_key: Ed25519PrivateKey, message: bytes) -> str:
    return encode_base64url(private_key.sign(message))


def _envelope(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "version": 1,
        "protocol": PROTOCOL_DOUBLE_RATCHET,
        "recipient": "conversation-123",
        "sender_device_id": "device-a",
        "epoch": 7,
        "client_message_id": "message-001",
        "header": encode_base64url(b"ratchet-header"),
        "ciphertext": encode_base64url(b"C" * 48),
    }
    value.update(changes)
    return value


def test_canonical_json_is_deterministic_versioned_and_unicode_normalized():
    first = canonical_json_bytes(
        {"z": [3, True, None], "name": "e\u0301"},
        schema="scap.test.statement",
    )
    second = canonical_json_bytes(
        {"name": "é", "z": [3, True, None]},
        schema="scap.test.statement",
    )

    assert first == second
    assert first == (
        b'{"payload":{"name":"\xc3\xa9","z":[3,true,null]},'
        b'"schema":"scap.test.statement","version":1}'
    )
    assert canonical_json_bytes(
        {"name": "é", "z": [3, True, None]},
        schema="scap.test.statement",
        version=2,
    ) != first


@pytest.mark.parametrize(
    "payload",
    [
        {"number": 1.25},
        {"number": float("nan")},
        {"number": 1 << 64},
        {1: "non-string key"},
        {"binary": b"not-json"},
    ],
)
def test_canonical_json_rejects_cross_runtime_ambiguous_values(payload: dict[object, object]):
    with pytest.raises(E2EEValidationError):
        canonical_json_bytes(payload, schema="scap.test.statement")  # type: ignore[arg-type]


def test_canonical_json_rejects_unicode_key_collision():
    with pytest.raises(E2EEValidationError, match="trùng nhau"):
        canonical_json_bytes(
            {"e\u0301": 1, "é": 2},
            schema="scap.test.statement",
        )


def test_strict_base64url_accepts_padded_and_unpadded_canonical_forms():
    raw = b"\xfb\xff\x00private-looking-but-opaque"
    padded = encode_base64url(raw)

    assert decode_base64_strict(padded) == raw
    assert decode_base64_strict(padded.rstrip("=")) == raw


@pytest.mark.parametrize(
    "value",
    [
        "YW Jj",  # whitespace
        "YWJj\n",  # newline
        "+///",  # standard-base64 alphabet is not base64url
        "A",  # impossible length
        "AA=",  # wrong amount of explicit padding
        "AB",  # non-zero/ambiguous pad bits (canonical form is AA)
        "YW=Jj",  # interior padding
    ],
)
def test_strict_base64url_rejects_ambiguous_or_non_urlsafe_input(value: str):
    with pytest.raises(E2EEValidationError):
        decode_base64_strict(value)


def test_strict_base64url_checks_exact_and_max_decoded_size():
    value = encode_base64url(b"12345")
    with pytest.raises(E2EEValidationError, match="đúng 4 byte"):
        decode_base64_strict(value, exact_bytes=4)
    with pytest.raises(E2EEValidationError, match="giới hạn 4 byte"):
        decode_base64_strict(value, max_bytes=4)


def test_device_possession_proof_is_bound_to_account_device_key_and_challenge():
    private_key, public_key = _keypair()
    challenge = encode_base64url(b"P" * 32)
    statement = build_device_possession_message(
        account_id="account-1",
        device_id="phone-1",
        identity_public_key_b64=public_key,
        challenge_b64=challenge,
    )
    signature = _sign(private_key, statement)

    assert verify_device_possession(
        public_key,
        signature,
        account_id="account-1",
        device_id="phone-1",
        challenge_b64=challenge,
    )
    assert not verify_device_possession(
        public_key,
        signature,
        account_id="account-2",
        device_id="phone-1",
        challenge_b64=challenge,
    )
    assert not verify_device_possession(
        public_key,
        signature,
        account_id="account-1",
        device_id="phone-2",
        challenge_b64=challenge,
    )
    assert not verify_device_possession(
        public_key,
        signature,
        account_id="account-1",
        device_id="phone-1",
        challenge_b64=encode_base64url(b"Q" * 32),
    )


def test_device_possession_rejects_wrong_or_malformed_public_material():
    private_key, public_key = _keypair()
    _, other_public_key = _keypair()
    challenge = encode_base64url(b"P" * 32)
    statement = build_device_possession_message(
        account_id="account-1",
        device_id="phone-1",
        identity_public_key_b64=public_key,
        challenge_b64=challenge,
    )
    signature = _sign(private_key, statement)

    assert not verify_device_possession(
        other_public_key,
        signature,
        account_id="account-1",
        device_id="phone-1",
        challenge_b64=challenge,
    )
    assert not verify_device_possession(
        public_key,
        "not base64!",
        account_id="account-1",
        device_id="phone-1",
        challenge_b64=challenge,
    )
    assert not verify_device_possession(
        public_key,
        signature,
        account_id="account-1",
        device_id="phone-1",
        challenge_b64=encode_base64url(b"short"),
    )


def test_device_approval_binds_approver_and_exact_new_device_key():
    approver_private, approver_public = _keypair()
    _, new_public = _keypair()
    _, replacement_public = _keypair()
    challenge = encode_base64url(b"A" * 32)
    statement = build_device_approval_message(
        account_id="account-1",
        approver_device_id="trusted-laptop",
        new_device_id="new-phone",
        new_device_public_key_b64=new_public,
        approval_challenge_b64=challenge,
    )
    signature = _sign(approver_private, statement)

    assert verify_device_approval(
        approver_public,
        signature,
        account_id="account-1",
        approver_device_id="trusted-laptop",
        new_device_id="new-phone",
        new_device_public_key_b64=new_public,
        approval_challenge_b64=challenge,
    )
    assert not verify_device_approval(
        approver_public,
        signature,
        account_id="account-1",
        approver_device_id="trusted-laptop",
        new_device_id="new-phone",
        new_device_public_key_b64=replacement_public,
        approval_challenge_b64=challenge,
    )
    assert not verify_device_approval(
        approver_public,
        signature,
        account_id="account-1",
        approver_device_id="untrusted-device",
        new_device_id="new-phone",
        new_device_public_key_b64=new_public,
        approval_challenge_b64=challenge,
    )


def test_safety_fingerprint_is_stable_but_changes_with_key_or_protocol():
    _, first = _keypair()
    _, second = _keypair()
    _, changed = _keypair()

    expected = safety_fingerprint(first, second)
    assert safety_fingerprint(second.rstrip("="), first.rstrip("=")) == expected
    assert safety_fingerprint(first, changed) != expected
    assert safety_fingerprint(first, second, protocol=PROTOCOL_MLS) != expected
    assert len(expected.replace(" ", "")) == 64


def test_safety_fingerprint_rejects_duplicate_or_malformed_keys():
    _, public_key = _keypair()
    with pytest.raises(E2EEValidationError, match="trùng lặp"):
        safety_fingerprint(public_key, public_key.rstrip("="))
    with pytest.raises(E2EEValidationError):
        safety_fingerprint("not-base64")


def test_valid_opaque_envelope_is_canonicalized_but_never_interpreted():
    envelope = _envelope()
    validated = validate_opaque_envelope(envelope, expected_recipient="conversation-123")

    assert validated.protocol == PROTOCOL_DOUBLE_RATCHET
    assert validated.recipient == "conversation-123"
    assert validated.epoch == 7
    assert validated.client_message_id == "message-001"
    assert validated.header_size == len(b"ratchet-header")
    assert validated.ciphertext_size == 48
    assert validated.as_dict() == envelope


def test_opaque_envelope_accepts_unambiguous_migration_aliases():
    envelope = _envelope()
    envelope["recipient_id"] = envelope.pop("recipient")
    envelope["header_b64"] = envelope.pop("header")
    envelope["ciphertext_b64"] = envelope.pop("ciphertext")

    validated = validate_opaque_envelope(envelope)
    assert validated.recipient == "conversation-123"
    assert validated.as_dict()["header"] == encode_base64url(b"ratchet-header")


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"version": 0}, "version envelope"),
        ({"version": 2}, "version envelope"),
        ({"version": 1.0}, "version envelope"),
        ({"protocol": "home-grown-ratchet"}, "protocol"),
        ({"epoch": -1}, "epoch"),
        ({"epoch": True}, "epoch"),
        ({"client_message_id": "contains whitespace"}, "client_message_id"),
        ({"recipient": "../unsafe?query"}, "recipient"),
        ({"header": "not base64!"}, "header"),
        ({"ciphertext": encode_base64url(b"too-short")}, "ciphertext"),
    ],
)
def test_opaque_envelope_rejects_invalid_metadata_or_wire_values(
    change: dict[str, object], message: str
):
    with pytest.raises(E2EEValidationError, match=message):
        validate_opaque_envelope(_envelope(**change))


def test_opaque_envelope_binds_authenticated_recipient():
    with pytest.raises(E2EEValidationError, match="không khớp"):
        validate_opaque_envelope(_envelope(), expected_recipient="another-conversation")


def test_opaque_envelope_rejects_ambiguous_aliases_and_plaintext_fields():
    with pytest.raises(E2EEValidationError, match="đồng thời"):
        validate_opaque_envelope(_envelope(recipient_id="conversation-123"))
    with pytest.raises(E2EEValidationError, match="plaintext"):
        validate_opaque_envelope(_envelope(plaintext="server must never receive this"))
    with pytest.raises(E2EEValidationError, match="private_key"):
        validate_opaque_envelope(_envelope(private_key="forbidden"))


def test_opaque_envelope_enforces_decoded_header_and_ciphertext_limits():
    with pytest.raises(E2EEValidationError, match="header.*giới hạn 4 byte"):
        validate_opaque_envelope(
            _envelope(header=encode_base64url(b"12345")),
            max_header_bytes=4,
        )
    with pytest.raises(E2EEValidationError, match="ciphertext.*giới hạn 32 byte"):
        validate_opaque_envelope(
            _envelope(ciphertext=encode_base64url(b"C" * 33)),
            max_ciphertext_bytes=32,
        )


def test_replay_key_is_stable_and_epoch_or_ciphertext_cannot_evade_it():
    first = validate_opaque_envelope(_envelope(epoch=1, ciphertext=encode_base64url(b"A" * 32)))
    mutated = validate_opaque_envelope(
        _envelope(epoch=99, ciphertext=encode_base64url(b"B" * 32))
    )

    assert first.replay_key == mutated.replay_key
    assert first.replay_key.startswith("e2ee:replay:v1:")
    assert len(first.replay_key.rsplit(":", 1)[1]) == 64
    assert first.replay_key != make_replay_key(
        recipient="conversation-123",
        sender_device_id="device-a",
        client_message_id="message-002",
    )


def test_server_module_exposes_no_private_key_or_decryption_api():
    source = inspect.getsource(e2ee)
    assert "Ed25519PrivateKey" not in source
    assert not any(name.startswith("decrypt") for name in e2ee.__all__)
    assert not any("private_key" in name for name in e2ee.__all__)
