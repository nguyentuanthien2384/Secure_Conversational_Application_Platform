"""Server-side boundary helpers for Private E2EE mode.

This module deliberately does **not** implement encryption, decryption, key
generation, Double Ratchet state, skipped-message-key handling, or MLS tree
state.  Double Ratchet and RFC 9420 MLS must run in a mature, audited client
library.  The server is limited to validating public identity proofs and
opaque, size-bounded ciphertext envelopes used for routing and replay control.

Private identity keys and conversation/session keys are never accepted by any
API in this module.  Keeping that boundary explicit is what makes "the server
cannot read the conversation" a testable architectural property rather than a
label placed on ordinary server-side encryption.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Protocol identifiers are routing metadata only.  The cryptographic protocol
# implementation and its state belong to an audited client library.
PROTOCOL_DOUBLE_RATCHET = "double-ratchet"
PROTOCOL_MLS = "mls-rfc9420"
DOUBLE_RATCHET_PROTOCOL = PROTOCOL_DOUBLE_RATCHET
MLS_PROTOCOL = PROTOCOL_MLS
SUPPORTED_E2EE_PROTOCOLS = frozenset({PROTOCOL_DOUBLE_RATCHET, PROTOCOL_MLS})

CANONICAL_JSON_VERSION = 1
E2EE_ENVELOPE_VERSION = 1
REPLAY_KEY_VERSION = 1

ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64
MIN_CHALLENGE_BYTES = 16
MAX_CHALLENGE_BYTES = 64

# A Double Ratchet header is normally tiny.  16 KiB leaves ample room for
# protocol evolution while preventing a field advertised as a header from
# becoming an unbounded allocation.  Ciphertext is intentionally capped before
# it reaches persistence; larger attachments need a separate chunked E2EE path.
MAX_E2EE_HEADER_BYTES = 16 * 1024
MAX_E2EE_CIPHERTEXT_BYTES = 1024 * 1024
MIN_E2EE_CIPHERTEXT_BYTES = 16
MAX_E2EE_EPOCH = (1 << 63) - 1

DEVICE_POSSESSION_SCHEMA = "scap.e2ee.device-possession"
DEVICE_APPROVAL_SCHEMA = "scap.e2ee.device-approval"
SAFETY_FINGERPRINT_SCHEMA = "scap.e2ee.safety-fingerprint"
REPLAY_KEY_SCHEMA = "scap.e2ee.replay-key"

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*={0,2}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]*$")
_SCHEMA_RE = re.compile(r"^[a-z][a-z0-9.-]{2,95}$")
_MAX_IDENTIFIER_LENGTH = 128
_MAX_CANONICAL_DEPTH = 16
_MAX_CANONICAL_ITEMS = 256
_MIN_JSON_INTEGER = -(1 << 63)
_MAX_JSON_INTEGER = (1 << 63) - 1


class E2EEValidationError(ValueError):
    """An E2EE boundary value is malformed or outside a safe server limit."""


def encode_base64url(value: bytes) -> str:
    """Return canonical padded RFC 4648 base64url for public/opaque bytes."""

    if not isinstance(value, bytes):
        raise TypeError("value phải là bytes.")
    return base64.urlsafe_b64encode(value).decode("ascii")


def decode_base64_strict(
    value: str,
    *,
    field: str = "value",
    min_bytes: int = 1,
    max_bytes: int | None = None,
    exact_bytes: int | None = None,
) -> bytes:
    """Decode canonical base64url without accepting whitespace or mixed alphabets.

    Padded and unpadded base64url are both accepted because both forms are
    common at API boundaries.  Re-encoding must reproduce the exact unpadded
    representation, which rejects non-zero pad bits and other ambiguous forms.
    Standard-base64 ``+``/``/``, whitespace, interior padding, and excessive
    padding are rejected.
    """

    if not isinstance(value, str):
        raise E2EEValidationError(f"{field} phải là chuỗi base64url.")
    if min_bytes < 0:
        raise ValueError("min_bytes không được âm.")
    if max_bytes is not None and max_bytes < min_bytes:
        raise ValueError("max_bytes phải lớn hơn hoặc bằng min_bytes.")
    if exact_bytes is not None and exact_bytes < 0:
        raise ValueError("exact_bytes không được âm.")
    if not _BASE64URL_RE.fullmatch(value):
        raise E2EEValidationError(f"{field} không phải base64url canonical hợp lệ.")

    core = value.rstrip("=")
    explicit_padding = len(value) - len(core)
    if not core and min_bytes:
        raise E2EEValidationError(f"{field} không được rỗng.")
    if len(core) % 4 == 1:
        raise E2EEValidationError(f"{field} có độ dài base64url không hợp lệ.")
    required_padding = (-len(core)) % 4
    if explicit_padding not in (0, required_padding):
        raise E2EEValidationError(f"{field} có padding base64url không canonical.")

    # Check the decoded-size upper bound before allocating the output.
    estimated_bytes = (len(core) * 6) // 8
    if exact_bytes is not None and estimated_bytes > exact_bytes:
        raise E2EEValidationError(f"{field} phải giải mã thành đúng {exact_bytes} byte.")
    if max_bytes is not None and estimated_bytes > max_bytes:
        raise E2EEValidationError(f"{field} vượt quá giới hạn {max_bytes} byte.")

    padded = core + ("=" * required_padding)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise E2EEValidationError(f"{field} không phải base64url hợp lệ.") from exc

    canonical_core = encode_base64url(decoded).rstrip("=")
    if canonical_core != core:
        raise E2EEValidationError(f"{field} chứa pad bits không canonical.")
    if exact_bytes is not None and len(decoded) != exact_bytes:
        raise E2EEValidationError(f"{field} phải giải mã thành đúng {exact_bytes} byte.")
    if len(decoded) < min_bytes:
        raise E2EEValidationError(f"{field} phải có ít nhất {min_bytes} byte.")
    if max_bytes is not None and len(decoded) > max_bytes:
        raise E2EEValidationError(f"{field} vượt quá giới hạn {max_bytes} byte.")
    return decoded


# Short alias useful to schema/integration code.
strict_b64decode = decode_base64_strict


def _canonical_value(value: Any, *, depth: int = 0) -> Any:
    if depth > _MAX_CANONICAL_DEPTH:
        raise E2EEValidationError("Dữ liệu canonical JSON lồng quá sâu.")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not _MIN_JSON_INTEGER <= value <= _MAX_JSON_INTEGER:
            raise E2EEValidationError("Số nguyên canonical JSON nằm ngoài miền signed 64-bit.")
        return value
    if isinstance(value, float):
        # Cross-runtime formatting of floats is an unnecessary source of
        # signature ambiguity.  Protocol payloads here do not need floats.
        raise E2EEValidationError("Canonical JSON không chấp nhận số thực.")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, Mapping):
        if len(value) > _MAX_CANONICAL_ITEMS:
            raise E2EEValidationError("Canonical JSON có quá nhiều trường.")
        result: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            if not isinstance(raw_key, str):
                raise E2EEValidationError("Mọi khóa canonical JSON phải là chuỗi.")
            key = unicodedata.normalize("NFC", raw_key)
            if key in result:
                raise E2EEValidationError("Khóa canonical JSON trùng nhau sau Unicode NFC.")
            result[key] = _canonical_value(raw_value, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        if len(value) > _MAX_CANONICAL_ITEMS:
            raise E2EEValidationError("Canonical JSON có quá nhiều phần tử.")
        return [_canonical_value(item, depth=depth + 1) for item in value]
    raise E2EEValidationError(
        "Canonical JSON chỉ chấp nhận null, bool, số nguyên, chuỗi, list và object."
    )


def canonical_json_bytes(
    payload: Mapping[str, Any],
    *,
    schema: str,
    version: int = CANONICAL_JSON_VERSION,
) -> bytes:
    """Return deterministic, UTF-8, domain-separated and versioned JSON.

    Every signed statement is wrapped as ``{schema, version, payload}`` so the
    same signature cannot be reinterpreted as another kind of statement.  Keys
    are sorted, strings are NFC-normalized, insignificant whitespace is
    removed, floats and out-of-range integers are rejected, and NaN is never
    permitted.  A version change necessarily changes the signed bytes.
    """

    if not isinstance(payload, Mapping):
        raise E2EEValidationError("payload canonical JSON phải là object.")
    if not isinstance(schema, str) or not _SCHEMA_RE.fullmatch(schema):
        raise E2EEValidationError("schema canonical JSON không hợp lệ.")
    if isinstance(version, bool) or not isinstance(version, int) or not 1 <= version <= 2**31 - 1:
        raise E2EEValidationError("version canonical JSON phải là số nguyên dương.")
    document = {
        "payload": _canonical_value(payload),
        "schema": schema,
        "version": version,
    }
    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


# Backwards-friendly concise name for callers that do not need to emphasize
# the return type.
canonical_json = canonical_json_bytes


def _identifier(value: str, *, field: str) -> str:
    if not isinstance(value, str):
        raise E2EEValidationError(f"{field} phải là chuỗi.")
    if len(value) > _MAX_IDENTIFIER_LENGTH or not _IDENTIFIER_RE.fullmatch(value):
        raise E2EEValidationError(
            f"{field} phải dài 1-{_MAX_IDENTIFIER_LENGTH} ký tự ASCII định danh an toàn."
        )
    return value


def _protocol(value: str) -> str:
    if value not in SUPPORTED_E2EE_PROTOCOLS:
        supported = ", ".join(sorted(SUPPORTED_E2EE_PROTOCOLS))
        raise E2EEValidationError(f"protocol không được hỗ trợ; chỉ chấp nhận: {supported}.")
    return value


def _canonical_public_key(public_key_b64: str, *, field: str) -> tuple[str, bytes]:
    raw = decode_base64_strict(
        public_key_b64,
        field=field,
        exact_bytes=ED25519_PUBLIC_KEY_BYTES,
    )
    return encode_base64url(raw), raw


def _canonical_challenge(challenge_b64: str, *, field: str) -> str:
    raw = decode_base64_strict(
        challenge_b64,
        field=field,
        min_bytes=MIN_CHALLENGE_BYTES,
        max_bytes=MAX_CHALLENGE_BYTES,
    )
    return encode_base64url(raw)


def build_device_possession_message(
    *,
    account_id: str,
    device_id: str,
    identity_public_key_b64: str,
    challenge_b64: str,
) -> bytes:
    """Build the statement a new device signs to prove key possession.

    A random, single-use server challenge must be persisted and consumed by the
    integration layer.  This helper only constructs unambiguous signed bytes;
    it never receives a private key and never signs on the server.
    """

    public_key, _ = _canonical_public_key(
        identity_public_key_b64, field="identity_public_key"
    )
    return canonical_json_bytes(
        {
            "account_id": _identifier(account_id, field="account_id"),
            "challenge": _canonical_challenge(challenge_b64, field="challenge"),
            "device_id": _identifier(device_id, field="device_id"),
            "identity_public_key": public_key,
        },
        schema=DEVICE_POSSESSION_SCHEMA,
    )


def verify_ed25519_signature(
    public_key_b64: str,
    signature_b64: str,
    message: bytes,
) -> bool:
    """Verify an Ed25519 signature using public material only.

    Malformed input and a cryptographically invalid signature both return
    ``False``.  Call :func:`decode_base64_strict` separately when an API needs
    to report detailed validation errors to a client.
    """

    if not isinstance(message, bytes):
        return False
    try:
        public_key = decode_base64_strict(
            public_key_b64,
            field="public_key",
            exact_bytes=ED25519_PUBLIC_KEY_BYTES,
        )
        signature = decode_base64_strict(
            signature_b64,
            field="signature",
            exact_bytes=ED25519_SIGNATURE_BYTES,
        )
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (E2EEValidationError, InvalidSignature, ValueError):
        return False
    return True


def verify_device_possession(
    public_key_b64: str,
    signature_b64: str,
    *,
    account_id: str,
    device_id: str,
    challenge_b64: str,
) -> bool:
    """Verify that a registering device controls its advertised Ed25519 key.

    The integration layer must additionally expire and atomically consume the
    challenge.  Ratchet/MLS identity state remains in an audited client library.
    """

    try:
        statement = build_device_possession_message(
            account_id=account_id,
            device_id=device_id,
            identity_public_key_b64=public_key_b64,
            challenge_b64=challenge_b64,
        )
    except E2EEValidationError:
        return False
    return verify_ed25519_signature(public_key_b64, signature_b64, statement)


def build_device_approval_message(
    *,
    account_id: str,
    approver_device_id: str,
    new_device_id: str,
    new_device_public_key_b64: str,
    approval_challenge_b64: str,
) -> bytes:
    """Build a trusted-device statement approving one exact new device/key.

    The single-use approval challenge prevents a captured approval from adding
    another device later.  The new device must separately pass possession
    verification; approval alone is not proof that it owns the advertised key.
    No private key is accepted or retained by the server.
    """

    new_public_key, _ = _canonical_public_key(
        new_device_public_key_b64,
        field="new_device_public_key",
    )
    return canonical_json_bytes(
        {
            "account_id": _identifier(account_id, field="account_id"),
            "approval_challenge": _canonical_challenge(
                approval_challenge_b64,
                field="approval_challenge",
            ),
            "approver_device_id": _identifier(
                approver_device_id,
                field="approver_device_id",
            ),
            "new_device_id": _identifier(new_device_id, field="new_device_id"),
            "new_device_public_key": new_public_key,
        },
        schema=DEVICE_APPROVAL_SCHEMA,
    )


def verify_device_approval(
    approver_public_key_b64: str,
    signature_b64: str,
    *,
    account_id: str,
    approver_device_id: str,
    new_device_id: str,
    new_device_public_key_b64: str,
    approval_challenge_b64: str,
) -> bool:
    """Verify approval signed by an already trusted device's public key."""

    try:
        statement = build_device_approval_message(
            account_id=account_id,
            approver_device_id=approver_device_id,
            new_device_id=new_device_id,
            new_device_public_key_b64=new_device_public_key_b64,
            approval_challenge_b64=approval_challenge_b64,
        )
    except E2EEValidationError:
        return False
    return verify_ed25519_signature(approver_public_key_b64, signature_b64, statement)


def safety_fingerprint(
    *identity_public_keys_b64: str,
    protocol: str = PROTOCOL_DOUBLE_RATCHET,
) -> str:
    """Return a stable, order-independent fingerprint for verified identity keys.

    Padding differences and participant order do not change the result.  Any
    identity-key or protocol change does.  The returned full SHA-256 digest is
    grouped for human comparison; clients should show a key-change warning and
    require re-verification rather than silently accepting a changed value.
    """

    _protocol(protocol)
    if not identity_public_keys_b64:
        raise E2EEValidationError("Cần ít nhất một identity public key.")
    if len(identity_public_keys_b64) > _MAX_CANONICAL_ITEMS:
        raise E2EEValidationError("Có quá nhiều identity public key.")

    raw_keys = [
        decode_base64_strict(
            value,
            field=f"identity_public_keys[{index}]",
            exact_bytes=ED25519_PUBLIC_KEY_BYTES,
        )
        for index, value in enumerate(identity_public_keys_b64)
    ]
    if len(set(raw_keys)) != len(raw_keys):
        raise E2EEValidationError("Danh sách fingerprint chứa identity key trùng lặp.")
    canonical_keys = [encode_base64url(value) for value in sorted(raw_keys)]
    digest = hashlib.sha256(
        canonical_json_bytes(
            {"identity_public_keys": canonical_keys, "protocol": protocol},
            schema=SAFETY_FINGERPRINT_SCHEMA,
        )
    ).hexdigest().upper()
    return " ".join(digest[index : index + 4] for index in range(0, len(digest), 4))


@dataclass(frozen=True, slots=True)
class OpaqueEnvelope:
    """Validated ciphertext routing record; its bytes are never interpreted.

    ``header_b64`` is an opaque Double Ratchet/MLS wire value.  Ratchet counters,
    MLS commits/welcomes, epoch transitions, authentication, and plaintext
    processing must all be handled by an audited client library.
    """

    version: int
    protocol: str
    recipient: str
    epoch: int
    client_message_id: str
    header_b64: str
    ciphertext_b64: str
    header_size: int
    ciphertext_size: int
    sender_device_id: str | None = None

    def as_dict(self) -> dict[str, str | int | None]:
        result: dict[str, str | int | None] = {
            "version": self.version,
            "protocol": self.protocol,
            "recipient": self.recipient,
            "epoch": self.epoch,
            "client_message_id": self.client_message_id,
            "header": self.header_b64,
            "ciphertext": self.ciphertext_b64,
        }
        if self.sender_device_id is not None:
            result["sender_device_id"] = self.sender_device_id
        return result

    @property
    def replay_key(self) -> str:
        return make_replay_key(
            recipient=self.recipient,
            client_message_id=self.client_message_id,
            sender_device_id=self.sender_device_id,
        )


def _one_alias(data: Mapping[str, Any], canonical: str, alias: str) -> Any:
    has_canonical = canonical in data
    has_alias = alias in data
    if has_canonical and has_alias:
        raise E2EEValidationError(f"Không được gửi đồng thời {canonical} và {alias}.")
    if not has_canonical and not has_alias:
        raise E2EEValidationError(f"Thiếu trường {canonical}.")
    return data[canonical] if has_canonical else data[alias]


def validate_opaque_envelope(
    envelope: Mapping[str, Any],
    *,
    expected_recipient: str | None = None,
    max_header_bytes: int = MAX_E2EE_HEADER_BYTES,
    max_ciphertext_bytes: int = MAX_E2EE_CIPHERTEXT_BYTES,
) -> OpaqueEnvelope:
    """Validate an E2EE envelope without parsing or decrypting protocol bytes.

    The accepted aliases (``recipient_id``, ``header_b64``, and
    ``ciphertext_b64``) ease API migration, but supplying both spellings is
    rejected to prevent ambiguous signed/stored data.  Unknown fields are also
    rejected: in particular, there is intentionally no ``plaintext``, private
    key, or conversation-key field.
    """

    if not isinstance(envelope, Mapping):
        raise E2EEValidationError("E2EE envelope phải là JSON object.")
    if not 1 <= max_header_bytes <= MAX_E2EE_HEADER_BYTES:
        raise ValueError(f"max_header_bytes phải nằm trong 1-{MAX_E2EE_HEADER_BYTES}.")
    if not MIN_E2EE_CIPHERTEXT_BYTES <= max_ciphertext_bytes <= MAX_E2EE_CIPHERTEXT_BYTES:
        raise ValueError(
            "max_ciphertext_bytes phải nằm trong "
            f"{MIN_E2EE_CIPHERTEXT_BYTES}-{MAX_E2EE_CIPHERTEXT_BYTES}."
        )

    allowed = {
        "version",
        "protocol",
        "recipient",
        "recipient_id",
        "epoch",
        "client_message_id",
        "header",
        "header_b64",
        "ciphertext",
        "ciphertext_b64",
        "sender_device_id",
    }
    unknown = set(envelope) - allowed
    if unknown:
        names = ", ".join(sorted(str(key) for key in unknown))
        raise E2EEValidationError(f"E2EE envelope chứa trường không được phép: {names}.")

    version = envelope.get("version")
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version != E2EE_ENVELOPE_VERSION
    ):
        raise E2EEValidationError(
            f"version envelope phải bằng {E2EE_ENVELOPE_VERSION}; không tự động downgrade."
        )
    protocol = envelope.get("protocol")
    if not isinstance(protocol, str):
        raise E2EEValidationError("protocol phải là chuỗi.")
    protocol = _protocol(protocol)

    recipient = _identifier(
        _one_alias(envelope, "recipient", "recipient_id"),
        field="recipient",
    )
    if expected_recipient is not None:
        expected = _identifier(expected_recipient, field="expected_recipient")
        if recipient != expected:
            raise E2EEValidationError("recipient không khớp tài nguyên đã xác thực.")

    epoch = envelope.get("epoch")
    if (
        isinstance(epoch, bool)
        or not isinstance(epoch, int)
        or not 0 <= epoch <= MAX_E2EE_EPOCH
    ):
        raise E2EEValidationError(f"epoch phải là số nguyên trong 0-{MAX_E2EE_EPOCH}.")
    client_message_id = _identifier(
        envelope.get("client_message_id"),
        field="client_message_id",
    )

    sender_device_raw = envelope.get("sender_device_id")
    sender_device_id = (
        None
        if sender_device_raw is None
        else _identifier(sender_device_raw, field="sender_device_id")
    )

    header = decode_base64_strict(
        _one_alias(envelope, "header", "header_b64"),
        field="header",
        min_bytes=1,
        max_bytes=max_header_bytes,
    )
    ciphertext = decode_base64_strict(
        _one_alias(envelope, "ciphertext", "ciphertext_b64"),
        field="ciphertext",
        min_bytes=MIN_E2EE_CIPHERTEXT_BYTES,
        max_bytes=max_ciphertext_bytes,
    )

    return OpaqueEnvelope(
        version=version,
        protocol=protocol,
        recipient=recipient,
        epoch=epoch,
        client_message_id=client_message_id,
        header_b64=encode_base64url(header),
        ciphertext_b64=encode_base64url(ciphertext),
        header_size=len(header),
        ciphertext_size=len(ciphertext),
        sender_device_id=sender_device_id,
    )


def make_replay_key(
    *,
    recipient: str,
    client_message_id: str,
    sender_device_id: str | None = None,
) -> str:
    """Build a safe deterministic store key for idempotency/replay rejection.

    Epoch and ciphertext are deliberately excluded.  A retry that mutates the
    epoch or ciphertext but reuses the same sender/recipient client-message ID
    must still collide with the original record instead of appearing as a new
    message.  The integration layer must insert this key atomically (for
    example, a database unique constraint or Redis ``SET NX``).
    """

    payload: dict[str, str] = {
        "client_message_id": _identifier(client_message_id, field="client_message_id"),
        "recipient": _identifier(recipient, field="recipient"),
    }
    if sender_device_id is not None:
        payload["sender_device_id"] = _identifier(
            sender_device_id,
            field="sender_device_id",
        )
    digest = hashlib.sha256(
        canonical_json_bytes(payload, schema=REPLAY_KEY_SCHEMA)
    ).hexdigest()
    return f"e2ee:replay:v{REPLAY_KEY_VERSION}:{digest}"


# Concise name requested by delivery/storage integrations.
replay_key = make_replay_key


__all__ = [
    "CANONICAL_JSON_VERSION",
    "DOUBLE_RATCHET_PROTOCOL",
    "E2EE_ENVELOPE_VERSION",
    "E2EEValidationError",
    "MAX_E2EE_CIPHERTEXT_BYTES",
    "MAX_E2EE_HEADER_BYTES",
    "MLS_PROTOCOL",
    "OpaqueEnvelope",
    "PROTOCOL_DOUBLE_RATCHET",
    "PROTOCOL_MLS",
    "SUPPORTED_E2EE_PROTOCOLS",
    "build_device_approval_message",
    "build_device_possession_message",
    "canonical_json",
    "canonical_json_bytes",
    "decode_base64_strict",
    "encode_base64url",
    "make_replay_key",
    "replay_key",
    "safety_fingerprint",
    "strict_b64decode",
    "validate_opaque_envelope",
    "verify_device_approval",
    "verify_device_possession",
    "verify_ed25519_signature",
]
