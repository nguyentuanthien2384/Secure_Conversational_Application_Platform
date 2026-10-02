"""A software FIDO2 authenticator for tests (ES256, "none" attestation).

It builds real WebAuthn structures — clientDataJSON, authenticatorData,
CBOR attestation objects and ECDSA signatures — so the server is exercised
through py_webauthn's full verification path, not through mocks.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class SoftAuthenticator:
    def __init__(self, *, origin: str = "http://localhost:8000", rp_id: str = "localhost") -> None:
        self.origin = origin
        self.rp_id = rp_id
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(32)
        self.sign_count = 0
        self.user_handle: bytes | None = None

    def _cose_key(self) -> bytes:
        numbers = self.key.public_key().public_numbers()
        return cbor2.dumps({
            1: 2, 3: -7, -1: 1,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        })

    def _client_data(self, kind: str, challenge: str, origin: str | None) -> bytes:
        return json.dumps({
            "type": kind,
            "challenge": challenge,
            "origin": origin or self.origin,
            "crossOrigin": False,
        }, separators=(",", ":")).encode()

    def _rp_hash(self, rp_id: str | None) -> bytes:
        return hashlib.sha256((rp_id or self.rp_id).encode()).digest()

    def register(self, public_key: dict, *, origin: str | None = None, uv: bool = True) -> dict:
        self.user_handle = unb64url(public_key["user"]["id"])
        flags = FLAG_UP | FLAG_AT | (FLAG_UV if uv else 0)
        auth_data = (
            self._rp_hash(public_key["rp"]["id"])
            + bytes([flags])
            + struct.pack(">I", self.sign_count)
            + bytes(16)  # AAGUID
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + self._cose_key()
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client_data = self._client_data("webauthn.create", public_key["challenge"], origin)
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "attestationObject": b64url(attestation),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
        }

    def assert_(
        self,
        public_key: dict,
        *,
        origin: str | None = None,
        uv: bool = True,
        sign_count: int | None = None,
        user_handle: bytes | None = None,
    ) -> dict:
        if sign_count is None:
            self.sign_count += 1
            sign_count = self.sign_count
        flags = FLAG_UP | (FLAG_UV if uv else 0)
        auth_data = self._rp_hash(public_key["rpId"]) + bytes([flags]) + struct.pack(">I", sign_count)
        client_data = self._client_data("webauthn.get", public_key["challenge"], origin)
        signature = self.key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        response = {
            "clientDataJSON": b64url(client_data),
            "authenticatorData": b64url(auth_data),
            "signature": b64url(signature),
        }
        handle = user_handle if user_handle is not None else self.user_handle
        if handle is not None:
            response["userHandle"] = b64url(handle)
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": response,
            "clientExtensionResults": {},
        }
