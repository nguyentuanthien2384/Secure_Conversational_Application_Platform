from __future__ import annotations

import base64

import pytest

from src.app.security import CryptoService


def test_aes_gcm_roundtrip_and_tamper_detection():
    service = CryptoService(base64.urlsafe_b64encode(b"A" * 32).decode("ascii"))
    ciphertext, nonce, version = service.encrypt("Xin chào Phenikaa", "session-1", "user")

    assert service.decrypt(ciphertext, nonce, "session-1", "user", version) == "Xin chào Phenikaa"

    raw = bytearray(base64.urlsafe_b64decode(ciphertext.encode("ascii")))
    raw[0] ^= 1
    tampered = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(ValueError, match="đã bị thay đổi"):
        service.decrypt(tampered, nonce, "session-1", "user", version)


def test_aad_prevents_ciphertext_copy_to_another_session():
    service = CryptoService(base64.urlsafe_b64encode(b"B" * 32).decode("ascii"))
    ciphertext, nonce, version = service.encrypt("secret", "session-a", "user")

    with pytest.raises(ValueError):
        service.decrypt(ciphertext, nonce, "session-b", "user", version)
