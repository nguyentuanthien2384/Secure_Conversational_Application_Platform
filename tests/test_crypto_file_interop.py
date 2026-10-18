"""Cross-check the file format with independent Python cryptographic primitives."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SUITE = "RSA-OAEP-3072-SHA256+A256GCM"
MAGIC = b"SCAPFIL1"
PASSPHRASE = "Independent file interoperability demo passphrase"
CORE = Path(__file__).resolve().parents[1] / "src/app/ui_assets/crypto_workbench_core.js"
NODE = shutil.which("node")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def prefix(value):
    return struct.pack(">I", len(value)) + value


@pytest.fixture(scope="module")
def identity():
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = hashlib.sha256(public).hexdigest()
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    header = dict(
        format="scap-key-backup", version=1, suite=SUITE, kdf="PBKDF2-SHA256",
        iterations=600000, salt=b64(salt), publicSpki=b64(public), fingerprint=fingerprint,
    )
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000).derive(
        PASSPHRASE.encode("utf-8")
    )
    der = private.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    backup = canonical({**header, "nonce": b64(nonce),
                        "ciphertext": b64(AESGCM(key).encrypt(nonce, der, canonical(header)))})
    return private, fingerprint, backup.decode("utf-8")


def encrypt_in_python(private, fingerprint, content, name, context):
    header = dict(format="scap-encrypted-file", version=1, suite=SUITE,
                  recipient=fingerprint, context=context)
    nonce, key = secrets.token_bytes(12), secrets.token_bytes(32)
    label = MAGIC + prefix(canonical(header)) + nonce
    wrapped = private.public_key().encrypt(
        key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label)
    )
    aad = label + wrapped
    metadata = dict(name=name, size=len(content), sha256=hashlib.sha256(content).hexdigest())
    return aad + AESGCM(key).encrypt(nonce, prefix(canonical(metadata)) + content, aad)


@pytest.mark.skipif(NODE is None, reason="Node.js required for Web Crypto interoperability")
@pytest.mark.parametrize("content", [b"", bytes(range(256)) * 257], ids=["empty", "binary"])
def test_webcrypto_and_python_exchange_binary_files_in_both_directions(tmp_path, identity, content):
    private, fingerprint, backup = identity
    name, context = "Tệp nhị phân 🔐.dat", "local-demo"
    original = tmp_path / "original.bin"
    python_packet = tmp_path / "python.scapenc"
    node_packet = tmp_path / "node.scapenc"
    restored = tmp_path / "restored.bin"
    original.write_bytes(content)
    python_packet.write_bytes(encrypt_in_python(private, fingerprint, content, name, context))
    script = """
globalThis.crypto ??= require('node:crypto').webcrypto;
const fs = require('node:fs');
const core = require(process.argv[1]);
(async () => {
  const args = JSON.parse(fs.readFileSync(0, 'utf8'));
  const pair = await core.restoreKeyPair(args.backup, args.passphrase);
  const result = await core.decryptFile(pair.privateKey, pair.fingerprint,
    fs.readFileSync(args.pythonPacket));
  fs.writeFileSync(args.restored, result.bytes);
  const packet = await core.encryptFile(pair, fs.readFileSync(args.original),
    {name: args.name, context: args.context});
  fs.writeFileSync(args.nodePacket, packet);
  process.stdout.write(JSON.stringify({name: result.name, context: result.context,
    sha256: result.sha256, bytes: result.bytes.byteLength}));
})().catch(() => { process.stderr.write('File interoperability failed'); process.exitCode = 1; });
"""
    result = subprocess.run(
        [NODE, "-e", script, str(CORE)],
        input=json.dumps(dict(backup=backup, passphrase=PASSPHRASE, name=name, context=context,
                              original=str(original), pythonPacket=str(python_packet),
                              nodePacket=str(node_packet), restored=str(restored))),
        capture_output=True, text=True, encoding="utf-8", timeout=30, check=True,
    )
    assert json.loads(result.stdout) == dict(name=name, context=context,
                                           sha256=hashlib.sha256(content).hexdigest(),
                                           bytes=len(content))
    assert restored.read_bytes() == content

    # Independently parse and decrypt the Web Crypto output, without using its helpers.
    packet = node_packet.read_bytes()
    assert packet[:8] == MAGIC
    header_length = struct.unpack(">I", packet[8:12])[0]
    header_end = 12 + header_length
    header = json.loads(packet[12:header_end])
    assert header == dict(format="scap-encrypted-file", version=1, suite=SUITE,
                          recipient=fingerprint, context=context)
    nonce_end, wrapped_end = header_end + 12, header_end + 12 + 384
    key = private.decrypt(
        packet[nonce_end:wrapped_end],
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
                     label=packet[:nonce_end]),
    )
    plaintext = AESGCM(key).decrypt(packet[header_end:nonce_end], packet[wrapped_end:],
                                  packet[:wrapped_end])
    metadata_length = struct.unpack(">I", plaintext[:4])[0]
    assert json.loads(plaintext[4:4 + metadata_length]) == dict(
        name=name, size=len(content), sha256=hashlib.sha256(content).hexdigest()
    )
    assert plaintext[4 + metadata_length:] == content
    assert name.encode("utf-8") not in packet
