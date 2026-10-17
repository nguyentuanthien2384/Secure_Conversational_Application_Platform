"""A standalone SCAP 1:1 Olm client; private keys never enter the web app.

Install the e2ee-client extra. All ratchet/key agreement operations are provided
by vodozemac, rather than a custom protocol implementation in Python.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import secrets
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from src.app.e2ee import (
    build_device_approval_message,
    build_device_possession_message,
    canonical_json_bytes,
    decode_base64_strict,
    encode_base64url,
    safety_fingerprint,
    verify_ed25519_signature,
)
from src.app.private_storage import (
    check_private_file,
    create_private_file,
    prepare_private_directory,
    private_directory_scope,
    read_regular_file,
)

try:
    import vodozemac as olm
except ImportError:
    olm = None

MAX_VAULT_BYTES = 2 * 1024 * 1024
MAX_CLIENT_SESSIONS = 256
_AAD = b"scap.e2ee-client-vault.v1"


class ClientError(RuntimeError):
    """A fixed, user-facing failure; never includes a bearer or private key."""


def _require_olm():
    if olm is None:
        raise ClientError("Install with: uv sync --frozen --extra e2ee-client")


def _public_url(value: str) -> str:
    raw = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    return encode_base64url(raw)


def _native_key(value: str):
    raw = decode_base64_strict(value, field="public key", exact_bytes=32)
    return olm.Curve25519PublicKey.from_bytes(raw)


def checked_server(value: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"}):
        raise ClientError("Use an HTTPS server origin, or HTTP on loopback for a local demo.")
    try:
        local = parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        local = False
    if parsed.scheme == "http" and not local:
        raise ClientError("HTTP is allowed only on loopback.")
    return value.rstrip("/")


class EncryptedVault:
    """Bounded, encrypted local state with a single-writer lock and private ACL.

    The passphrase and bearer are never persisted. Vodozemac pickles and their
    surrounding routing/pin metadata are encrypted before any filesystem write.
    """

    def __init__(self, directory: Path, passphrase: str):
        if len(passphrase.encode("utf-8")) < 16:
            raise ClientError("Client vault passphrase must contain at least 16 UTF-8 bytes.")
        self.directory = prepare_private_directory(directory)
        self.path = self.directory / "client.scapclient"
        self.lock_path = self.directory / "client.lock"
        self._lock = None
        self.state: dict = {}
        self._passphrase = passphrase.encode("utf-8")
        self.key = b""
        self.salt = b""

    def __enter__(self):
        try:
            self._lock = create_private_file(self.lock_path)
        except FileExistsError as exc:
            raise ClientError("This client profile is already open; do not run two writers.") from exc
        try:
            if self.path.exists():
                check_private_file(self.path)
                with read_regular_file(self.path) as source:
                    raw = source.read(MAX_VAULT_BYTES + 1)
                if len(raw) > MAX_VAULT_BYTES:
                    raise ClientError("Client vault exceeds its size budget.")
                document = json.loads(raw)
                if document.get("version") != 1:
                    raise ClientError("Unsupported client vault format.")
                self.salt = decode_base64_strict(document["salt"], field="salt", exact_bytes=16)
                self._derive_key()
                nonce = decode_base64_strict(document["nonce"], field="nonce", exact_bytes=12)
                ciphertext = decode_base64_strict(document["ciphertext"], field="vault", max_bytes=MAX_VAULT_BYTES)
                self.state = json.loads(AESGCM(self.key).decrypt(nonce, ciphertext, _AAD))
                if not isinstance(self.state, dict):
                    raise ClientError("Invalid client vault.")
            else:
                self.salt = secrets.token_bytes(16)
                self._derive_key()
                self.state = {"version": 1, "peers": {}, "sessions": {}, "active": {}, "cursors": {}, "outbox": {}}
            return self
        except (ValueError, KeyError, TypeError, InvalidTag) as exc:
            self.__exit__(None, None, None)
            raise ClientError("Cannot unlock client vault; check the passphrase and backup.") from exc
        except BaseException:
            self.__exit__(None, None, None)
            raise
        finally:
            self._passphrase = b""

    def _derive_key(self):
        self.key = Scrypt(salt=self.salt, length=32, n=2**15, r=8, p=1).derive(self._passphrase)

    def save(self):
        if self._lock is None:
            raise ClientError("Client vault is not locked.")
        payload = json.dumps(self.state, separators=(",", ":"), ensure_ascii=False).encode()
        if len(payload) > MAX_VAULT_BYTES // 2:
            raise ClientError("Client state is full; archive this profile before opening more conversations.")
        nonce = secrets.token_bytes(12)
        encrypted = AESGCM(self.key).encrypt(nonce, payload, _AAD)
        document = json.dumps({"version": 1, "salt": encode_base64url(self.salt),
                               "nonce": encode_base64url(nonce), "ciphertext": encode_base64url(encrypted)}).encode()
        temporary = self.directory / f"{uuid.uuid4()}.tmp"
        with private_directory_scope(self.directory):
            try:
                with create_private_file(temporary) as target:
                    target.write(document)
                    target.flush()
                    os.fsync(target.fileno())
                if self.path.exists():
                    check_private_file(self.path)
                os.replace(temporary, self.path)
            finally:
                temporary.unlink(missing_ok=True)

    def __exit__(self, *_):
        if self._lock is not None:
            self._lock.close()
            self._lock = None
            self.lock_path.unlink(missing_ok=True)
        self.key = b""


class PrivateClient:
    """Client-owned Olm account, pinned identities, durable ratchets and outbox."""

    def __init__(self, api, token: str, vault: EncryptedVault, *, server: str):
        _require_olm()
        self.api, self.token, self.vault = api, token, vault
        self.server = checked_server(server)
        self.me = self.request("GET", "/api/auth/me")
        state = vault.state
        binding = {"server": self.server, "account_id": self.me["id"]}
        if state.get("binding", binding) != binding:
            raise ClientError("This profile belongs to a different server or account.")
        state["binding"] = binding
        self.account = (olm.Account.from_pickle(state["account"], vault.key)
                        if state.get("account") else olm.Account())
        self.device_id = state.setdefault("device_id", str(uuid.uuid4()))
        self._save()

    @property
    def identity(self):
        return _public_url(self.account.ed25519_key.to_base64())

    @property
    def fingerprint(self):
        return safety_fingerprint(self.identity)

    def request(self, method, path, **kwargs):
        response = self.api.request(method, path, headers={"Authorization": f"Bearer {self.token}"}, **kwargs)
        if response.status_code >= 400:
            raise ClientError(f"SCAP request rejected (HTTP {response.status_code}); authenticate/step up or check policy.")
        return response.json() if response.content else None

    def _save(self):
        self.vault.state["account"] = self.account.pickle(self.vault.key)
        self.vault.save()

    def registration_offer(self, display_name="Private client"):
        challenge = self.request("POST", "/api/e2ee/devices/challenge")
        if not self.account.one_time_keys:
            self.account.generate_one_time_keys(20)
        curve = self.account.curve25519_key.to_bytes()
        offer = {
            "challenge_id": challenge["id"], "challenge": challenge["challenge"],
            "device_id": self.device_id, "display_name": display_name,
            "identity_key": self.identity,
            "possession_signature": _public_url(self.account.sign(build_device_possession_message(
                account_id=self.me["id"], device_id=self.device_id,
                identity_public_key_b64=self.identity, challenge_b64=challenge["challenge"],
            )).to_base64()),
            "signed_prekey": encode_base64url(curve),
            "signed_prekey_signature": _public_url(self.account.sign(curve).to_base64()),
            "one_time_prekeys": [_public_url(key.to_base64()) for key in self.account.one_time_keys.values()],
        }
        self.vault.state["registration_offer"] = offer
        self._save()
        return offer

    def approve(self, offer):
        statement = build_device_approval_message(
            account_id=self.me["id"], approver_device_id=self.device_id,
            new_device_id=offer["device_id"], new_device_public_key_b64=offer["identity_key"],
            approval_challenge_b64=offer["challenge"],
        )
        return {"approver_device_id": self.device_id,
                "approval_signature": _public_url(self.account.sign(statement).to_base64())}

    def register_device(self, *, approval=None):
        existing = next((item for item in self.request("GET", "/api/e2ee/devices")
                         if item["id"] == self.device_id), None)
        if existing is not None:
            if existing["trust_state"] != "trusted" or existing["fingerprint"] != self.fingerprint:
                raise ClientError("This device was revoked or its identity changed; review before registering a new profile.")
            self.account.mark_keys_as_published()
            self.vault.state.pop("registration_offer", None)
            self._save()
            return existing
        offer = self.vault.state.get("registration_offer") or self.registration_offer()
        payload = {**offer, **(approval or {})}
        result = self.request("POST", "/api/e2ee/devices", json=payload)
        if result["fingerprint"] != self.fingerprint:
            raise ClientError("Server device identity does not match the local key.")
        self.account.mark_keys_as_published()
        self.vault.state.pop("registration_offer", None)
        self._save()
        return result

    def refill(self, count=20):
        if not 1 <= count <= 100:
            raise ClientError("Prekey count must be between 1 and 100.")
        challenge = self.request("POST", "/api/e2ee/devices/challenge")
        if not self.account.one_time_keys:
            self.account.generate_one_time_keys(count)
        prekeys = [_public_url(key.to_base64()) for key in self.account.one_time_keys.values()]
        public = {"account_id": self.me["id"], "device_id": self.device_id,
                  "challenge": challenge["challenge"], "one_time_prekeys": prekeys,
                  "signed_prekey": None, "signed_prekey_signature": None}
        self._save()  # Persist the matching private prekeys before uploading.
        result = self.request("POST", f"/api/e2ee/devices/{self.device_id}/prekeys", json={
            "challenge_id": challenge["id"], "challenge": challenge["challenge"],
            "one_time_prekeys": prekeys,
            "update_signature": _public_url(self.account.sign(canonical_json_bytes(
                public, schema="scap.e2ee.prekey-update")).to_base64()),
        })
        self.account.mark_keys_as_published()
        self._save()
        return result

    def pin_peer(self, username, fingerprint, device_id=None):
        expected = re.sub(r"\s", "", fingerprint).upper()
        if not re.fullmatch(r"[0-9A-F]{64}", expected):
            raise ClientError("Verify the full 64-hex fingerprint through another channel first.")
        params = {"device_id": device_id} if device_id else {}
        bundle = self.request("GET", f"/api/e2ee/users/{username}/prekey-bundle", params=params)
        actual = safety_fingerprint(bundle["identity_key"])
        if actual.replace(" ", "") != expected:
            raise ClientError("Fingerprint mismatch; do not trust this device.")
        raw_curve = decode_base64_strict(bundle["signed_prekey"], field="curve key", exact_bytes=32)
        if not verify_ed25519_signature(bundle["identity_key"], bundle["signed_prekey_signature"], raw_curve):
            raise ClientError("Invalid signed prekey.")
        peers = self.vault.state["peers"]
        previous = peers.get(bundle["device_id"])
        if previous and (previous["identity_key"] != bundle["identity_key"]
                         or previous["signed_prekey"] != bundle["signed_prekey"]):
            raise ClientError("Peer identity changed; review it in a new client profile.")
        if len(peers) >= MAX_CLIENT_SESSIONS and bundle["device_id"] not in peers:
            raise ClientError("Client peer budget exhausted.")
        bundle["username"] = username
        peers[bundle["device_id"]] = bundle
        self._save()
        return bundle

    def new_conversation(self, peer_username, title="Private conversation"):
        row = self.request("POST", "/api/sessions", json={
            "title": title, "security_mode": "private_e2ee", "data_classification": "e2ee_private",
        })
        self.request("POST", f"/api/sessions/{row['id']}/e2ee/members", json={"username": peer_username})
        return row["id"]

    def prepare(self, conversation, peer_device, text):
        if not isinstance(text, str) or not text or len(text) > 8_000:
            raise ClientError("Message must contain 1–8000 characters.")
        state = self.vault.state
        if state["outbox"]:
            raise ClientError("Retry the pending ciphertext before preparing another message.")
        peer = state["peers"].get(peer_device)
        if peer is None:
            raise ClientError("Pin the peer fingerprint before sending.")
        routing = self.request("GET", f"/api/sessions/{conversation}/e2ee/state")
        key = f"{conversation}:{peer_device}"
        ratchet_id = state["active"].get(key)
        if ratchet_id:
            ratchet = olm.Session.from_pickle(state["sessions"][ratchet_id], self.vault.key)
        else:
            if not peer.get("one_time_prekey"):
                peer = self.pin_peer(peer["username"], peer["fingerprint"], peer_device)
            if not peer.get("one_time_prekey"):
                raise ClientError("Peer prekeys are exhausted; ask the peer to refill.")
            ratchet = self.account.create_outbound_session(
                _native_key(peer["signed_prekey"]), _native_key(peer["one_time_prekey"]),
            )
            ratchet_id = f"{key}:{ratchet.session_id}"
            peer["one_time_prekey"] = None
        if len(state["sessions"]) >= MAX_CLIENT_SESSIONS and ratchet_id not in state["sessions"]:
            raise ClientError("Client ratchet budget exhausted.")
        message_id = str(uuid.uuid4())
        bound = {"session_id": conversation, "sender_device_id": self.device_id,
                 "recipient_device_id": peer_device, "epoch": routing["epoch"],
                 "client_message_id": message_id, "text": text}
        message = ratchet.encrypt(canonical_json_bytes(bound, schema="scap.e2ee.message"))
        message_type, ciphertext = message.to_parts()
        header = {"schema": "scap.olm.v1", "type": message_type,
                  "curve_key": encode_base64url(self.account.curve25519_key.to_bytes()),
                  "ratchet_id": ratchet.session_id}
        envelope = {"version": 1, "protocol": "double-ratchet", "recipient": peer_device,
                    "recipient_device_id": peer_device, "epoch": routing["epoch"],
                    "client_message_id": message_id, "sender_device_id": self.device_id,
                    "message_kind": "application", "header": encode_base64url(json.dumps(header).encode()),
                    "ciphertext": encode_base64url(ciphertext)}
        state["sessions"][ratchet_id] = ratchet.pickle(self.vault.key)
        state["active"][key] = ratchet_id
        state["outbox"] = {"conversation": conversation, "envelope": envelope}
        self._save()  # Durable outbox + advanced ratchet before the HTTP write.
        return envelope

    def flush(self):
        pending = self.vault.state["outbox"]
        if not pending:
            return None
        response = self.api.post(f"/api/sessions/{pending['conversation']}/e2ee/envelopes",
                                 headers={"Authorization": f"Bearer {self.token}"}, json=pending["envelope"])
        duplicate = response.status_code == 409 and response.json().get("detail") == "Bản mã trùng hoặc đã được phát lại."
        if response.status_code != 201 and not duplicate:
            raise ClientError(f"Ciphertext remains in the local outbox (HTTP {response.status_code}); use retry.")
        self.vault.state["outbox"] = {}
        self._save()
        return {"delivered": True, "duplicate_acknowledged": duplicate}

    def send(self, conversation, peer_device, text):
        self.prepare(conversation, peer_device, text)
        return self.flush()

    def decrypt(self, conversation, envelope, *, persist=True):
        state = self.vault.state
        sender = envelope["sender_device_id"]
        peer = state["peers"].get(sender)
        if peer is None:
            raise ClientError("Unverified sender; pin this device before receiving.")
        if envelope.get("recipient_device_id") != self.device_id or envelope.get("protocol") != "double-ratchet":
            raise ClientError("Ciphertext is addressed to a different client/protocol.")
        header = json.loads(decode_base64_strict(envelope["header"], field="header", max_bytes=1024))
        if header.get("schema") != "scap.olm.v1" or header.get("curve_key") != peer["signed_prekey"]:
            raise ClientError("Sender key does not match the verified peer.")
        ciphertext = decode_base64_strict(envelope["ciphertext"], field="ciphertext", max_bytes=65536)
        if type(header.get("type")) is not int or header["type"] not in {0, 1}:
            raise ClientError("Invalid Olm message type.")
        message = olm.AnyOlmMessage.from_parts(header["type"], ciphertext)
        key = f"{conversation}:{sender}"
        ratchet_id = f"{key}:{header['ratchet_id']}"
        account = self.account
        if ratchet_id in state["sessions"]:
            ratchet = olm.Session.from_pickle(state["sessions"][ratchet_id], self.vault.key)
            plaintext = ratchet.decrypt(message)
        else:
            if len(state["sessions"]) >= MAX_CLIENT_SESSIONS or message.to_pre_key() is None:
                raise ClientError("Unknown ratchet; a verified prekey message is required.")
            account = olm.Account.from_pickle(self.account.pickle(self.vault.key), self.vault.key)
            ratchet, plaintext = account.create_inbound_session(_native_key(peer["signed_prekey"]), message.to_pre_key())
        if ratchet.session_id != header["ratchet_id"]:
            raise ClientError("Ratchet identity mismatch.")
        bound = json.loads(plaintext)
        expected = {"session_id": conversation, "sender_device_id": sender,
                    "recipient_device_id": self.device_id, "epoch": envelope["group_epoch"],
                    "client_message_id": envelope["client_message_id"]}
        body = bound.get("payload", {})
        if (bound.get("schema") != "scap.e2ee.message" or bound.get("version") != 1
                or any(body.get(field) != value for field, value in expected.items())
                or set(body) != {*expected, "text"} or not isinstance(body["text"], str)
                or len(body["text"]) > 8000):
            raise ClientError("Authenticated message does not match its routing context.")
        self.account = account
        state["sessions"][ratchet_id] = ratchet.pickle(self.vault.key)
        state["active"][key] = ratchet_id
        if persist:
            self._save()
        return body["text"]

    def receive(self, conversation):
        received = []
        for _ in range(100):
            cursor = self.vault.state["cursors"].get(conversation, {})
            params = {"recipient_device_id": self.device_id, "limit": 100, **cursor}
            envelopes = self.request("GET", f"/api/sessions/{conversation}/e2ee/envelopes", params=params)
            if not envelopes:
                break
            for envelope in envelopes:
                text = self.decrypt(conversation, envelope, persist=False)
                self.vault.state["cursors"][conversation] = {"after": envelope["created_at"], "after_id": envelope["id"]}
                self._save()
                received.append({"sender_device": envelope["sender_device_id"], "text": text})
            if len(envelopes) < 100:
                break
        return received
