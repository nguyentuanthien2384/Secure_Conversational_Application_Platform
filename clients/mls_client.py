"""Standalone RFC 9420 group client backed exclusively by native OpenMLS.

The helper receives secrets over anonymous pipes, with no network, mounts or
container logs. Only EncryptedVault writes client state. KeyPackage offers are
public, signed by an already fingerprint-pinned SCAP device, and transferable
out of band; the web server never receives private group or identity keys.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import uuid
from datetime import UTC, datetime

import httpx

from clients.e2ee_client import ClientError, PrivateClient, _public_url
from src.app.e2ee import (
    PROTOCOL_MLS,
    canonical_json_bytes,
    decode_base64_strict,
    encode_base64url,
    verify_ed25519_signature,
)

SCHEMA = "scap.mls.context.v1"
OFFER_SCHEMA = "scap.mls.key-package.v1"
MAX_HELPER_BYTES = 8 * 1024 * 1024
MAX_RECEIVE_PAGES = 100
RECEIVE_PAGE_SIZE = 100


class NativeMls:
    """Use a locally built helper; do not download/run a remotely named image."""

    def __init__(self, command=None):
        self._docker = command is None
        self._configured = False
        self.environment = None
        self.command = command or [
            "docker", "run", "--rm", "-i", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--log-driver", "none", "--memory", "128m", "--cpus", "1",
            "--pull", "never", "scap-mls-client:local",
        ]

    def _local_docker(self):
        if not self._docker or self._configured:
            return
        # A developer may also use Docker to deploy to a remote VPS. Never send
        # client private state to such a DOCKER_HOST/context by accident. Context
        # inspection reads local config only; no secret has entered a subprocess.
        try:
            inspected = subprocess.run(
                ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
                capture_output=True, timeout=10, check=False)
            endpoint = inspected.stdout.decode("utf-8").strip()
            if os.environ.get("DOCKER_HOST") and not os.environ.get("DOCKER_CONTEXT"):
                endpoint = os.environ["DOCKER_HOST"]
            if (inspected.returncode or len(endpoint) > 500 or any(c.isspace() for c in endpoint)
                    or not endpoint.startswith(("npipe:////./pipe/", "unix:///"))):
                raise ClientError("MLS requires a local Docker socket; remote Docker contexts are not allowed.")
        except (OSError, UnicodeError, subprocess.TimeoutExpired):
            raise ClientError("Cannot verify a local Docker runtime for the MLS client.") from None
        self.environment = os.environ.copy()
        for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
            self.environment.pop(name, None)
        self.command = ["docker", "--host", endpoint, *self.command[1:]]
        self._configured = True

    def call(self, **payload):
        self._local_docker()
        raw = json.dumps(payload, separators=(",", ":")).encode()
        if len(raw) > MAX_HELPER_BYTES:
            raise ClientError("MLS helper input exceeds its size budget.")
        try:
            result = subprocess.run(self.command, input=raw, capture_output=True, timeout=45, check=False,
                                    env=self.environment)
        except (OSError, subprocess.TimeoutExpired):
            raise ClientError("MLS helper is unavailable; build the local native client image first.") from None
        if result.returncode or len(result.stdout) > MAX_HELPER_BYTES:
            raise ClientError("MLS operation rejected; no received state was committed.")
        try:
            document = json.loads(result.stdout)
        except (ValueError, UnicodeError):
            raise ClientError("Invalid MLS helper response.") from None
        if not isinstance(document, dict):
            raise ClientError("Invalid MLS helper response.")
        return document


class MlsClient:
    """Owner-managed groups, pinned credentials and a durable retry outbox.

    Each account contributes one device per group. Membership commits belong to
    the owner; all members must pin the complete roster before joining/reading.
    Unsupported/concurrent membership or device revocation stops sending rather
    than guessing a new epoch or silently replacing group secrets.
    """

    def __init__(self, client: PrivateClient, native=None):
        self.client, self.native = client, native or NativeMls()
        self.last_receive_error = None
        self.data = client.vault.state.setdefault("mls", {
            "native": None, "pins": {}, "groups": {}, "cursors": {}, "outbox": None, "own": {},
        })
        if self.data["native"] is None:
            result = self._native("key_package")
            self.data["native"] = result["state"]
            self.data["key_package"] = result["key_package"]
            self.data["signing_key"] = result["signing_key"]
            self._save()

    def _save(self):
        self.client._save()

    def _native(self, op, **kwargs):
        self.client._require_healthy()
        return self.native.call(op=op, device_id=self.client.device_id,
                                state=self.data["native"], **kwargs)

    def offer(self):
        self.client._require_healthy()
        public = {"server": self.client.server, "username": self.client.me["username"],
                  "account_id": self.client.me["id"], "device_id": self.client.device_id,
                  "key_package": self.data["key_package"], "signing_key": self.data["signing_key"]}
        return {**public, "signature": _public_url(self.client.account.sign(
            canonical_json_bytes(public, schema=OFFER_SCHEMA)).to_base64())}

    def refresh_offer(self):
        """Generate fresh one-use join material after a Welcome was consumed."""
        self._idle()
        result = self._native("key_package")
        self.data.update(native=result["state"], key_package=result["key_package"])
        self._save()
        return self.offer()

    def pin_offer(self, offer):
        self.client._require_healthy()
        fields = {"server", "username", "account_id", "device_id", "key_package", "signing_key", "signature"}
        if not isinstance(offer, dict) or set(offer) != fields or any(not isinstance(v, str) for v in offer.values()):
            raise ClientError("Invalid MLS KeyPackage offer.")
        peer = self.client.vault.state["peers"].get(offer["device_id"])
        if (peer is None or offer["server"] != self.client.server or peer["username"] != offer["username"]
                or peer["user_id"] != offer["account_id"]):
            raise ClientError("Pin the device fingerprint before accepting its MLS offer.")
        public = {key: value for key, value in offer.items() if key != "signature"}
        if not verify_ed25519_signature(peer["identity_key"], offer["signature"],
                                        canonical_json_bytes(public, schema=OFFER_SCHEMA)):
            raise ClientError("Invalid MLS device signature.")
        inspected = self.native.call(op="inspect", key_package=offer["key_package"])
        if inspected != {"device_id": offer["device_id"], "signing_key": offer["signing_key"]}:
            raise ClientError("MLS KeyPackage credential does not match its signed offer.")
        old = self.data["pins"].get(offer["device_id"])
        if old and old["signing_key"] != offer["signing_key"]:
            raise ClientError("MLS identity changed; review in a new client profile.")
        self.data["pins"][offer["device_id"]] = copy.deepcopy(offer)
        self._save()

    def _idle(self):
        self.client._require_healthy()
        if self.data["outbox"]:
            raise ClientError("Retry the pending MLS operation before preparing another.")

    def _routing(self, conversation):
        return self.client.request("GET", f"/api/sessions/{conversation}/e2ee/state")

    def create(self, title="Private MLS group"):
        self._idle()
        row = self.client.request("POST", "/api/sessions", json={
            "title": title, "security_mode": "private_e2ee", "data_classification": "e2ee_private"})
        result = self._native("create", group_id=row["id"])
        self.data["native"] = result["state"]
        self.data["groups"][row["id"]] = {"epoch": 1, "owner_id": self.client.me["id"],
                                            "owner_device": self.client.device_id}
        self._save()
        return row["id"]

    def _context(self, conversation, epoch, message_id, kind, sender=None):
        return {"session_id": conversation, "epoch": epoch, "client_message_id": message_id,
                "message_kind": kind, "sender_device_id": sender or self.client.device_id}

    def _envelope(self, conversation, epoch, kind, message, message_id, recipient=None):
        header = self._context(conversation, epoch, message_id, kind)
        return {"version": 1, "protocol": PROTOCOL_MLS, "sender_device_id": self.client.device_id,
                "recipient_device_id": recipient, "recipient": recipient or conversation,
                "epoch": epoch, "message_kind": kind, "client_message_id": message_id,
                "header": encode_base64url(canonical_json_bytes(header, schema=SCHEMA)), "ciphertext": message}

    def _roster(self, result):
        expected = {self.client.device_id: self.data["signing_key"],
                    **{key: value["signing_key"] for key, value in self.data["pins"].items()}}
        members = result.get("members")
        if not isinstance(members, list) or not members or any(
                not isinstance(member, dict) or not isinstance(member.get("device_id"), str)
                or not isinstance(member.get("signing_key"), str)
                or expected.get(member["device_id"]) != member["signing_key"] for member in members):
            raise ClientError("MLS roster contains an unverified device or changed credential.")

    def change_member(self, conversation, device_id, *, remove=False):
        self._idle()
        group = self.data["groups"].get(conversation)
        peer = self.data["pins"].get(device_id)
        if not group or group["owner_device"] != self.client.device_id or peer is None:
            raise ClientError("Only the group owner can change a fingerprint-pinned member.")
        routing = self._routing(conversation)
        if routing["epoch"] != group["epoch"]:
            raise ClientError("MLS membership epoch changed; receive pending commits before sending.")
        memberships = self.client.request("GET", f"/api/sessions/{conversation}/e2ee/members")
        active = any(member["user_id"] == peer["account_id"] and member["active"] for member in memberships)
        if active != remove:
            raise ClientError("This MLS client supports one device per account; membership does not match the requested action.")
        epoch, message_id = group["epoch"] + 1, str(uuid.uuid4())
        context = canonical_json_bytes(self._context(conversation, epoch, message_id, "commit"), schema=SCHEMA)
        kwargs = {"target_device": device_id} if remove else {"key_package": peer["key_package"]}
        result = self._native("remove" if remove else "add", group_id=conversation,
                              aad=encode_base64url(context), **kwargs)
        self._roster(result)
        if result["epoch"] + 1 != epoch:
            raise ClientError("MLS group and relay epoch disagree.")
        envelopes = [self._envelope(conversation, epoch, "commit", result["commit"], message_id)]
        if not remove:
            envelopes.append(self._envelope(conversation, epoch, "welcome", result["welcome"],
                                            str(uuid.uuid4()), device_id))
        # Persist all native state, exact ciphertext and membership intent before
        # making a request. Response loss can retry without generating new keys.
        self.data["native"] = result["state"]
        group["epoch"] = epoch
        self.data["outbox"] = {"conversation": conversation, "epoch": epoch,
            "membership": {"username": peer["username"], "account_id": peer["account_id"], "remove": remove},
            "envelopes": envelopes}
        self._save()
        return self.flush()

    def send(self, conversation, text):
        self._idle()
        if not isinstance(text, str) or not text or len(text) > 8000:
            raise ClientError("Message must contain 1–8000 characters.")
        group = self.data["groups"].get(conversation)
        if not group or self._routing(conversation)["epoch"] != group["epoch"]:
            raise ClientError("Receive the current MLS epoch before sending.")
        mid, epoch = str(uuid.uuid4()), group["epoch"]
        context = self._context(conversation, epoch, mid, "application")
        result = self._native("send", group_id=conversation, plaintext=encode_base64url(text.encode()),
            aad=encode_base64url(canonical_json_bytes(context, schema=SCHEMA)))
        if result["epoch"] + 1 != epoch:
            raise ClientError("MLS group and relay epoch disagree.")
        self.data["native"] = result["state"]
        self.data["outbox"] = {"conversation": conversation, "epoch": epoch, "membership": None,
            "envelopes": [self._envelope(conversation, epoch, "application", result["message"], mid)]}
        self._save()
        return self.flush()

    def flush(self):
        self.client._require_healthy()
        pending = self.data["outbox"]
        if not pending:
            return {"delivered": True}
        conversation, epoch = pending["conversation"], pending["epoch"]
        membership = pending["membership"]
        routing = self._routing(conversation)
        if membership:
            if routing["epoch"] == epoch - 1:
                username = membership["username"]
                if membership["remove"]:
                    self.client.request("DELETE", f"/api/sessions/{conversation}/e2ee/members/{username}")
                else:
                    self.client.request("POST", f"/api/sessions/{conversation}/e2ee/members", json={"username": username})
            elif routing["epoch"] != epoch:
                raise ClientError("Membership changed concurrently; keep this profile for recovery.")
            members = self.client.request("GET", f"/api/sessions/{conversation}/e2ee/members")
            matched = next((m for m in members if m["user_id"] == membership["account_id"]), None)
            key = "removed_epoch" if membership["remove"] else "joined_epoch"
            if matched is None or matched[key] != epoch or matched["active"] == membership["remove"]:
                raise ClientError("Membership acknowledgement does not match the pending MLS commit.")
        elif routing["epoch"] != epoch:
            raise ClientError("MLS epoch changed before ciphertext delivery; keep the pending outbox.")
        while pending["envelopes"]:
            envelope = pending["envelopes"][0]
            response = self.client._request_response("POST", f"/api/sessions/{conversation}/e2ee/envelopes", json=envelope)
            duplicate = False
            if response.status_code == 409:
                try:
                    verdict = response.json()
                except (ValueError, UnicodeError):
                    verdict = None
                duplicate = isinstance(verdict, dict) and verdict.get("detail") == "Bản mã trùng hoặc đã được phát lại."
            if response.status_code != 201 and not duplicate:
                raise ClientError(f"MLS ciphertext remains pending (HTTP {response.status_code}).")
            if envelope["recipient_device_id"] in {None, self.client.device_id}:
                own = self.data["own"].setdefault(conversation, {})
                own[envelope["client_message_id"]] = hashlib.sha256(envelope["ciphertext"].encode()).hexdigest()
            pending["envelopes"].pop(0)
            self._save()
        self.data["outbox"] = None
        self._save()
        return {"delivered": True}

    def receive(self, conversation, *, owner_device=None):
        self._idle()
        routing = self._routing(conversation)
        if conversation not in self.data["groups"]:
            owner = self.data["pins"].get(owner_device)
            if owner is None or owner["account_id"] != routing["owner_id"]:
                raise ClientError("Provide the pinned group owner device before joining.")
        else:
            owner_device = self.data["groups"][conversation]["owner_device"]
        messages = []
        self.last_receive_error = None
        for _ in range(MAX_RECEIVE_PAGES):
            params = {"recipient_device_id": self.client.device_id, "limit": RECEIVE_PAGE_SIZE}
            cursor = self.data["cursors"].get(conversation)
            if cursor:
                params.update(after=cursor["created_at"], after_id=cursor["id"])
            try:
                rows = self.client.request("GET", f"/api/sessions/{conversation}/e2ee/envelopes", params=params)
                if not isinstance(rows, list) or len(rows) > RECEIVE_PAGE_SIZE:
                    raise ClientError("Invalid MLS envelope list.")
                for row in rows:
                    received = self._receive_one(conversation, row, owner_device, routing)
                    if received is not None:
                        messages.append(received)
            except (ClientError, OSError, ValueError, KeyError, TypeError, httpx.HTTPError):
                if not messages:
                    raise
                self.last_receive_error = "Receiving stopped; earlier messages are returned. Check the next ciphertext and retry."
                return messages
            if len(rows) < RECEIVE_PAGE_SIZE:
                return messages
        self.last_receive_error = "Receive batch budget reached; run receive again to continue."
        return messages

    def _receive_one(self, conversation, row, owner_device, routing):
        if not isinstance(row, dict) or row.get("protocol") != PROTOCOL_MLS:
            raise ClientError("Unexpected protocol in an MLS group.")
        fields = ("id", "created_at", "sender_device_id", "message_kind", "client_message_id", "header", "ciphertext")
        if (any(not isinstance(row.get(field), str) for field in fields)
                or row["message_kind"] not in {"application", "commit", "welcome"}
                or not isinstance(row.get("group_epoch"), int) or isinstance(row["group_epoch"], bool)
                or row["group_epoch"] < 1):
            raise ClientError("Invalid MLS envelope or cursor.")
        try:
            if str(uuid.UUID(row["id"])) != row["id"]:
                raise ValueError
            timestamp = datetime.fromisoformat(row["created_at"].replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=UTC)  # SQLite's API timestamps denote UTC.
            previous = self.data["cursors"].get(conversation)
            if previous:
                prior_time = datetime.fromisoformat(previous["created_at"].replace("Z", "+00:00"))
                if prior_time.tzinfo is None:
                    prior_time = prior_time.replace(tzinfo=UTC)
                if (timestamp, row["id"]) <= (prior_time, previous["id"]):
                    raise ValueError
        except (ValueError, TypeError):
            raise ClientError("Invalid or replayed MLS envelope cursor.") from None
        received = None
        # A relay cannot forge a self-sent acknowledgement: its exact ciphertext
        # digest must already have been saved when our outbox was acknowledged.
        own = self.data["own"].get(conversation, {}).get(row["client_message_id"])
        if row["sender_device_id"] == self.client.device_id:
            if own != hashlib.sha256(row["ciphertext"].encode()).hexdigest():
                raise ClientError("Unrecognized self-sent MLS ciphertext.")
            del self.data["own"][conversation][row["client_message_id"]]
            if not self.data["own"][conversation]:
                del self.data["own"][conversation]
            result = None
        else:
            kind, epoch = row["message_kind"], row["group_epoch"]
            context = self._context(conversation, epoch, row["client_message_id"], kind, row["sender_device_id"])
            aad = canonical_json_bytes(context, schema=SCHEMA)
            if decode_base64_strict(row["header"], field="MLS header", max_bytes=16384) != aad:
                raise ClientError("MLS routing context mismatch.")
            if kind in {"commit", "welcome"} and row["sender_device_id"] != owner_device:
                raise ClientError("Only the pinned owner may commit this MLS group's membership.")
            if kind == "welcome":
                if conversation in self.data["groups"] or row["recipient_device_id"] != self.client.device_id:
                    raise ClientError("Unexpected or replayed MLS Welcome.")
                result = self._native("join", group_id=conversation, message=row["ciphertext"])
                if result.get("welcome_sender") != owner_device:
                    raise ClientError("MLS Welcome was not signed by the pinned group owner.")
            elif conversation not in self.data["groups"] and kind == "commit":
                # The add commit is broadcast before its recipient Welcome. It
                # cannot be processed by a joining member lacking the old epoch.
                result = None
            else:
                result = self._native("receive", group_id=conversation, message=row["ciphertext"])
                if (result.get("kind") != kind or result.get("sender_device") != row["sender_device_id"]
                        or result.get("aad") != encode_base64url(aad)):
                    raise ClientError("Authenticated MLS sender/context does not match relay metadata.")
            if result is not None:
                self._roster(result)
                if result["epoch"] + 1 != epoch or not result["active"]:
                    raise ClientError("MLS epoch is inconsistent or this device was removed.")
                if result.get("kind") == "application":
                    received = {"sender_device": row["sender_device_id"], "text": decode_base64_strict(
                        result["plaintext"], field="MLS plaintext", max_bytes=32768).decode("utf-8")}
                self.data["native"] = result["state"]
                self.data["groups"][conversation] = {"epoch": epoch, "owner_id": routing["owner_id"], "owner_device": owner_device}
        # State and cursor are acknowledged together in one encrypted write.
        self.data["cursors"][conversation] = {"id": row["id"], "created_at": row["created_at"]}
        self._save()
        return received
