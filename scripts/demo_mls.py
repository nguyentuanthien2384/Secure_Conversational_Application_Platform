"""Three local OpenMLS clients, a separate disposable SCAP server, and removal.

Build the native client first: docker build -t scap-mls-client:local clients/mls_native
uv run --frozen --extra e2ee-client python -m scripts.demo_mls --check
"""
from __future__ import annotations

import argparse
import json
import multiprocessing
import secrets
import socket
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

import httpx

from clients.e2ee_client import ClientError, EncryptedVault, PrivateClient
from clients.mls_client import MlsClient
from scripts.demo_e2ee import _register, _serve


def _check(condition):
    if not condition:
        raise RuntimeError("MLS rehearsal verification failed.")


def rehearse():
    context = multiprocessing.get_context("spawn")
    with tempfile.TemporaryDirectory(prefix="scap-mls-rehearsal-") as directory:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
        stop = context.Event()
        process = context.Process(target=_serve, args=(directory, listener, stop), daemon=True)
        process.start()
        listener.close()
        try:
            with httpx.Client(base_url=origin, timeout=10, trust_env=False, follow_redirects=False) as api:
                deadline = time.monotonic() + 25
                while True:
                    try:
                        if api.get("/api/health").status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    if time.monotonic() >= deadline or not process.is_alive():
                        raise RuntimeError("Disposable MLS server did not become ready.")
                    time.sleep(0.1)
                with ExitStack() as stack:
                    people = []
                    for name in ("mls.alice", "mls.bob", "mls.charlie"):
                        vault = stack.enter_context(EncryptedVault(Path(directory) / name, secrets.token_urlsafe(32)))
                        person = PrivateClient(api, _register(api, name), vault, server=origin)
                        person.register_device()
                        people.append(person)
                    for person in people:
                        for peer in people:
                            if peer is not person:
                                person.pin_peer(peer.me["username"], peer.fingerprint, peer.device_id)
                    groups = [MlsClient(person) for person in people]
                    for member in groups:
                        for peer in groups:
                            if peer is not member:
                                member.pin_offer(peer.offer())
                    alice, bob, charlie = groups
                    conversation = alice.create("Recruiter MLS demonstration")
                    alice.change_member(conversation, bob.client.device_id)
                    bob.receive(conversation, owner_device=alice.client.device_id)
                    alice.change_member(conversation, charlie.client.device_id)
                    bob.receive(conversation)
                    charlie.receive(conversation, owner_device=alice.client.device_id)
                    first = "Private RFC 9420 message for three members"
                    alice.send(conversation, first)
                    _check(bob.receive(conversation)[0]["text"] == first)
                    _check(charlie.receive(conversation)[0]["text"] == first)
                    bob.send(conversation, "MLS reply from Bob")
                    _check(alice.receive(conversation)[0]["text"] == "MLS reply from Bob")
                    _check(charlie.receive(conversation)[0]["text"] == "MLS reply from Bob")
                    old_private_state = charlie.data["native"]
                    alice.change_member(conversation, charlie.client.device_id, remove=True)
                    bob.receive(conversation)
                    final = "New epoch available only to Alice and Bob"
                    alice.send(conversation, final)
                    _check(bob.receive(conversation)[0]["text"] == final)
                    try:
                        charlie.receive(conversation)
                    except ClientError:
                        pass
                    else:
                        raise RuntimeError("Removed member retained relay access.")
                    export = api.get(f"/api/sessions/{conversation}/export",
                                     headers={"Authorization": f"Bearer {alice.client.token}"})
                    _check(export.status_code == 200)
                    document = export.json()
                    _check(all(m.get("opaque_e2ee") for m in document["messages"]))
                    _check(first not in export.text and final not in export.text)
                    # Use the remaining member's ciphertext download to verify
                    # cryptographic removal independently of relay authorization.
                    rows = bob.client.request("GET", f"/api/sessions/{conversation}/e2ee/envelopes",
                        params={"recipient_device_id": bob.client.device_id})
                    message = next(m for m in reversed(rows) if m["message_kind"] == "application")
                    try:
                        charlie.native.call(op="receive", device_id=charlie.client.device_id,
                            state=old_private_state, group_id=conversation, message=message["ciphertext"])
                    except ClientError:
                        pass
                    else:
                        raise RuntimeError("Removed private state decrypted the new epoch.")
                    _check(alice.receive(conversation) == [] and bob.receive(conversation) == [])
            return {"status": "pass", "library": "OpenMLS 0.9.1", "members_before_removal": 3,
                    "members_after_removal": 2, "application_messages": 3, "add_remove_commits": 3,
                    "all_active_members_decrypted": True, "removed_member_new_epoch_decryption_rejected": True,
                    "device_fingerprints_and_key_package_signatures_verified": True,
                    "server_export_ciphertext_only": True, "separate_server_process": True,
                    "external_services_used": False, "temporary_state_cleaned_on_exit": True}
        finally:
            stop.set()
            process.join(timeout=10)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/mls-demo"))
    args = parser.parse_args(argv)
    try:
        result = rehearse()
    except Exception:
        print("MLS rehearsal failed. Build the local native helper and run the focused native tests; existing data was not used.")
        return 1
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "mls-demo.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
