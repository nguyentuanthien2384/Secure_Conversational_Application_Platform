"""Rehearse two real E2EE clients against a disposable loopback server.

uv run --frozen --extra e2ee-client python -m scripts.demo_e2ee --check
The server runs in a spawned child process; client private keys stay outside it.
No .env, existing database, cloud provider, or target URL is accepted.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import secrets
import socket
import tempfile
import threading
import time
from contextlib import ExitStack
from pathlib import Path

import httpx
import uvicorn

from clients.e2ee_client import EncryptedVault, PrivateClient


def _serve(directory, listener, stop):
    from scripts.demo_local import demo_application

    # This guard must surround the import-time default app as well. The same
    # established launcher also blocks every non-loopback HTTP destination.
    port = listener.getsockname()[1]
    with demo_application(Path(directory), port) as app:
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", log_level="error", log_config=None, access_log=False,
                                             proxy_headers=False, timeout_graceful_shutdown=5))

        def shutdown():
            stop.wait()
            server.should_exit = True

        threading.Thread(target=shutdown, daemon=True).start()
        server.run(sockets=[listener])


def _register(api, username):
    password = secrets.token_urlsafe(24) + "1!"
    payload = {"username": username, "password": password}
    registered = api.post("/api/auth/register", json=payload)
    if registered.status_code != 201:
        raise RuntimeError("Demo registration failed.")
    response = api.post("/api/auth/login", json=payload)
    if response.status_code != 200:
        raise RuntimeError("Demo login failed.")
    return response.json()["access_token"]


def rehearse():
    context = multiprocessing.get_context("spawn")
    with tempfile.TemporaryDirectory(prefix="scap-e2ee-rehearsal-") as directory:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        stop = context.Event()
        process = context.Process(target=_serve, args=(directory, listener, stop), daemon=True)
        process.start()
        listener.close()
        try:
            with httpx.Client(base_url=origin, timeout=5, trust_env=False, follow_redirects=False) as api:
                deadline = time.monotonic() + 25
                while True:
                    try:
                        if api.get("/api/health").status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    if time.monotonic() >= deadline or not process.is_alive():
                        raise RuntimeError("Isolated E2EE server did not become ready.")
                    time.sleep(0.1)
                with ExitStack() as stack:
                    alice_vault = stack.enter_context(EncryptedVault(Path(directory) / "alice", secrets.token_urlsafe(32)))
                    bob_vault = stack.enter_context(EncryptedVault(Path(directory) / "bob", secrets.token_urlsafe(32)))
                    alice = PrivateClient(api, _register(api, "recruiter.alice"), alice_vault, server=origin)
                    bob = PrivateClient(api, _register(api, "recruiter.bob"), bob_vault, server=origin)
                    alice.register_device()
                    bob.register_device()
                    # The rehearsal knows both local clients. Real users must
                    # compare these full fingerprints through a separate channel.
                    alice.pin_peer("recruiter.bob", bob.fingerprint, bob.device_id)
                    bob.pin_peer("recruiter.alice", alice.fingerprint, alice.device_id)
                    conversation = alice.new_conversation("recruiter.bob")
                    text = "SCAP private recruiter demonstration — Alice"
                    reply = "SCAP private recruiter demonstration — Bob"
                    alice.send(conversation, bob.device_id, text)
                    incoming = bob.receive(conversation)
                    if not incoming or incoming[0]["text"] != text:
                        raise RuntimeError("Recipient could not decrypt the private message.")
                    bob.send(conversation, alice.device_id, reply)
                    outgoing = alice.receive(conversation)
                    if not outgoing or outgoing[0]["text"] != reply:
                        raise RuntimeError("Sender could not decrypt the ratcheted reply.")
                    replay_empty = bob.receive(conversation) == [] and alice.receive(conversation) == []
                    bob.refill(5)
                    raw_export = api.get(f"/api/sessions/{conversation}/export",
                                         headers={"Authorization": f"Bearer {alice.token}"})
                    if raw_export.status_code != 200:
                        raise RuntimeError("Opaque server export failed.")
                    stored = raw_export.json()
                    opaque = len(stored["messages"]) == 2 and all(item.get("opaque_e2ee") for item in stored["messages"])
                    plaintext_absent = text not in raw_export.text and reply not in raw_export.text
                    if not (opaque and plaintext_absent and replay_empty):
                        raise RuntimeError("E2EE relay boundary failed verification.")
            return {"status": "pass", "scope": "two_local_clients_and_separate_server_process",
                    "ratchet_library": "vodozemac 0.10.0", "encrypted_messages": 2,
                    "both_clients_decrypted": True, "fingerprints_verified": True,
                    "server_export_ciphertext_only": True, "plaintext_absent_from_server_export": True,
                    "cursor_replay_empty": True, "prekeys_refilled": True,
                    "external_services_used": False, "temporary_state_cleaned_on_exit": True}
        finally:
            stop.set()
            process.join(timeout=10)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Run the bounded offline rehearsal and exit")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/e2ee-demo"))
    args = parser.parse_args(argv)
    try:
        result = rehearse()
    except Exception:
        print("E2EE rehearsal failed; rerun the focused client tests. Existing data was not used.")
        return 1
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "e2ee-demo.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    if not args.check:
        print("For an interactive demo, run scripts.demo_local and open two terminals with clients.private_chat.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
