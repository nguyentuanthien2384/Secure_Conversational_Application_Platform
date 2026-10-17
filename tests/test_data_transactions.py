"""Data mutations retain their bearer, quota and audit transaction boundary."""
from __future__ import annotations

import functools
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import event, select
from sqlalchemy.exc import OperationalError

from src.app.audit_chain import verify_chain
from src.app.db import utcnow
from src.app.e2ee import (
    build_device_approval_message,
    build_device_possession_message,
    encode_base64url,
)
from src.app.models import (
    AuditEvent,
    ChatSession,
    ConversationMember,
    E2eeDevice,
    E2eeDeviceChallenge,
    E2eeEnvelope,
    E2eePreKey,
    SecureMessage,
    SessionKeyEpoch,
)
from tests.conftest import register_and_login
from tests.test_high_security_features import auth, register_device


def device_payload(client, token, *, approver=None):
    account_id = client.get("/api/auth/me", headers=auth(token)).json()["id"]
    challenge = client.post("/api/e2ee/devices/challenge", headers=auth(token)).json()
    key, device_id = Ed25519PrivateKey.generate(), str(uuid.uuid4())
    identity = encode_base64url(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    ))
    signed = os.urandom(32)
    payload = {
        "challenge_id": challenge["id"], "challenge": challenge["challenge"],
        "device_id": device_id, "display_name": "Transaction device", "identity_key": identity,
        "possession_signature": encode_base64url(key.sign(build_device_possession_message(
            account_id=account_id, device_id=device_id,
            identity_public_key_b64=identity, challenge_b64=challenge["challenge"],
        ))),
        "signed_prekey": encode_base64url(signed),
        "signed_prekey_signature": encode_base64url(key.sign(signed)),
        "one_time_prekeys": [encode_base64url(os.urandom(32))],
    }
    if approver is not None:
        approver_id, approver_key = approver
        payload["approver_device_id"] = approver_id
        payload["approval_signature"] = encode_base64url(approver_key.sign(build_device_approval_message(
            account_id=account_id, approver_device_id=approver_id, new_device_id=device_id,
            new_device_public_key_b64=identity, approval_challenge_b64=challenge["challenge"],
        )))
    return payload


def prepare_data_action(client, operation, app=None):
    token = register_and_login(client, "data-transaction-owner")
    private = operation.startswith("e2ee_") or operation == "prekey"
    sid = client.post("/api/sessions", headers=auth(token), json={
        "title": "Transaction conversation", "security_mode": "private_e2ee" if private else "secure",
    }).json()["id"]
    method, expected = "POST", 201
    if operation == "create":
        path, body, audit = "/api/sessions", {"title": "Atomic new conversation"}, "chat.session.create"
    elif operation == "rename":
        method, path, body, audit, expected = "PATCH", f"/api/sessions/{sid}", {"title": "Atomic rename"}, "chat.session.rename", 200
    elif operation == "policy":
        method, path, body, audit, expected = "PATCH", f"/api/sessions/{sid}/security", {"security_mode": "confidential", "data_classification": "confidential"}, "chat.session.security_policy", 200
    elif operation == "delete":
        method, path, body, audit, expected = "DELETE", f"/api/sessions/{sid}", None, "chat.session.delete", 204
    elif operation == "retention":
        with app.state.database.session_factory() as db:
            db.get(ChatSession, sid).retention_expires_at = utcnow() - timedelta(seconds=1)
            db.commit()
        method, path, body, audit, expected = "GET", f"/api/sessions/{sid}", None, "chat.session.retention_expired", 404
    elif operation in {"chat", "chat_dlp"}:
        path, body, audit = f"/api/sessions/{sid}/messages", {"content": "Email person@example.com" if operation == "chat_dlp" else "Ordinary hello"}, "dlp.redacted" if operation == "chat_dlp" else "chat.message.send"
    elif operation in {"export", "export_ticket"}:
        method = "GET" if operation == "export" else "POST"
        path = f"/api/sessions/{sid}/" + ("export" if operation == "export" else "export-ticket")
        body, expected = None, 200
        audit = "chat.session.export" if operation == "export" else "chat.session.export_ticket"
    elif operation == "e2ee_challenge":
        path, body, audit, expected = "/api/e2ee/devices/challenge", None, "e2ee.device.challenge", 200
    elif operation == "e2ee_register":
        path, body, audit = "/api/e2ee/devices", device_payload(client, token), "e2ee.device.register"
    elif operation in {"e2ee_add", "e2ee_remove"}:
        register_and_login(client, "data-transaction-member")
        path, body, audit = f"/api/sessions/{sid}/e2ee/members", {"username": "data-transaction-member"}, "e2ee.member.add"
        if operation == "e2ee_remove":
            assert client.post(path, headers=auth(token), json=body).status_code == 201
            method, path, body, audit, expected = "DELETE", path + "/data-transaction-member", None, "e2ee.member.remove", 204
    else:
        device_id, key = register_device(client, token)
        if operation == "e2ee_revoke":
            assert client.post("/api/e2ee/devices", headers=auth(token), json=device_payload(
                client, token, approver=(device_id, key),
            )).status_code == 201
            method, path, body, audit, expected = "DELETE", f"/api/e2ee/devices/{device_id}", None, "e2ee.device.revoke", 204
        elif operation == "prekey":
            method, path, body, audit, expected = "GET", f"/api/e2ee/users/data-transaction-owner/prekey-bundle?device_id={device_id}", None, "e2ee.prekey.consume", 200
        else:
            assert operation == "e2ee_send"
            path, audit = f"/api/sessions/{sid}/e2ee/envelopes", "e2ee.envelope.send"
            body = {"version": 1, "protocol": "double-ratchet", "recipient": device_id,
                    "recipient_device_id": device_id, "epoch": 1, "client_message_id": "atomic-message",
                    "sender_device_id": device_id, "message_kind": "application",
                    "header": encode_base64url(os.urandom(32)), "ciphertext": encode_base64url(os.urandom(64))}
    return token, method, path, body, audit, expected


def data_snapshot(app):
    models = (ChatSession, SecureMessage, SessionKeyEpoch, E2eeDevice, E2eeDeviceChallenge,
              E2eePreKey, E2eeEnvelope, ConversationMember, AuditEvent)
    with app.state.database.session_factory() as db:
        return {model.__name__: sorted([tuple(getattr(row, column.name) for column in model.__table__.columns)
                                       for row in db.scalars(select(model))], key=repr)
                for model in models}


OPERATIONS = ["create", "rename", "policy", "delete", "retention", "chat", "chat_dlp", "export", "export_ticket", "e2ee_challenge",
              "e2ee_register", "e2ee_revoke", "prekey", "e2ee_add", "e2ee_remove", "e2ee_send"]


@pytest.mark.parametrize("operation", OPERATIONS)
def test_data_mutations_and_required_audits_roll_back_together(client, app, operation):
    token, method, path, body, audit, expected = prepare_data_action(client, operation, app)
    before = data_snapshot(app)
    failed = []

    def fail_selected(_conn, _cursor, statement, _params, context, _many):
        if (statement.lstrip().lower().startswith("insert into audit_events")
                and any(item.get("event_type") == audit for item in context.compiled_parameters)):
            failed.append(True)
            raise OperationalError("simulated audit failure", None, RuntimeError("test"))

    event.listen(app.state.database.engine, "before_cursor_execute", fail_selected)
    try:
        response = client.request(method, path, headers=auth(token), json=body)
    finally:
        event.remove(app.state.database.engine, "before_cursor_execute", fail_selected)
    assert failed == [True]
    assert response.status_code == 503, response.text
    assert data_snapshot(app) == before
    retry = client.request(method, path, headers=auth(token), json=body)
    assert retry.status_code == expected, retry.text
    with app.state.database.session_factory() as db:
        assert verify_chain(db, app.state.audit_key).intact


@pytest.mark.parametrize("operation", [item for item in OPERATIONS if item != "chat_dlp"])
@pytest.mark.parametrize("transition", ["logout", "refresh", "logout-all"])
def test_data_mutation_rechecks_the_exact_inflight_bearer(client, app, operation, transition):
    token, method, path, body, _audit, _expected = prepare_data_action(client, operation, app)
    route = next(item for item in app.routes if getattr(item, "path", "") == "/api/auth/password")
    dependency = next(item.call for item in route.dependant.dependencies if item.name == "user")
    reached, release = threading.Event(), threading.Event()

    @functools.wraps(dependency)
    def pause(*args, **kwargs):
        user = dependency(*args, **kwargs)
        if kwargs["request"].url.path == path.split("?")[0] and kwargs["request"].method == method:
            reached.set()
            assert release.wait(10)
        return user

    app.dependency_overrides[dependency] = pause
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(client.request, method, path, headers=auth(token), json=body)
            try:
                assert reached.wait(10)
                revoked = client.post(f"/api/auth/{transition}", headers=auth(token))
                assert revoked.status_code in {200, 204}, revoked.text
                before = data_snapshot(app)
            finally:
                release.set()
            response = pending.result(timeout=10)
    finally:
        app.dependency_overrides.pop(dependency, None)
    assert response.status_code == 401, response.text
    assert 'error="invalid_token"' in response.headers.get("WWW-Authenticate", "")
    assert data_snapshot(app) == before


def test_concurrent_creation_cannot_exceed_the_per_owner_quota(client, app):
    token = register_and_login(client, "creation-quota")
    object.__setattr__(app.state.settings, "max_sessions_per_user", 1)
    start = threading.Barrier(2)

    def create(index):
        start.wait(timeout=10)
        return client.post("/api/sessions", headers=auth(token), json={"title": f"Concurrent {index}"})

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(create, range(2)))
    assert sorted(item.status_code for item in responses) == [201, 409]
    assert len(client.get("/api/sessions", headers=auth(token)).json()) == 1
