from __future__ import annotations

import asyncio
import json

import pytest
from sqlalchemy import select

from src.app.models import AuditEvent
from src.app.request_limits import MAX_BODY_BYTES, RequestLimitsMiddleware
from tests.conftest import register_and_login


def exercise_guard(chunks, *, headers=(), timeout=1.0, delay=0):
    sent = []
    seen = []
    remaining = iter(chunks)

    async def downstream(scope, receive, send):
        seen.append(await receive())
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        if delay:
            await asyncio.sleep(delay)
        return next(remaining)

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "path": "/api/auth/login", "headers": list(headers)}
    asyncio.run(RequestLimitsMiddleware(downstream, read_timeout=timeout)(scope, receive, send))
    return sent, seen


@pytest.mark.parametrize("headers", [(), ((b"content-length", b"2"),)])
def test_actual_stream_size_is_bounded_before_route_runs(headers):
    sent, seen = exercise_guard(
        [
            {"type": "http.request", "body": b"x" * MAX_BODY_BYTES, "more_body": True},
            {"type": "http.request", "body": b"x", "more_body": False},
        ],
        headers=headers,
    )
    assert sent[0]["status"] == 413
    assert not seen


def test_legal_chunked_body_replayed_intact():
    sent, seen = exercise_guard([
        {"type": "http.request", "body": b'{"x":', "more_body": True},
        {"type": "http.request", "body": b'1}', "more_body": False},
    ])
    assert sent[0]["status"] == 204
    assert seen == [{"type": "http.request", "body": b'{"x":1}', "more_body": False}]


@pytest.mark.parametrize("headers", [
    ((b"content-length", b"-1"),),
    ((b"content-length", b"bogus"),),
    ((b"content-length", b"9" * 100),),
    ((b"content-length", b"1"), (b"content-length", b"2")),
])
def test_invalid_length_rejected_without_reading(headers):
    sent, seen = exercise_guard([], headers=headers)
    assert sent[0]["status"] == 400
    assert not seen


def test_slow_body_times_out_before_handler():
    sent, seen = exercise_guard([], timeout=0.01, delay=0.1)
    assert sent[0]["status"] == 408
    assert not seen


def test_disconnect_never_invokes_handler():
    sent, seen = exercise_guard([{"type": "http.disconnect"}])
    assert not sent and not seen


def test_large_uri_rejected_with_safe_headers(client):
    response = client.get("/api/health?q=" + "a" * 16_384)
    assert response.status_code == 414
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-request-id"]


def test_signature_after_old_telemetry_truncation_is_detected(client, app):
    response = client.get("/" + "a" * 250 + "/%3Cscript%3E", headers={"X-Request-ID": "late-path"})
    assert response.status_code in {403, 404}
    with app.state.database.session_factory() as db:
        events = list(db.scalars(select(AuditEvent).where(AuditEvent.request_id == "late-path")))
    assert any(row.target_id == "XSS-001" for row in events)


def test_encoded_fragment_in_path_does_not_hide_ids_payload(client, app):
    client.get("/test%23%3Cscript%3E", headers={"X-Request-ID": "fragment-proof"})
    with app.state.database.session_factory() as db:
        events = list(db.scalars(select(AuditEvent).where(AuditEvent.request_id == "fragment-proof")))
    assert any(row.target_id == "XSS-001" for row in events)


def test_privileged_route_denial_is_audited(client, app):
    token = register_and_login(client, "ordinary-user")
    response = client.get("/api/admin/security/maintenance", headers={
        "Authorization": f"Bearer {token}", "X-Request-ID": "role-denial",
    })
    assert response.status_code == 403
    with app.state.database.session_factory() as db:
        event = db.scalar(select(AuditEvent).where(AuditEvent.request_id == "role-denial"))
    assert event.event_type == "authorization.denied"
    assert json.loads(event.details_json)["reason"] == "admin_role_required"


@pytest.mark.parametrize("headers, reason", [
    ({}, "missing_credentials"),
    ({"Authorization": "Bearer confidential-invalid-token"}, "invalid_token"),
])
def test_auth_denial_is_correlated_without_token_leak(client, app, headers, reason):
    response = client.get("/api/auth/me", headers={**headers, "X-Request-ID": "denial-proof"})
    assert response.status_code == 401
    with app.state.database.session_factory() as db:
        event = db.scalar(select(AuditEvent).where(AuditEvent.request_id == "denial-proof"))
        assert event.event_type == "auth.access.denied"
        assert event.outcome == "denied"
        assert json.loads(event.details_json)["reason"] == reason
        assert "confidential-invalid-token" not in event.details_json


def test_auth_denial_audit_writes_are_bounded(client, app):
    for _ in range(15):
        assert client.get("/api/auth/me").status_code == 401
    with app.state.database.session_factory() as db:
        events = list(db.scalars(select(AuditEvent).where(AuditEvent.event_type == "auth.access.denied")))
    assert len(events) == 10
