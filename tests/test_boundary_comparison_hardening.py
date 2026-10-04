from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from src.app.request_limits import RequestLimitsMiddleware
from tests.conftest import register_and_login


def exercise_boundary(body=b"", *, headers=()):
    sent = []
    seen = []

    async def downstream(scope, receive, send):
        seen.append(await receive())
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "method": "POST", "path": "/api/auth/login",
        "headers": list(headers),
    }
    asyncio.run(RequestLimitsMiddleware(downstream)(scope, receive, send))
    return sent, seen


@pytest.mark.parametrize("header", [
    b"host", b"authorization", b"content-type", b"origin", b"sec-fetch-site",
    b"x-request-id", b"transfer-encoding",
])
def test_ambiguous_security_headers_do_not_reach_handlers(header):
    sent, seen = exercise_boundary(headers=[(header, b"first"), (header, b"second")])
    assert sent[0]["status"] == 400
    assert not seen


def test_conflicting_message_framing_is_rejected():
    sent, seen = exercise_boundary(headers=[
        (b"content-length", b"0"), (b"transfer-encoding", b"chunked"),
    ])
    assert sent[0]["status"] == 400
    assert not seen


@pytest.mark.parametrize("headers", [
    [(b"x-large", b"a" * 32_768)],
    [(f"x-{index}".encode(), b"a") for index in range(101)],
])
def test_excessive_headers_are_rejected_before_body_read(headers):
    sent, seen = exercise_boundary(headers=headers)
    assert sent[0]["status"] == 431
    assert not seen


def test_oversized_request_id_is_never_reflected_in_boundary_response():
    sent, seen = exercise_boundary(headers=[(b"x-request-id", b"a" * 32_768)])
    assert sent[0]["status"] == 431
    response_headers = dict(sent[0]["headers"])
    assert 1 <= len(response_headers[b"x-request-id"]) <= 64
    assert response_headers[b"referrer-policy"] == b"no-referrer"
    assert not seen


def test_duplicate_login_identity_is_rejected_instead_of_last_key_winning(client):
    register_and_login(client, "json-ambiguity-user")
    response = client.post("/api/auth/login", content=(
        '{"username":"wrong-user","username":"json-ambiguity-user",'
        '"password":"Correct Horse Battery1"}'
    ), headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert "wrong-user" not in response.text
    assert "Correct Horse" not in response.text


@pytest.mark.parametrize("body", [
    b'{"unexpected":{"value":1,"value":2}}',
    b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}',
    b'{"value":1e999}',
    b'{"value":"\\ud800"}', b'{"\\udfff":"value"}',
    b'{"value":["\\ud800"]}',
    b'{"value":' + b"[" * 1_100 + b"0" + b"]" * 1_100 + b"}",
], ids=["duplicate", "nan", "infinity", "negative-infinity", "overflow",
        "surrogate-value", "surrogate-key", "surrogate-array", "nesting"])
def test_unsafe_json_never_reaches_the_csp_report_parser(client, body):
    response = client.post("/api/security/csp-report", content=body, headers={
        "Content-Type": "application/csp-report",
    })
    assert response.status_code == 400
    assert response.headers["cache-control"] == "no-store"
    assert "value" not in response.text


def test_valid_nested_unicode_json_is_replayed_without_rewriting():
    body = json.dumps({
        "data": ['literal brackets [] {}, quote \" and slash \\', {"text": "Tiếng Việt 🌦"}],
        "pair": "\U0001f600", "number": 1.25,
    }).encode()
    sent, seen = exercise_boundary(body, headers=[(b"content-type", b"application/json")])
    assert sent[0]["status"] == 204
    assert seen[0]["body"] == body


@pytest.mark.parametrize("content_type", [b"application/json", b"application/problem+json", b""])
def test_json_guard_is_not_bypassed_by_vendor_type_or_missing_content_type(content_type):
    sent, seen = exercise_boundary(
        b'{"identity":"first","ident\\u0069ty":"second"}',
        headers=[(b"content-type", content_type)] if content_type else [],
    )
    assert sent[0]["status"] == 400
    assert not seen


def test_binary_and_form_payloads_keep_their_original_content():
    for body, content_type in (
        (b"identity=first&identity=second", b"application/x-www-form-urlencoded"),
        (b"\xff\xfe\x00", b"application/octet-stream"),
    ):
        sent, seen = exercise_boundary(body, headers=[(b"content-type", content_type)])
        assert sent[0]["status"] == 204
        assert seen[0]["body"] == body


def test_direct_uvicorn_deployments_explicitly_disable_proxy_header_trust():
    for path in (Path("Dockerfile"), Path("docker-compose.local.yml")):
        source = path.read_text(encoding="utf-8")
        assert '"--no-proxy-headers"' in source
