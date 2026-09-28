from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from src.app.ui_session import (
    COOKIE_NAME,
    BrowserSessionStore,
    UISessionCapacityError,
    _secure_cookie,
    register_ui_session_routes,
)


@pytest.fixture
def clock():
    return [1_900_000_000.0]


@pytest.fixture
def store(clock):
    return BrowserSessionStore(clock=lambda: clock[0])


def client_for(store, base_url="https://chat.example"):
    app = FastAPI()
    register_ui_session_routes(app, store)
    return TestClient(app, base_url=base_url)


def attach(client, ticket, **kwargs):
    return client.post(
        "/api/ui-session/attach", json={"ticket": ticket},
        headers={"X-SCAP-UI": "1", "Origin": str(client.base_url).rstrip("/")},
        **kwargs,
    )


def test_ticket_rotates_browser_handle_and_never_extends_expiry(store, clock):
    expiry = clock[0] + 100
    first_ticket = store.issue("jwt-one", expiry)
    first_cookie = store.attach(first_ticket)
    assert first_cookie != first_ticket
    clock[0] += 25
    assert store.restore(first_cookie) == ("jwt-one", expiry)
    second_cookie = store.attach(store.issue("jwt-two", expiry), first_cookie)
    assert second_cookie != first_cookie
    assert store.restore(first_cookie) is None
    assert store.restore(second_cookie) == ("jwt-two", expiry)
    clock[0] = expiry
    assert store.restore(second_cookie) is None
    assert not store._sessions


def test_ticket_expires_after_60_seconds_or_token_expiry(store, clock):
    long_ticket = store.issue("jwt-long", clock[0] + 300)
    short_ticket = store.issue("jwt-short", clock[0] + 10)
    clock[0] += 10
    with pytest.raises(ValueError):
        store.attach(short_ticket)
    clock[0] += 50
    with pytest.raises(ValueError):
        store.attach(long_ticket)
    assert not store._tickets


def test_ticket_is_consumed_atomically_across_concurrent_requests(store, clock):
    ticket = store.issue("jwt", clock[0] + 300)

    def consume(_):
        try:
            return store.attach(ticket)
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        cookies = list(pool.map(consume, range(16)))
    assert sum(cookie is not None for cookie in cookies) == 1
    assert len(store._sessions) == 1


def test_capacity_preserves_existing_sessions_and_expired_entries_are_pruned(clock):
    store = BrowserSessionStore(clock=lambda: clock[0], max_tickets=1, max_sessions=1)
    ticket = store.issue("first", clock[0] + 10)
    with pytest.raises(UISessionCapacityError):
        store.issue("second", clock[0] + 100)
    cookie = store.attach(ticket)
    next_ticket = store.issue("second", clock[0] + 100)
    with pytest.raises(UISessionCapacityError):
        store.attach(next_ticket)
    assert store.restore(cookie) == ("first", clock[0] + 10)
    replacement = store.attach(next_ticket, cookie)
    assert store.restore(cookie) is None
    assert store.restore(replacement)[0] == "second"
    clock[0] += 100
    fresh = store.attach(store.issue("fresh", clock[0] + 20))
    assert store.restore(fresh)[0] == "fresh"
    assert len(store._sessions) == 1


def test_revoke_is_browser_specific_and_invalid_handles_are_safe(store, clock):
    first = store.attach(store.issue("first", clock[0] + 100))
    second = store.attach(store.issue("second", clock[0] + 100))
    store.revoke(first)
    store.revoke(None)
    store.revoke("malformed")
    assert store.restore(first) is None
    assert store.restore("malformed") is None
    assert store.restore(second)[0] == "second"
    assert first not in store._sessions and second not in store._sessions
    assert "first" not in repr(store._sessions)


@pytest.mark.parametrize("expiry", [float("inf"), float("nan"), 0])
def test_invalid_expiration_cannot_be_stored(store, expiry):
    with pytest.raises(ValueError):
        store.issue("jwt", expiry)


def test_attach_cookie_is_httponly_host_only_strict_and_contains_no_token(store, clock):
    with client_for(store) as client:
        expiry = clock[0] + 300
        ticket = store.issue("jwt-secret-never-in-response", expiry)
        response = attach(client, ticket)
        assert response.status_code == 204
        assert response.content == b""
        header = response.headers["set-cookie"]
        assert "HttpOnly" in header and "SameSite=strict" in header and "Secure" in header
        assert "Domain=" not in header and "Path=/" in header
        assert ticket not in header and "jwt-secret" not in header
        cookie = client.cookies.get(COOKIE_NAME)
        assert cookie != ticket
        assert store.restore(cookie) == ("jwt-secret-never-in-response", expiry)
        expires = header.split("expires=", 1)[1].split(";", 1)[0]
        assert parsedate_to_datetime(expires) == datetime.fromtimestamp(expiry, timezone.utc)
        assert response.headers["cache-control"] == "no-store"
        assert attach(client, ticket).status_code == 401


@pytest.mark.parametrize("base_url, secure", [
    ("http://localhost:8000", False), ("http://127.0.0.1:8000", False),
    ("https://localhost", True),
    ("http://chat.example", True), ("http://localhost.evil.example", True),
])
def test_only_actual_loopback_http_gets_nonsecure_cookie(store, clock, base_url, secure):
    with client_for(store, base_url) as client:
        response = attach(client, store.issue("jwt", clock[0] + 300))
        assert response.status_code == 204
        assert ("; Secure" in response.headers["set-cookie"]) is secure


def test_ipv6_loopback_http_cookie_exception():
    # This Starlette TestClient release cannot construct IPv6 transport URLs.
    request = Request({
        "type": "http", "scheme": "http", "path": "/api/ui-session/attach",
        "headers": [(b"host", b"[::1]:8000")], "query_string": b"",
    })
    assert _secure_cookie(request) is False


@pytest.mark.parametrize("headers", [
    {"Origin": "https://chat.example"},
    {"X-SCAP-UI": "1", "Origin": "https://evil.example"},
    {"X-SCAP-UI": "1", "Origin": "https://child.chat.example"},
    {"X-SCAP-UI": "1", "Origin": "null"},
    {"X-SCAP-UI": "1", "Sec-Fetch-Site": "cross-site"},
    {"X-SCAP-UI": "1", "Sec-Fetch-Site": "same-site"},
    {"X-SCAP-UI": "1", "Origin": "https://evil.example", "X-Forwarded-Host": "evil.example"},
])
def test_cross_origin_attach_and_clear_fail_without_consuming_or_revoking(store, clock, headers):
    with client_for(store) as client:
        existing = store.attach(store.issue("current", clock[0] + 300))
        client.cookies.set(COOKIE_NAME, existing)
        ticket = store.issue("next", clock[0] + 300)
        for path in ("attach", "clear"):
            response = client.post(f"/api/ui-session/{path}", json={"ticket": ticket}, headers=headers)
            assert response.status_code == 403
            assert response.headers["cache-control"] == "no-store"
            assert "set-cookie" not in response.headers
        assert store.restore(existing)[0] == "current"
        assert attach(client, ticket).status_code == 204
        assert store.restore(existing) is None


def test_clear_deletes_cookie_and_only_its_server_record(store, clock):
    with client_for(store) as first, client_for(store) as second:
        attach(first, store.issue("first", clock[0] + 300))
        attach(second, store.issue("second", clock[0] + 300))
        first_cookie = first.cookies.get(COOKIE_NAME)
        second_cookie = second.cookies.get(COOKIE_NAME)
        response = first.post("/api/ui-session/clear", headers={"X-SCAP-UI": "1"})
        assert response.status_code == 204
        assert "Max-Age=0" in response.headers["set-cookie"]
        assert "HttpOnly" in response.headers["set-cookie"]
        assert not first.cookies.get(COOKIE_NAME)
        assert store.restore(first_cookie) is None
        assert store.restore(second_cookie)[0] == "second"


def test_request_size_schema_and_content_type_are_bounded_without_echoing_ticket(store, clock):
    with client_for(store) as client:
        ticket = store.issue("jwt", clock[0] + 300)
        common = {"X-SCAP-UI": "1", "Content-Type": "application/json"}
        cases = [
            ("x" * 513, common, 413),
            ('{"ticket":"' + ticket + '","extra":1}', common, 400),
            ('{"ticket":{}}', common, 400),
            ("not json", common, 400),
            ("[]", common, 400),
            ('{"ticket":"' + ticket + '"}', {"X-SCAP-UI": "1"}, 415),
        ]
        for body, headers, status in cases:
            response = client.post("/api/ui-session/attach", content=body, headers=headers)
            assert response.status_code == status
            assert ticket not in response.text
            assert "set-cookie" not in response.headers
        assert attach(client, ticket).status_code == 204


def test_unknown_browser_cookie_cannot_restore_or_change_an_existing_login(store, clock):
    with client_for(store) as client:
        victim = store.attach(store.issue("victim", clock[0] + 300))
        guessed = "a" * 43
        client.cookies.set(COOKIE_NAME, guessed)
        assert store.restore(guessed) is None
        assert attach(client, store.issue("attacker", clock[0] + 300)).status_code == 204
        assert store.restore(victim)[0] == "victim"


def test_packaged_bridge_route_is_javascript_without_evaluating_inline_code(store, tmp_path, monkeypatch):
    asset = tmp_path / "session_bridge.js"
    asset.write_text("/* packaged session bridge */", encoding="utf-8")
    monkeypatch.setattr("src.app.ui_session._BRIDGE_PATH", asset)
    with client_for(store) as client:
        response = client.get("/api/ui-session/bridge.js")
        assert response.status_code == 200
        assert response.text == "/* packaged session bridge */"
        assert response.headers["content-type"].startswith("text/javascript")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["cache-control"] == "no-store"
        assert "set-cookie" not in response.headers


def test_packaged_login_credentials_script_is_served_without_credentials(store):
    with client_for(store) as client:
        response = client.get("/api/ui-session/login-credentials.js")
        assert response.status_code == 200
        assert "PasswordCredential" in response.text
        assert response.headers["content-type"].startswith("text/javascript")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["cache-control"] == "no-store"
        assert "set-cookie" not in response.headers
