from __future__ import annotations

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from src.app.browser_security import browser_request_denial
from src.app.main import create_app
from tests.conftest import register_and_login


def check(headers=(), *, method="POST", allowed=(), scheme="https", host="chat.example"):
    request = Request({
        "type": "http", "method": method, "scheme": scheme,
        "path": "/api/auth/login", "headers": [(b"host", host.encode()), *headers],
    })
    return browser_request_denial(request, allowed)


@pytest.mark.parametrize("origin", [
    "https://evil.example", "https://chat.example.evil.example", "https://evil.chat.example",
    "http://chat.example", "https://chat.example:444", "null", "",
    "https://chat.example/", "https://chat.example#", "https://chat.example?",
    "https://chat.example@evil.example", "https://evil.example@chat.example",
    "https://chat.example\\@evil.example", "https://chat.example:",
    "https://chat.example:0", "https://chat.example:65536", "https://chat.example\t",
    "https://chat.example https://evil.example", "https://chat.example,https://evil.example",
])
def test_unsafe_origin_cannot_be_laundered_by_same_origin_fetch_header(origin):
    assert check([(b"origin", origin.encode()), (b"sec-fetch-site", b"same-origin")])


@pytest.mark.parametrize("headers", [
    [], [(b"sec-fetch-site", b"same-origin")], [(b"sec-fetch-site", b"none")],
    [(b"origin", b"https://chat.example")], [(b"origin", b"https://CHAT.EXAMPLE:443")],
])
def test_same_origin_and_headerless_api_clients_remain_supported(headers):
    assert check(headers) is None


@pytest.mark.parametrize("site", [b"cross-site", b"same-site", b"bogus", b""])
def test_untrusted_fetch_metadata_is_denied(site):
    assert check([(b"sec-fetch-site", site)])


def test_only_exact_allowlisted_origin_exempts_cross_site_request():
    headers = [(b"origin", b"https://frontend.example"), (b"sec-fetch-site", b"cross-site")]
    assert check(headers, allowed=("https://frontend.example",)) is None
    assert check(headers, allowed=("*", "https://*.example", "https://frontend.example/"))
    assert check([(b"sec-fetch-site", b"same-site")], allowed=("https://frontend.example",))


def test_duplicate_headers_and_untrusted_proxy_headers_cannot_bypass_guard():
    assert check([(b"origin", b"https://chat.example"), (b"origin", b"https://evil.example")])
    assert check([(b"sec-fetch-site", b"same-origin"), (b"sec-fetch-site", b"cross-site")])
    assert check([
        (b"origin", b"https://evil.example"), (b"x-forwarded-host", b"evil.example"),
        (b"x-forwarded-proto", b"https"),
    ])


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_safe_methods_and_preflights_are_allowed(method):
    assert check([(b"origin", b"https://evil.example")], method=method) is None


def test_ipv6_and_default_ports_are_compared_by_origin():
    assert check([(b"origin", b"https://[::1]:443")], host="[::1]") is None
    assert check([(b"origin", b"https://[::1]:444")], host="[::1]")


def test_cross_origin_write_rejected_before_authenticated_handler(client):
    token = register_and_login(client, "browser-origin-owner")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/api/sessions", headers={
        **headers, "Origin": "https://untrusted.example", "Sec-Fetch-Site": "cross-site",
    }, json={"title": "Should never be created"})
    assert response.status_code == 403
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["vary"] == "Origin, Sec-Fetch-Site"
    assert client.get("/api/sessions", headers=headers).json() == []
    assert client.post("/api/sessions", headers={
        **headers, "Origin": "http://testserver", "Sec-Fetch-Site": "same-origin",
    }, json={"title": "Allowed conversation"}).status_code == 201


def test_guard_covers_mounted_gradio_endpoints_and_scrubs_telemetry(client, monkeypatch):
    events = []
    monkeypatch.setattr("src.app.main.emit_security_event", lambda *args, **kw: events.append((args, kw)))
    for _ in range(12):
        response = client.post("/gradio_api/queue/join", json={"secret": "never-log-this"}, headers={
            "Origin": "https://evil.example/secret-path", "Sec-Fetch-Site": "cross-site",
        })
        assert response.status_code == 403
    assert len(events) == 10
    assert all(args == ("browser.origin.denied",) for args, _ in events)
    assert "never-log-this" not in repr(events)
    assert "evil.example" not in repr(events)


def test_explicit_cors_frontend_can_register_and_receive_cors_response(settings):
    application = create_app(replace(settings, allowed_origins=("https://frontend.example",)))
    with TestClient(application) as client:
        response = client.post("/api/auth/register", json={
            "username": "allowed-browser", "password": "Correct Horse Battery1",
        }, headers={"Origin": "https://frontend.example", "Sec-Fetch-Site": "cross-site"})
        assert response.status_code == 201
        assert response.headers["access-control-allow-origin"] == "https://frontend.example"
        preflight = client.options("/api/auth/register", headers={
            "Origin": "https://frontend.example", "Access-Control-Request-Method": "POST",
        })
        assert preflight.status_code == 200
