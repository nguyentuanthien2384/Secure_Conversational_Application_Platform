"""Rotated-token reuse detection (RFC 9700 §4.14.2) and device cookies (OWASP)."""

from __future__ import annotations

from datetime import timedelta

import gradio as gr
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.requests import Request

from src.app import gradio_ui
from src.app.account_security import (
    DEVICE_COOKIE_NAME,
    DEVICE_TOKEN_HEADER,
    DeviceTokenService,
)
from src.app.audit import sign_ui_client_context
from src.app.db import utcnow
from src.app.main import create_app
from src.app.models import AuditEvent, RevokedToken, User
from src.app.ui_session import COOKIE_NAME, BrowserSessionStore
from tests.conftest import register_and_login

PASSWORD = "Correct Horse Battery1"
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36"


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def refresh(client: TestClient, token: str) -> str:
    response = client.post("/api/auth/refresh", headers=auth(token))
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def age_rotation(app, jti_token: str, seconds: int) -> None:
    jti = app.state.token_service.decode(jti_token)["jti"]
    with app.state.database.session_factory() as db:
        row = db.get(RevokedToken, jti)
        row.created_at = utcnow() - timedelta(seconds=seconds)
        db.commit()


def audit_rows(app, event_type: str) -> list[AuditEvent]:
    with app.state.database.session_factory() as db:
        rows = list(db.scalars(select(AuditEvent).where(AuditEvent.event_type == event_type)))
        for row in rows:
            db.expunge(row)
        return rows


# ───────────────────────── token reuse ─────────────────────────


def test_in_flight_use_of_a_just_rotated_token_is_only_rejected(client: TestClient, app):
    old = register_and_login(client, "reuse-grace")
    new = refresh(client, old)
    assert client.get("/api/auth/me", headers=auth(old)).status_code == 401
    assert client.get("/api/auth/me", headers=auth(new)).status_code == 200
    assert audit_rows(app, "auth.session.token_reuse") == []


def test_reuse_after_grace_revokes_the_whole_device_family(client: TestClient, app):
    stolen = register_and_login(client, "reuse-theft")
    other_device = client.post(
        "/api/auth/login", json={"username": "reuse-theft", "password": PASSWORD}
    ).json()["access_token"]
    current = refresh(client, refresh(client, stolen))
    age_rotation(app, stolen, 120)

    assert client.get("/api/auth/me", headers=auth(stolen)).status_code == 401
    assert client.get("/api/auth/me", headers=auth(current)).status_code == 401
    assert client.get("/api/auth/me", headers=auth(other_device)).status_code == 200

    alerts = audit_rows(app, "auth.session.token_reuse")
    assert len(alerts) == 1 and alerts[0].outcome == "blocked"
    assert '"mitre_technique":"T1550.001"' in alerts[0].details_json
    # Presenting it again finds an already closed family: no duplicate alert.
    client.get("/api/auth/me", headers=auth(stolen))
    assert len(audit_rows(app, "auth.session.token_reuse")) == 1


def test_reuse_after_logout_is_not_reported_as_theft(client: TestClient, app):
    old = register_and_login(client, "reuse-logout")
    new = refresh(client, old)
    assert client.post("/api/auth/logout", headers=auth(new)).status_code == 204
    age_rotation(app, old, 120)
    assert client.get("/api/auth/me", headers=auth(old)).status_code == 401
    assert audit_rows(app, "auth.session.token_reuse") == []


def test_token_reuse_is_shown_to_the_account_owner(client: TestClient, app):
    stolen = register_and_login(client, "reuse-visible")
    refresh(client, stolen)
    age_rotation(app, stolen, 120)
    client.get("/api/auth/me", headers=auth(stolen))
    fresh = client.post(
        "/api/auth/login", json={"username": "reuse-visible", "password": PASSWORD}
    ).json()["access_token"]
    events = client.get("/api/auth/security-activity", headers=auth(fresh)).json()["events"]
    reuse = next(item for item in events if item["event_type"] == "auth.session.token_reuse")
    assert reuse["severity"] == "critical"


def test_ui_follows_rotations_so_stale_tabs_never_look_like_theft(monkeypatch):
    store = BrowserSessionStore()
    store.rotate_token("token-a", "token-b", 10**10)
    store.rotate_token("token-b", "token-c", 10**10)
    assert store.current_token("token-a") == "token-c"
    assert store.current_token("unrelated") == "unrelated"

    sent = {}

    class Response:
        status_code = 200
        headers: dict = {}

        @staticmethod
        def json():
            return {}

    class Client:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get(self, _path, headers=None, params=None):
            sent.update(headers)
            return Response()

    import httpx

    monkeypatch.setattr(httpx, "Client", Client)
    monkeypatch.setattr(gradio_ui, "_SESSION_STORE", store)
    gradio_ui._api("token-a", "GET", "/api/auth/me")
    assert sent["Authorization"] == "Bearer token-c"


# ───────────────────────── device tokens ─────────────────────────


def test_device_tokens_are_account_bound_tamper_evident_and_expire():
    service = DeviceTokenService("secret-for-device-tests-0123456789", max_age_days=30)
    device = service.new_device_id()
    token = service.issue("user-1", device, now=1_000_000)
    assert service.verify(token, "user-1", now=1_000_100) == device
    assert service.verify(token, "user-2", now=1_000_100) is None
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    assert service.verify(tampered, "user-1", now=1_000_100) is None
    assert service.verify(token, "user-1", now=1_000_000 + 31 * 86_400) is None
    other = DeviceTokenService("another-deployment-secret-000000000", max_age_days=30)
    assert other.verify(token, "user-1", now=1_000_100) is None


def test_device_token_beats_a_spoofed_user_agent(client: TestClient, app):
    client.post("/api/auth/register", json={"username": "device-owner", "password": PASSWORD})
    owner = sign_ui_client_context(app.state.ui_client_context_key, "192.0.2.10", CHROME)
    first = client.post(
        "/api/auth/login", json={"username": "device-owner", "password": PASSWORD}, headers=owner
    ).json()
    owner[DEVICE_TOKEN_HEADER] = first["device_token"]

    again = client.post(
        "/api/auth/login", json={"username": "device-owner", "password": PASSWORD}, headers=owner
    )
    assert again.status_code == 200
    assert audit_rows(app, "auth.login.new_device") == []

    # Same IP and identical User-Agent, but no device token: a different machine.
    attacker = sign_ui_client_context(app.state.ui_client_context_key, "192.0.2.10", CHROME)
    client.post(
        "/api/auth/login", json={"username": "device-owner", "password": PASSWORD},
        headers=attacker,
    )
    assert len(audit_rows(app, "auth.login.new_device")) == 1


def test_trusted_device_on_a_new_network_survives_a_stranger_lockout(client: TestClient, app):
    client.post("/api/auth/register", json={"username": "device-travel", "password": PASSWORD})
    home = sign_ui_client_context(app.state.ui_client_context_key, "192.0.2.20", CHROME)
    device_token = client.post(
        "/api/auth/login", json={"username": "device-travel", "password": PASSWORD}, headers=home
    ).json()["device_token"]
    stranger = sign_ui_client_context(app.state.ui_client_context_key, "198.51.100.20", CHROME)
    for _ in range(5):
        client.post(
            "/api/auth/login", json={"username": "device-travel", "password": "wrong password!!"},
            headers=stranger,
        )
    hotel = {
        **sign_ui_client_context(app.state.ui_client_context_key, "203.0.113.20", CHROME),
        DEVICE_TOKEN_HEADER: device_token,
    }
    response = client.post(
        "/api/auth/login", json={"username": "device-travel", "password": PASSWORD}, headers=hotel
    )
    assert response.status_code == 200, response.text
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "device-travel"))
        assert user.locked_until is not None  # still locked for strangers


def test_handoff_sets_an_httponly_device_cookie_once(settings):
    app = create_app(settings)
    with TestClient(app) as client:
        store: BrowserSessionStore = app.state.ui_session_store
        store.remember_device("access-token", "v1.device-token-value")
        ticket = store.issue("access-token", 10**10)
        response = client.post(
            "/api/ui-session/attach", json={"ticket": ticket},
            headers={"X-SCAP-UI": "1", "Origin": str(client.base_url).rstrip("/")},
        )
        assert response.status_code == 204
        cookies = response.headers.get_list("set-cookie")
        device = next(item for item in cookies if item.startswith(f"{DEVICE_COOKIE_NAME}="))
        assert "HttpOnly" in device and "SameSite=strict" in device and "Max-Age=" in device
        assert any(item.startswith(f"{COOKIE_NAME}=") for item in cookies)
        handle = response.cookies.get(COOKIE_NAME)
        assert store.take_device_token(handle) is None  # delivered exactly once


def test_ui_relays_the_device_cookie_to_the_api(app, monkeypatch):
    from gradio.context import LocalContext

    monkeypatch.setattr(gradio_ui, "_CLIENT_CONTEXT_KEY", app.state.ui_client_context_key)
    browser = gr.Request(Request({
        "type": "http", "method": "POST", "path": "/gradio_api/queue/join",
        "headers": [(b"user-agent", CHROME.encode()),
                    (b"cookie", f"{DEVICE_COOKIE_NAME}=v1.abc".encode())],
        "client": ("203.0.113.40", 443),
    }))
    marker = LocalContext.request.set(browser)
    try:
        headers = gradio_ui._browser_context_headers()
    finally:
        LocalContext.request.reset(marker)
    assert headers[DEVICE_TOKEN_HEADER] == "v1.abc"


@pytest.mark.parametrize("value", ["", "x" * 201, "v1.é"])
def test_ui_drops_malformed_device_cookies(app, monkeypatch, value):
    from gradio.context import LocalContext

    browser = gr.Request(Request({
        "type": "http", "method": "POST", "path": "/",
        "headers": [(b"cookie", f"{DEVICE_COOKIE_NAME}={value}".encode())],
        "client": ("203.0.113.41", 443),
    }))
    marker = LocalContext.request.set(browser)
    try:
        assert DEVICE_TOKEN_HEADER not in gradio_ui._browser_context_headers()
    finally:
        LocalContext.request.reset(marker)
