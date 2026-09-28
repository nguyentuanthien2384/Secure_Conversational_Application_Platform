"""Exercise the registered Gradio callbacks against the real auth API.

Only the UI's HTTP transport is adapted to TestClient. Authentication,
revocation, MFA, cookie handoff, and the isolated SQLite database remain real.
"""

from __future__ import annotations

import inspect
import re
from datetime import timedelta
from types import SimpleNamespace

import gradio as gr
import pytest
from fastapi.testclient import TestClient
from gradio.helpers import special_args
from starlette.requests import Request

from src.app import gradio_ui
from src.app.db import utcnow
from src.app.models import AuthSession, User
from src.app.ui_session import COOKIE_NAME
from tests.test_mfa import enroll_and_enable

PASSWORD = "Correct Horse Battery1"
ORIGIN = "http://127.0.0.1"
BRIDGE_HEADERS = {"Origin": ORIGIN, "X-SCAP-UI": "1"}


def _headers(token):
    return {"Authorization": f"Bearer {token}"}


def _request(cookie=None):
    headers = [] if cookie is None else [(b"cookie", f"{COOKIE_NAME}={cookie}".encode())]
    return gr.Request(Request({
        "type": "http", "scheme": "http", "method": "GET", "path": "/",
        "query_string": b"", "server": ("127.0.0.1", 80),
        "client": ("127.0.0.1", 12345), "headers": headers,
    }))


def _callback(demo, name):
    return next(callback for callback in demo.fns.values()
                if callback.fn is not None and callback.fn.__name__ == name)


def _invoke(demo, name, *values, cookie=None):
    callback = _callback(demo, name)
    request = _request(cookie)
    # This is the installed Gradio injection path, not direct request= kwargs.
    inputs, *_ = special_args(callback.fn, list(values), request=request)
    if "request" in inspect.signature(callback.fn).parameters:
        assert inputs[-1] is request, "The guard hid Gradio's request annotation"
    result = callback.fn(*inputs)
    if len(callback.outputs) > 1:
        assert len(result) == len(callback.outputs)
    return result


@pytest.fixture()
def ui(app, monkeypatch):
    with TestClient(app, base_url=ORIGIN) as client:
        calls = []

        def api(token, method, path, payload=None):
            calls.append((method, path))
            response = client.request(method, path, headers=_headers(token) if token else {},
                                      json=payload)
            if response.status_code >= 400:
                raise gr.Error(response.json().get("detail", "Request failed"))
            return response.json() if response.content else {}

        monkeypatch.setattr(gradio_ui, "_api", api)
        monkeypatch.setattr(gr, "Info", lambda *args, **kwargs: None)
        monkeypatch.setattr(gr, "Warning", lambda *args, **kwargs: None)
        store = app.state.ui_session_store
        yield SimpleNamespace(app=app, client=client, store=store, calls=calls,
                              demo=gradio_ui.build_ui(session_store=store))


def _login(ui, username="reload-user"):
    response = ui.client.post("/api/auth/register", json={"username": username, "password": PASSWORD})
    assert response.status_code == 201, response.text
    return _invoke(ui.demo, "do_login", username, PASSWORD)


def _remember(ui, state):
    markup = _invoke(ui.demo, "remember_session", state[0], state[1])
    assert state[0] not in markup
    ticket = re.search(r'data-scap-session-ticket="([A-Za-z0-9_-]{43})"', markup)[1]
    response = ui.client.post("/api/ui-session/attach", headers=BRIDGE_HEADERS,
                              json={"ticket": ticket})
    assert response.status_code == 204, response.text
    assert "HttpOnly" in response.headers["set-cookie"]
    return ui.client.cookies.get(COOKIE_NAME)


def _assert_logged_out(result):
    assert result[:3] == ("", 0.0, "")
    assert result[3] == gr.update(visible=True)
    assert result[4] == gr.update(visible=False)


def test_reload_restores_real_account_and_history_without_extending_expiry(ui):
    state = _login(ui)
    response = ui.client.post("/api/sessions", headers=_headers(state[0]),
                              json={"title": "Restored conversation"})
    assert response.status_code == 201, response.text
    session_id = response.json()["id"]
    cookie = _remember(ui, state)
    ui.calls.clear()

    restored = _invoke(ui.demo, "restore_session", cookie=cookie)
    workspace = _invoke(ui.demo, "load_workspace", restored[0])

    assert restored[:2] == state[:2]
    assert restored[3] == gr.update(visible=False)
    assert restored[4] == gr.update(visible=True)
    assert "reload-user" in workspace[3]
    assert workspace[4]["value"] == session_id
    assert ui.store.restore(cookie) == state[:2]
    assert ("GET", "/api/auth/me") in ui.calls
    assert ("POST", "/api/auth/refresh") not in ui.calls


def test_mfa_challenge_is_not_remembered_until_second_factor_succeeds(ui):
    _, _, recovery_codes = enroll_and_enable(ui.client, "reload-mfa")
    challenged = _invoke(ui.demo, "do_login", "reload-mfa", PASSWORD)
    assert challenged[0] == "" and challenged[1] == 0 and challenged[2]
    result = _invoke(ui.demo, "remember_session", challenged[0], challenged[1])
    assert "data-scap-login-result" in result
    assert "data-scap-session-ticket" not in result
    _assert_logged_out(_invoke(ui.demo, "restore_session"))

    authenticated = _invoke(ui.demo, "do_mfa_verify", challenged[2], recovery_codes[0])
    cookie = _remember(ui, authenticated)
    restored = _invoke(ui.demo, "restore_session", cookie=cookie)
    assert restored[:2] == authenticated[:2]
    assert ui.client.get("/api/auth/me", headers=_headers(restored[0])).json()["mfa_enabled"]


@pytest.mark.parametrize("change", ["revoke", "logout_all", "password", "disable"])
def test_reload_rechecks_server_side_account_and_session_revocation(ui, change):
    state = _login(ui)
    cookie = _remember(ui, state)
    token = state[0]
    headers = _headers(token)
    if change == "revoke":
        jti = ui.app.state.token_service.decode(token)["jti"]
        response = ui.client.delete(f"/api/auth/sessions/{jti}", headers=headers)
    elif change == "logout_all":
        response = ui.client.post("/api/auth/logout-all", headers=headers)
    elif change == "password":
        response = ui.client.patch("/api/auth/password", headers=headers,
                                   json={"current_password": PASSWORD,
                                         "new_password": "New Correct Horse Battery2"})
    else:
        user_id = ui.client.get("/api/auth/me", headers=headers).json()["id"]
        with ui.app.state.database.session_factory() as db:
            db.add(User(username="reload-admin", role="admin",
                        password_hash=ui.app.state.password_service.hash(PASSWORD)))
            db.commit()
        admin = ui.client.post("/api/auth/login", json={"username": "reload-admin",
                                                        "password": PASSWORD}).json()["access_token"]
        response = ui.client.patch(f"/api/admin/users/{user_id}/status", headers=_headers(admin),
                                   json={"is_active": False})
    assert response.status_code in (200, 204), response.text
    assert ui.store.restore(cookie) is not None, "Server revocation must be independently checked"

    _assert_logged_out(_invoke(ui.demo, "restore_session", cookie=cookie))
    assert ui.store.restore(cookie) is None


def test_idle_expired_auth_is_rejected_even_while_browser_handle_is_live(ui):
    state = _login(ui)
    cookie = _remember(ui, state)
    jti = ui.app.state.token_service.decode(state[0])["jti"]
    with ui.app.state.database.session_factory() as db:
        db.get(AuthSession, jti).last_activity_at = utcnow() - timedelta(minutes=31)
        db.commit()
    assert ui.store.restore(cookie) is not None
    _assert_logged_out(_invoke(ui.demo, "restore_session", cookie=cookie))
    assert ui.store.restore(cookie) is None


def test_expired_browser_handle_does_not_attempt_auth_or_expose_workspace(ui, monkeypatch):
    state = _login(ui)
    cookie = _remember(ui, state)
    monkeypatch.setattr(ui.store, "_clock", lambda: state[1] + 1)
    ui.calls.clear()
    _assert_logged_out(_invoke(ui.demo, "restore_session", cookie=cookie))
    assert ui.calls == []


def test_renewal_remembers_latest_token_and_rotates_old_browser_handle(ui):
    state = _login(ui)
    old_cookie = _remember(ui, state)
    renewed = _invoke(ui.demo, "extend_session", state[0])
    assert renewed[0] != state[0]
    # Reload can race the asynchronous JS cookie update immediately after
    # the success message. The old cookie must already resolve to the new JWT.
    assert _invoke(ui.demo, "restore_session", cookie=old_cookie)[:2] == renewed[:2]
    cookie = _remember(ui, renewed)
    assert cookie != old_cookie
    assert ui.store.restore(old_cookie) is None
    assert ui.client.get("/api/auth/me", headers=_headers(state[0])).status_code == 401

    restored = _invoke(ui.demo, "restore_session", cookie=cookie)
    assert restored[:2] == renewed[:2]
    assert ui.store.restore(cookie) == renewed[:2]


def test_logout_revokes_cookie_and_api_session_before_future_reload(ui):
    state = _login(ui)
    cookie = _remember(ui, state)
    _assert_logged_out(_invoke(ui.demo, "do_logout", state[0], cookie=cookie))
    assert ui.store.restore(cookie) is None
    assert ui.client.get("/api/auth/me", headers=_headers(state[0])).status_code == 401
    _assert_logged_out(_invoke(ui.demo, "restore_session", cookie=cookie))
    response = ui.client.post("/api/ui-session/clear", headers=BRIDGE_HEADERS)
    assert response.status_code == 204
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert ui.client.cookies.get(COOKIE_NAME) is None


def test_separate_browser_cannot_restore_another_browsers_account(ui):
    first = _login(ui, "browser-alice")
    first_cookie = _remember(ui, first)
    ui.client.cookies.clear()
    second = _login(ui, "browser-bob")
    second_cookie = _remember(ui, second)
    _assert_logged_out(_invoke(ui.demo, "restore_session"))
    alice = _invoke(ui.demo, "restore_session", cookie=first_cookie)
    bob = _invoke(ui.demo, "restore_session", cookie=second_cookie)
    assert alice[0] == first[0] and bob[0] == second[0] and alice[0] != bob[0]
    _invoke(ui.demo, "do_logout", first[0], cookie=first_cookie)
    assert ui.store.restore(second_cookie) == second[:2]


def test_request_injection_and_persistence_are_wired_to_real_ui_events(ui):
    dependencies = ui.demo.config["dependencies"]
    for name in ("restore_session", "do_logout", "change_password", "logout_all"):
        callback = _callback(ui.demo, name)
        request = _request()
        values = [None] * len(callback.inputs)
        inputs, *_ = special_args(callback.fn, values, request=request)
        assert inputs[-1] is request, name
    restore = _callback(ui.demo, "restore_session")
    load_event = next(item for item in dependencies if item["id"] == restore._id)
    assert any(event == "load" for _, event in load_event["targets"])
    for name in ("do_login", "do_mfa_verify", "extend_session"):
        callback = _callback(ui.demo, name)
        next_event = next(item for item in dependencies if item["trigger_after"] == callback._id)
        assert ui.demo.fns[next_event["id"]].fn.__name__ == "remember_session"
        assert next_event["api_visibility"] == "private"


def test_old_tab_expiry_does_not_clear_a_newer_browser_session(ui, monkeypatch):
    state = _login(ui)
    _remember(ui, state)
    renewed = _invoke(ui.demo, "extend_session", state[0])
    cookie = _remember(ui, renewed)
    monkeypatch.setattr(gradio_ui.time, "time", lambda: state[1] + 1)
    result = _invoke(ui.demo, "tick", state[1], False, cookie=cookie)
    _assert_logged_out(result)
    assert gradio_ui.SESSION_CLEAR_MARKUP not in result
    assert ui.store.restore(cookie) == renewed[:2]


def test_logout_from_stale_tab_also_revokes_the_current_browser_token(ui):
    state = _login(ui)
    _remember(ui, state)
    renewed = _invoke(ui.demo, "extend_session", state[0])
    cookie = _remember(ui, renewed)
    _invoke(ui.demo, "do_logout", state[0], cookie=cookie)
    assert ui.client.get("/api/auth/me", headers=_headers(renewed[0])).status_code == 401
    assert ui.store.restore(cookie) is None
