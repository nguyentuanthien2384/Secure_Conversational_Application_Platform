"""Gradio callbacks for passkeys, recovery email and password reset (fake API)."""

from __future__ import annotations

import base64
import json
import re

import gradio as gr
import pytest

from src.app import gradio_ui


@pytest.fixture(scope="module")
def demo():
    return gradio_ui.build_ui()


@pytest.fixture(autouse=True)
def notices(monkeypatch):
    shown = []
    monkeypatch.setattr(gr, "Info", lambda message, *a, **k: shown.append(("info", message)))
    monkeypatch.setattr(gr, "Warning", lambda message, *a, **k: shown.append(("warn", message)))
    return shown


def _callback(demo, name):
    return next(
        item.fn for item in demo.fns.values() if item.fn is not None and item.fn.__name__ == name
    )


class Api:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, token, method, path, body=None, *, params=None):
        self.calls.append((token, method, path, body))
        handler = self.routes.get((method, path))
        if handler is None:
            raise AssertionError(f"unexpected {method} {path}")
        return handler(body) if callable(handler) else handler


def test_passkey_login_result_is_verified_by_the_api(demo, monkeypatch):
    api = Api({("POST", "/api/auth/passkeys/authentication/verify"): {
        "access_token": "jwt", "expires_in": 1800, "device_token": "v1.dev",
    }})
    monkeypatch.setattr(gradio_ui, "_api", api)
    result = json.dumps({"mode": "get", "challenge_id": "c" * 36, "credential": {"id": "x"}})
    outputs = _callback(demo, "finish_passkey_login")(result)
    assert outputs[0] == "jwt" and outputs[-1] == ""
    assert api.calls[0][3] == {"challenge_id": "c" * 36, "credential": {"id": "x"}}


@pytest.mark.parametrize(("payload", "expected"), [
    ({"mode": "get", "error": "NotAllowedError"}, "hủy"),
    ({"mode": "get", "error": "wrong_host", "rp_id": "localhost"}, "localhost"),
    ({"mode": "get", "error": "wrong_host", "rp_id": "<script>"}, "localhost"),
    ({"mode": "create", "challenge_id": "x"}, "Không hoàn tất"),
])
def test_passkey_errors_are_explained_without_calling_the_api(demo, monkeypatch, notices, payload, expected):
    api = Api({})
    monkeypatch.setattr(gradio_ui, "_api", api)
    outputs = _callback(demo, "finish_passkey_login")(json.dumps(payload))
    assert api.calls == []
    assert all(item == gr.skip() for item in outputs[:-1])
    assert expected in notices[-1][1] and "<script>" not in notices[-1][1]


def test_passkey_registration_publishes_options_then_verifies_the_matching_result(demo, monkeypatch):
    public_key = {"challenge": "abc", "rp": {"id": "localhost"}, "user": {"id": "dXNlcg"}}
    api = Api({
        ("POST", "/api/auth/passkeys/registration/options"): {
            "challenge_id": "k" * 36, "public_key": public_key,
        },
        ("POST", "/api/auth/passkeys/registration/verify"): {"name": "Laptop"},
        ("GET", "/api/auth/passkeys"): [{
            "id": "p1", "name": "Laptop", "created_at": "2026-10-02T07:00:00Z",
            "last_used_at": None, "backed_up": True,
        }],
    })
    monkeypatch.setattr(gradio_ui, "_api", api)
    markup, state, hint, confirm, *_ = _callback(demo, "prepare_passkey")("jwt", "Laptop", "", "")
    nonce = re.search(r'data-scap-passkey-request="([a-f0-9]{32})"', markup).group(1)
    encoded = re.search(r'data-scap-passkey-options="([A-Za-z0-9_-]+)"', markup).group(1)
    assert json.loads(base64.urlsafe_b64decode(encoded + "==")) == public_key
    assert state == {"challenge_id": "k" * 36, "nonce": nonce, "name": "Laptop"}
    assert confirm["visible"] is True and hint["visible"] is True

    finish = _callback(demo, "finish_passkey_registration")
    forged = finish("jwt", json.dumps({"mode": "create", "nonce": "0" * 32, "credential": {}}), state)
    assert not any(call[2].endswith("/verify") for call in api.calls)
    assert forged[0] == "" and forged[3]["visible"] is False

    outputs = finish(
        "jwt", json.dumps({"mode": "create", "nonce": nonce, "credential": {"id": "c"}}), state
    )
    verify = next(call for call in api.calls if call[2].endswith("/registration/verify"))
    assert verify[3] == {"challenge_id": "k" * 36, "credential": {"id": "c"}, "name": "Laptop"}
    assert outputs[5] == [["Laptop", "02/10/2026 07:00", "—", "Có"]]
    assert outputs[4] == ""  # the hidden result box is cleared


def test_step_up_is_requested_once_when_the_server_asks(demo, monkeypatch):
    attempts = []

    def options(_body):
        attempts.append("options")
        if len(attempts) == 1:
            raise gr.Error("Cần xác thực lại trước thao tác nhạy cảm.")
        return {"challenge_id": "k" * 36, "public_key": {"challenge": "a"}}

    api = Api({
        ("POST", "/api/auth/passkeys/registration/options"): options,
        ("POST", "/api/auth/step-up"): {"verified_at": "now", "valid_for_seconds": 300},
    })
    monkeypatch.setattr(gradio_ui, "_api", api)
    _callback(demo, "prepare_passkey")("jwt", "", "Current password value!", "123456")
    assert [call[2] for call in api.calls] == [
        "/api/auth/passkeys/registration/options", "/api/auth/step-up",
        "/api/auth/passkeys/registration/options",
    ]
    assert api.calls[1][3] == {"password": "Current password value!", "code": "123456"}


def test_step_up_without_a_password_explains_what_to_do(demo, monkeypatch, notices):
    def options(_body):
        raise gr.Error("Cần xác thực lại trước thao tác nhạy cảm.")

    monkeypatch.setattr(gradio_ui, "_api", Api({
        ("POST", "/api/auth/passkeys/registration/options"): options,
    }))
    _callback(demo, "prepare_passkey")("jwt", "", "", "")
    assert "Nhập mật khẩu" in notices[-1][1]


def test_password_reset_callbacks(demo, monkeypatch, notices):
    api = Api({
        ("POST", "/api/auth/password-reset/request"): {"message": "Nếu tài khoản có email..."},
        ("POST", "/api/auth/password-reset/confirm"): {},
    })
    monkeypatch.setattr(gradio_ui, "_api", api)
    _callback(demo, "send_reset_code")("  student01 ")
    assert api.calls[-1][3] == {"identifier": "student01"}
    outputs = _callback(demo, "confirm_reset")("student01", " abcde-fghjk ", "A long new passphrase 2026")
    assert api.calls[-1][3] == {
        "identifier": "student01", "code": "abcde-fghjk", "new_password": "A long new passphrase 2026",
    }
    assert outputs[0] == "" and outputs[1] == "" and outputs[3] == "student01"
    by_email = _callback(demo, "confirm_reset")("a@example.com", "abcde-fghjk", "A long new passphrase 2026")
    assert by_email[3] == gr.skip()  # an email never lands in the username box
    short = _callback(demo, "confirm_reset")("student01", "abcde-fghjk", "short")
    assert short == (gr.skip(),) * 4 and "ít nhất" in notices[-1][1]


def test_email_state_is_escaped_markdown():
    rendered = gradio_ui._email_markdown({
        "email": "a_b*c@example.com", "verified_at": "2026-10-02T07:00:00Z",
        "pending_email": None, "delivery_available": True,
    })
    assert gradio_ui._safe_markdown_text("a_b*c@example.com") in rendered
    assert "a_b*c" not in rendered  # Markdown emphasis cannot be injected


def test_recovery_email_callbacks(demo, monkeypatch):
    state = {"email": None, "verified_at": None, "pending_email": None, "delivery_available": True}

    def request(body):
        state["pending_email"] = body["email"]
        return dict(state)

    def verify(body):
        assert body == {"code": "abcde-fghjk"}
        state.update(email=state["pending_email"], pending_email=None,
                     verified_at="2026-10-02T07:00:00Z")
        return dict(state)

    api = Api({
        ("POST", "/api/auth/email"): request,
        ("POST", "/api/auth/email/verify"): verify,
        ("GET", "/api/auth/email"): lambda _b: dict(state),
        ("DELETE", "/api/auth/email"): {},
    })
    monkeypatch.setattr(gradio_ui, "_api", api)
    md, *_ = _callback(demo, "send_email_code")("jwt", "me@example.com", "", "")
    assert "Đang chờ xác minh" in md
    md, code_box, email_box = _callback(demo, "verify_email_code")("jwt", "abcde-fghjk")
    assert gradio_ui._safe_markdown_text("me@example.com") in md
    assert code_box == "" and email_box == ""
    md, *_ = _callback(demo, "remove_email")("jwt", "", "")
    assert [call[1:3] for call in api.calls][-2:] == [
        ("DELETE", "/api/auth/email"), ("GET", "/api/auth/email"),
    ]


def test_passkey_script_is_served_and_loaded(app):
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        script = client.get("/api/ui-session/passkey.js")
        assert script.status_code == 200
        assert script.headers["content-type"].startswith("text/javascript")
        assert "navigator.credentials.get" in script.text and "eval(" not in script.text
        page = client.get("/")
        assert '/api/ui-session/passkey.js' in page.text
