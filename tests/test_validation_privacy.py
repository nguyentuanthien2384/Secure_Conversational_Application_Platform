from __future__ import annotations

import pytest

from tests.conftest import register_and_login


@pytest.mark.parametrize(
    ("path", "payload", "private_value", "field"),
    [
        (
            "/api/auth/login",
            {"username": "validation.test", "password": "private-login-password-" * 8},
            "private-login-password-" * 8,
            "password",
        ),
        (
            "/api/auth/register",
            {"username": "validation.test", "password": "private"},
            "private",
            "password",
        ),
        (
            "/api/auth/mfa/verify",
            {"mfa_token": "private-token", "code": "12345"},
            "12345",
            "code",
        ),
        (
            "/api/auth/register",
            {"username": "validation.test", "password": "  private-passphrase-2026  "},
            "  private-passphrase-2026  ",
            "password",
        ),
    ],
)
def test_rejected_auth_values_are_not_reflected(client, path, payload, private_value, field):
    response = client.post(path, json=payload)

    assert response.status_code == 422
    assert private_value not in response.text
    body = response.json()
    assert body["request_id"] == response.headers["x-request-id"]
    assert response.headers["cache-control"] == "no-store"
    assert any(error["loc"] == ["body", field] for error in body["detail"])
    assert all(set(error) == {"type", "loc", "msg"} for error in body["detail"])


def test_model_error_does_not_echo_the_entire_body(client):
    token = register_and_login(client, "validation.chat")
    private_title = "PRIVATE-CONVERSATION-TITLE"
    response = client.post(
        "/api/sessions",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "title": private_title,
            "security_mode": "secure",
            "data_classification": "highly_confidential",
        },
    )

    assert response.status_code == 422
    assert private_title not in response.text
    assert response.json()["detail"][0]["loc"] == ["body"]
    assert "Dữ liệu nhạy cảm" in response.json()["detail"][0]["msg"]


def test_rejected_chat_content_is_not_reflected(client):
    token = register_and_login(client, "validation.prompt")
    headers = {"Authorization": f"Bearer {token}"}
    session = client.post("/api/sessions", headers=headers, json={"title": "Validation"}).json()
    private_content = "PRIVATE-PROMPT-CONTENT-" + "x" * 16_000
    response = client.post(
        f"/api/sessions/{session['id']}/messages",
        headers=headers,
        json={"content": private_content},
    )

    assert response.status_code == 422
    assert "PRIVATE-PROMPT-CONTENT" not in response.text
    assert all(set(error) == {"type", "loc", "msg"} for error in response.json()["detail"])


@pytest.mark.parametrize(
    "path", ["/gradio_api/queue/join", "/gradio_api/api/login", "/gradio_api/run/login"]
)
def test_gradio_validation_errors_use_the_same_private_projection(client, path):
    private_value = "PRIVATE-RECOVERY-CODE-123456"
    response = client.post(
        path,
        json={"data": [], "fn_index": private_value, "session_hash": private_value},
    )

    assert response.status_code == 422
    assert private_value not in response.text
    assert response.json()["request_id"] == response.headers["x-request-id"]
    assert all(set(error) == {"type", "loc", "msg"} for error in response.json()["detail"])
