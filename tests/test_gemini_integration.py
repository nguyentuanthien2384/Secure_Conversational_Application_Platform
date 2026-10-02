"""Gemini provider integration: deadlines, retries, response parsing and UI consent.

No test here reaches Google. A local socket that never answers stands in for a
hung provider, and the UI callbacks run against an in-memory fake API.
"""

from __future__ import annotations

import socket
import time
from types import SimpleNamespace

import gradio as gr
import pytest

from src.app import gradio_ui
from src.app.config import Settings
from src.app.services import EXTERNAL_AI_CONSENT_REQUIRED_MESSAGE, AIService
from src.core.ai_core import gemini_ai
from src.core.ai_core.gemini_ai import GeminiClient


def _http_options(client: GeminiClient):
    return client.client._api_client._http_options


def test_client_sets_a_deadline_and_bounded_retry():
    options = _http_options(GeminiClient(api_key="unit-test-key", timeout_seconds=7, retry_attempts=2))
    assert options.timeout == 7000
    assert options.retry_options.attempts == 2
    assert options.retry_options.max_delay <= 4.0


def test_client_without_options_keeps_sdk_single_attempt():
    options = _http_options(GeminiClient(api_key="unit-test-key"))
    assert options.timeout is None and options.retry_options is None


@pytest.mark.parametrize(("kwargs", "message"), [
    ({"timeout_seconds": 0}, "timeout_seconds"),
    ({"retry_attempts": 0}, "retry_attempts"),
])
def test_client_rejects_invalid_limits(kwargs, message):
    with pytest.raises(ValueError, match=message):
        GeminiClient(api_key="unit-test-key", **kwargs)


def test_ai_service_applies_configured_provider_deadline(tmp_path):
    settings = Settings(
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'ai.db'}",
        google_genai_api_key="unit-test-key",
        gemini_timeout_seconds=9,
    )
    options = _http_options(AIService(settings)._client)
    assert options.timeout == 9000
    assert options.retry_options.attempts == 2


@pytest.mark.parametrize("value", ["4", "26", "slow"])
def test_provider_deadline_configuration_is_bounded(monkeypatch, value):
    monkeypatch.setattr("src.app.config.load_dotenv", lambda: None)
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("SECURITY_PROFILE", "standard")
    monkeypatch.setenv("KEY_PROVIDER", "local")
    monkeypatch.setenv("GEMINI_TIMEOUT_SECONDS", value)
    with pytest.raises(RuntimeError, match="GEMINI_TIMEOUT_SECONDS"):
        Settings.from_env()


def test_hung_provider_fails_within_the_deadline(monkeypatch):
    """Before the fix the SDK waited forever on a connection that never answers."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)  # accepts TCP handshakes, never sends an HTTP response
    port = listener.getsockname()[1]
    real_client = gemini_ai.genai.Client

    def local_client(*, api_key, http_options):
        http_options.base_url = f"http://127.0.0.1:{port}/"
        return real_client(api_key=api_key, http_options=http_options)

    monkeypatch.setattr(gemini_ai.genai, "Client", local_client)
    client = GeminiClient(api_key="unit-test-key", timeout_seconds=1, retry_attempts=1)
    started = time.monotonic()
    try:
        with pytest.raises(Exception) as caught:
            client.generate("ping")
    finally:
        listener.close()
    assert time.monotonic() - started < 10
    assert "timeout" in type(caught.value).__name__.lower()


@pytest.mark.parametrize("response", [
    SimpleNamespace(candidates=None),
    SimpleNamespace(candidates=[SimpleNamespace(content=None)]),
    SimpleNamespace(candidates=[SimpleNamespace(content=SimpleNamespace(parts=None))]),
    SimpleNamespace(candidates=[SimpleNamespace(content=SimpleNamespace(parts=[]))]),
])
def test_blocked_or_empty_candidates_raise_a_clear_runtime_error(response):
    client = GeminiClient(api_key="unit-test-key")
    client.client = SimpleNamespace(
        models=SimpleNamespace(generate_content=lambda **_kwargs: response)
    )
    with pytest.raises(RuntimeError):
        client.generate("ping")


def test_system_instruction_matches_the_plain_text_chat_view(tmp_path):
    captured = {}

    class Recorder:
        def generate(self, prompt, **kwargs):
            captured.update(kwargs)
            return "ok"

    service = AIService(Settings(environment="test", database_url=f"sqlite:///{tmp_path / 'p.db'}"))
    service._client = Recorder()
    service.generate("Xin chào", [], allow_external_ai=True)
    assert "văn bản thuần" in captured["system_instruction"]
    assert "**" in captured["system_instruction"]  # names the syntax to avoid


# ───────────────────────── UI consent / confirmation flow ─────────────────────────


@pytest.fixture(scope="module")
def demo():
    return gradio_ui.build_ui()


@pytest.fixture(autouse=True)
def quiet_notices(monkeypatch):
    monkeypatch.setattr(gr, "Info", lambda *args, **kwargs: None)
    monkeypatch.setattr(gr, "Warning", lambda *args, **kwargs: None)


def _callback(demo, name):
    return next(
        item.fn for item in demo.fns.values() if item.fn is not None and item.fn.__name__ == name
    )


class FakeApi:
    """Server semantics that matter here: consent first, then confidential confirmation."""

    def __init__(self, *, consent: bool, mode: str = "secure"):
        self.consent = consent
        self.mode = mode
        self.sessions: list[dict] = []
        self.sent: list[dict] = []

    def __call__(self, _token, method, path, body=None, *, params=None):
        del params
        if (method, path) == ("GET", "/api/auth/me"):
            return {"ai_data_consent": self.consent}
        if (method, path) == ("PATCH", "/api/auth/ai-consent"):
            self.consent = body["ai_data_consent"]
            return {}
        if (method, path) == ("POST", "/api/sessions"):
            session = {"id": f"s{len(self.sessions) + 1}", "title": body["title"],
                       "security_mode": self.mode}
            self.sessions.append(session)
            return session
        if (method, path) == ("GET", "/api/sessions"):
            return self.sessions
        if method == "GET" and path.endswith("/messages"):
            return []
        if method == "GET" and path.startswith("/api/sessions/"):
            return {"security_mode": self.mode}
        if method == "POST" and path.endswith("/messages"):
            if not self.consent:
                raise gr.Error(EXTERNAL_AI_CONSENT_REQUIRED_MESSAGE)
            if self.mode == "confidential" and not body["confirm_external_ai"]:
                raise gr.Error("Nội dung mật cần xác nhận riêng trước khi gửi tới AI bên ngoài.")
            self.sent.append(body)
            return {"dlp_redacted": []}
        raise AssertionError(f"Unexpected API call {method} {path}")


def test_consent_retry_reuses_the_auto_created_conversation(demo, monkeypatch):
    api = FakeApi(consent=False)
    monkeypatch.setattr(gradio_ui, "_api", api)
    send = _callback(demo, "send_message")
    resend = _callback(demo, "consent_and_resend")

    outputs = send("token", None, "Xin chào")
    assert [session["id"] for session in api.sessions] == ["s1"]
    assert outputs[0]["value"] == "s1"  # the new conversation is now selected
    assert outputs[4]["value"] == gradio_ui.CONSENT_NOTICE

    resend("token", outputs[0]["value"], "Xin chào")
    assert [session["id"] for session in api.sessions] == ["s1"]  # no orphan
    assert len(api.sent) == 1


def test_consent_click_does_not_also_confirm_confidential_content(demo, monkeypatch):
    api = FakeApi(consent=False, mode="confidential")
    monkeypatch.setattr(gradio_ui, "_api", api)
    send = _callback(demo, "send_message")
    resend = _callback(demo, "consent_and_resend")

    assert send("token", "s9", "Kế hoạch nội bộ")[4]["value"] == gradio_ui.CONSENT_NOTICE
    first = resend("token", "s9", "Kế hoạch nội bộ")
    assert api.consent is True
    assert api.sent == []  # consent alone must not send confidential content
    assert first[4]["value"] == gradio_ui.CONFIDENTIAL_CONFIRM_NOTICE
    assert first[5]["visible"] is True

    resend("token", "s9", "Kế hoạch nội bộ")
    assert api.sent == [{"content": "Kế hoạch nội bộ", "confirm_external_ai": True}]


def test_secure_conversation_sends_after_a_single_consent_click(demo, monkeypatch):
    api = FakeApi(consent=False)
    monkeypatch.setattr(gradio_ui, "_api", api)
    _callback(demo, "consent_and_resend")("token", "s1", "Câu hỏi")
    assert api.sent == [{"content": "Câu hỏi", "confirm_external_ai": False}]
