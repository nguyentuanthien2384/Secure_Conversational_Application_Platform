"""Claude provider integration: configuration isolation, request shape and parsing.

No test here reaches the gateway. A mock HTTP transport answers every request.
"""

from __future__ import annotations

import json
from dataclasses import replace

import httpx2
import pytest

from src.app.config import Settings
from src.app.dlp import DLPScanner
from src.app.services import AIService
from src.core.ai_core.claude_ai import ClaudeClient


def _message(*, text="Xin chào", stop_reason="end_turn", model="claude-opus-5-5"):
    content = [{"type": "thinking", "thinking": "", "signature": "sig"}]
    if text is not None:
        content.append({"type": "text", "text": text})
    return {
        "id": "msg_unit", "type": "message", "role": "assistant", "model": model,
        "content": content, "stop_reason": stop_reason, "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }


def _mocked(client: ClaudeClient, body: dict) -> list[httpx2.Request]:
    requests: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return httpx2.Response(200, json=body)

    client.client = client.client.with_options(
        http_client=httpx2.Client(transport=httpx2.MockTransport(handler))
    )
    return requests


def test_client_ignores_ambient_claude_code_configuration(monkeypatch):
    # Claude Code/VSCode keep their own gateway settings in ANTHROPIC_*;
    # the application must use only the values it was given.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ambient-api-key")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "ambient-auth-token")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://ambient.invalid")
    monkeypatch.delenv("CLAUDE_BASE_URL", raising=False)
    client = ClaudeClient(api_key="sk-unit-test", timeout_seconds=7, retry_attempts=2).client
    assert str(client.base_url).rstrip("/") == "https://1gw.gwai.cloud"
    assert client.auth_token == "sk-unit-test"
    assert client.api_key is None
    assert client.timeout == 7.0
    assert client.max_retries == 1


@pytest.mark.parametrize(("kwargs", "message"), [
    ({"api_key": " "}, "CLAUDE_API_KEY"),
    ({"timeout_seconds": 0}, "timeout_seconds"),
    ({"retry_attempts": 0}, "retry_attempts"),
    ({"max_output_tokens": 0}, "max_output_tokens"),
    ({"effort": "extreme"}, "effort"),
])
def test_client_rejects_invalid_options(kwargs, message):
    with pytest.raises(ValueError, match=message):
        ClaudeClient(**{"api_key": "sk-unit-test", **kwargs})


def test_generate_sends_bearer_key_system_prompt_effort_and_token_cap():
    client = ClaudeClient(
        api_key="sk-unit-test", base_url="https://gateway.example",
        max_output_tokens=512, effort="low",
    )
    requests = _mocked(client, _message())

    assert client.generate("Câu hỏi", system_instruction="Chỉ thị") == "Xin chào"

    request = requests[0]
    assert str(request.url) == "https://gateway.example/v1/messages"
    assert request.headers["authorization"] == "Bearer sk-unit-test"
    assert "x-api-key" not in request.headers
    body = json.loads(request.content)
    assert body["model"] == "claude-opus-5-5"
    assert body["max_tokens"] == 512
    assert body["system"] == "Chỉ thị"
    assert body["output_config"] == {"effort": "low"}
    assert body["messages"] == [{"role": "user", "content": "Câu hỏi"}]
    assert "temperature" not in body and "thinking" not in body


@pytest.mark.parametrize("model", ["claude-haiku-4-5", "claude-sonnet-4-5"])
def test_effort_is_omitted_for_models_that_reject_it(model):
    client = ClaudeClient(api_key="sk-unit-test", model=model, effort="low")
    requests = _mocked(client, _message(model=model))
    client.generate("Câu hỏi")
    assert "output_config" not in json.loads(requests[0].content)


@pytest.mark.parametrize("stop_reason", ["refusal", "pause_turn", "tool_use"])
def test_incomplete_responses_raise(stop_reason):
    client = ClaudeClient(api_key="sk-unit-test")
    _mocked(client, _message(stop_reason=stop_reason))
    with pytest.raises(RuntimeError, match="không hoàn tất"):
        client.generate("Câu hỏi")


def test_response_without_text_raises():
    client = ClaudeClient(api_key="sk-unit-test")
    _mocked(client, _message(text=None))
    with pytest.raises(RuntimeError, match="text"):
        client.generate("Câu hỏi")


def test_truncated_response_is_labelled():
    client = ClaudeClient(api_key="sk-unit-test")
    _mocked(client, _message(text="Phần đầu", stop_reason="max_tokens"))
    reply = client.generate("Câu hỏi")
    assert reply.startswith("Phần đầu") and "giới hạn token" in reply


def _env(monkeypatch, **values):
    monkeypatch.setattr("src.app.config.load_dotenv", lambda: None)
    for name in ("CLAUDE_API_KEY", "CLAUDE_API_KEY_FILE", "CLAUDE_BASE_URL", "CLAUDE_MODEL",
                 "CLAUDE_EFFORT_LEVEL", "CLAUDE_TIMEOUT_SECONDS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("SECURITY_PROFILE", "standard")
    monkeypatch.setenv("KEY_PROVIDER", "local")
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_settings_load_claude_configuration(monkeypatch, tmp_path):
    key_file = tmp_path / "claude_api_key"
    key_file.write_text("sk-from-file\n", encoding="utf-8")
    _env(monkeypatch, CLAUDE_API_KEY_FILE=str(key_file), CLAUDE_MODEL="claude-sonnet-5",
         CLAUDE_EFFORT_LEVEL="Medium", CLAUDE_TIMEOUT_SECONDS="15")
    configured = Settings.from_env()
    assert configured.claude_api_key == "sk-from-file"
    assert configured.claude_base_url == "https://1gw.gwai.cloud"
    assert configured.claude_model == "claude-sonnet-5"
    assert configured.claude_effort == "medium"
    assert configured.claude_timeout_seconds == 15
    assert "sk-from-file" not in repr(configured)


def test_settings_defaults_without_claude_variables(monkeypatch):
    _env(monkeypatch)
    configured = Settings.from_env()
    assert configured.claude_api_key == ""
    assert configured.claude_model == "claude-opus-5-5"
    assert configured.claude_effort == "low"
    assert configured.claude_timeout_seconds == 25


@pytest.mark.parametrize(("name", "value"), [
    ("CLAUDE_BASE_URL", "http://1gw.gwai.cloud"),
    ("CLAUDE_BASE_URL", "https://user:secret@1gw.gwai.cloud"),
    ("CLAUDE_EFFORT_LEVEL", "extreme"),
    ("CLAUDE_TIMEOUT_SECONDS", "26"),
])
def test_settings_reject_unsafe_claude_values(monkeypatch, name, value):
    _env(monkeypatch, **{name: value})
    with pytest.raises(RuntimeError, match=name):
        Settings.from_env()


def test_ai_service_uses_claude_as_its_only_provider(tmp_path):
    base = Settings(environment="test", database_url=f"sqlite:///{tmp_path / 'ai.db'}")
    assert AIService(base)._client is None  # no key: offline demo AI or 503

    service = AIService(replace(base, claude_api_key="sk-unit-test", claude_timeout_seconds=9))
    assert isinstance(service._client, ClaudeClient)
    assert service.provider_model == "claude-opus-5-5"
    assert service._client.client.timeout == 9.0
    assert service._client.client.max_retries == 1
    assert service._client.max_output_tokens == base.ai_max_output_tokens


@pytest.mark.parametrize("text", [
    "CLAUDE_API_KEY=abcdef123456",
    "anthropic api key: abcdef123456",
    "ANTHROPIC_AUTH_TOKEN=abcdef123456",
    "claude_auth_token: abcdef123456",
])
def test_claude_key_assignments_are_detected(text):
    assert DLPScanner().scan(text)


def test_claude_client_blank_model_falls_back_to_default():
    client = ClaudeClient(api_key="sk-test", model="   ")
    assert client.model == "claude-opus-5-5"

