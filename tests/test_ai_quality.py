from __future__ import annotations

import json
from dataclasses import replace

import pytest

from src.app.config import Settings
from src.app.services import MAX_PROVIDER_RESPONSE_CHARACTERS, AIService
from tests.conftest import register_and_login


class RecordingProvider:
    def __init__(self, response="Safe answer"):
        self.calls = []
        self.response = response

    def generate(self, prompt, **kwargs):
        self.calls.append((prompt, kwargs))
        return self.response


@pytest.mark.parametrize("value", ["1", "41", "unlimited"])
def test_history_budget_rejects_unbounded_configuration(monkeypatch, value):
    monkeypatch.setattr("src.app.config.load_dotenv", lambda: None)
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("SECURITY_PROFILE", "standard")
    monkeypatch.setenv("KEY_PROVIDER", "local")
    monkeypatch.setenv("AI_HISTORY_MESSAGES", value)
    with pytest.raises(RuntimeError, match="AI_HISTORY_MESSAGES"):
        Settings.from_env()


def test_balanced_ai_defaults_are_loaded_without_model_change(monkeypatch):
    monkeypatch.setattr("src.app.config.load_dotenv", lambda: None)
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("SECURITY_PROFILE", "standard")
    monkeypatch.setenv("KEY_PROVIDER", "local")
    for name in ("AI_HISTORY_MESSAGES", "AI_MAX_OUTPUT_TOKENS", "CLAUDE_MODEL"):
        monkeypatch.delenv(name, raising=False)
    configured = Settings.from_env()
    assert configured.ai_history_messages == 16
    assert configured.ai_max_output_tokens == 2048
    assert configured.claude_model == "claude-opus-5-5"


def test_configured_history_preserves_order_and_redacts_every_sent_item(settings):
    service = AIService(replace(settings, ai_history_messages=12))
    provider = RecordingProvider()
    service._client = provider
    history = [{"role": "user" if i % 2 == 0 else "assistant",
                "content": f"Message {i}: user{i}@example.com"} for i in range(20)]

    service.generate("Question", history, allow_external_ai=True)

    prompt, kwargs = provider.calls[0]
    payload = json.loads(prompt.split("UNTRUSTED_USER_DATA_JSON:\n", 1)[1])
    sent = payload["conversation_history"]
    assert len(sent) == 12
    assert [item["content"].split(":", 1)[0] for item in sent] == [
        f"Message {i}" for i in range(8, 20)
    ]
    assert "@example.com" not in prompt
    assert kwargs["temperature"] is None


def test_api_history_loader_uses_same_configured_budget_after_consent(client, app, monkeypatch):
    service = app.state.chat_service
    service.ai.settings = replace(service.ai.settings, ai_history_messages=6)
    service.ai._client = RecordingProvider()
    observed = []

    def recent_messages(_db, _session, *, limit, since):
        observed.append((limit, since))
        return []

    monkeypatch.setattr(service, "recent_messages", recent_messages)
    headers = {"Authorization": f"Bearer {register_and_login(client, 'ai.quality.context')}"}
    consent = client.patch("/api/auth/ai-consent", headers=headers,
                           json={"ai_data_consent": True})
    assert consent.status_code == 200
    session_id = client.post("/api/sessions", headers=headers,
                             json={"title": "Quality context"}).json()["id"]
    sent = client.post(f"/api/sessions/{session_id}/messages", headers=headers,
                      json={"content": "Question"})
    assert sent.status_code == 201
    assert len(observed) == 1 and observed[0][0] == 6
    assert observed[0][1] is not None


def test_long_safe_answer_is_preserved_after_output_scan(settings):
    expected = "Useful explanation. " * 600
    assert 8000 < len(expected) < MAX_PROVIDER_RESPONSE_CHARACTERS
    service = AIService(settings)
    service._client = RecordingProvider(expected)
    response, labels = service.generate("Explain", [], allow_external_ai=True)
    assert response == expected
    assert labels == []


def test_redaction_expansion_has_explicit_bounded_display_notice(settings):
    provider_response = "a@b.vn " * 2000
    assert len(provider_response) < MAX_PROVIDER_RESPONSE_CHARACTERS
    service = AIService(settings)
    service._client = RecordingProvider(provider_response)
    response, labels = service.generate("Explain", [], allow_external_ai=True)
    assert "@b.vn" not in response
    assert "email" in labels
    assert len(response) <= MAX_PROVIDER_RESPONSE_CHARACTERS
    assert response.endswith("[Phản hồi vượt giới hạn hiển thị; hãy yêu cầu tiếp tục phần còn lại.]")


def test_system_instruction_requires_honesty_about_uncertainty_and_sources(settings):
    service = AIService(settings)
    provider = RecordingProvider()
    service._client = provider
    service.generate("Question", [], allow_external_ai=True)
    instruction = provider.calls[0][1]["system_instruction"]
    assert "nếu không chắc" in instruction
    assert "không tuyên bố" in instruction
    assert "bịa nguồn" in instruction
    assert "Dùng Markdown" in instruction
