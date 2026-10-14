from __future__ import annotations

import json
from dataclasses import replace

import pytest

from src.app.config import Settings
from src.app.dlp import DataClass
from src.app.services import MAX_PROVIDER_RESPONSE_CHARACTERS, AIService, DLPPolicyViolation
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
    for name in ("AI_HISTORY_MESSAGES", "AI_MAX_OUTPUT_TOKENS", "GEMINI_MODEL"):
        monkeypatch.delenv(name, raising=False)
    configured = Settings.from_env()
    assert configured.ai_history_messages == 16
    assert configured.ai_max_output_tokens == 2048
    assert configured.gemini_model == "gemini-flash-lite-latest"


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


def test_search_requires_server_opt_in_before_loading_history_or_calling_provider(settings):
    service = AIService(settings)
    provider = RecordingProvider()
    service._client = provider

    def history():
        pytest.fail("Disabled search must not decrypt history.")

    with pytest.raises(PermissionError, match="chưa được"):
        service.generate("Public question", history, allow_external_ai=True,
                         data_class=DataClass.PUBLIC.value, use_web_search=True)
    assert provider.calls == []


@pytest.mark.parametrize("classification", [DataClass.INTERNAL, DataClass.CONFIDENTIAL,
                                            DataClass.HIGHLY_CONFIDENTIAL, DataClass.E2EE_PRIVATE])
def test_search_cannot_use_nonpublic_conversation_history(settings, classification):
    service = AIService(replace(settings, gemini_web_search_enabled=True))
    provider = RecordingProvider()
    service._client = provider

    def history():
        pytest.fail("Nonpublic search must not decrypt history.")

    with pytest.raises(PermissionError, match="Public"):
        service.generate("Question", history, allow_external_ai=True,
                         data_class=classification.value, confirmed=True, use_web_search=True)
    assert provider.calls == []


@pytest.mark.parametrize("in_history", [False, True])
def test_search_with_sensitive_prompt_or_history_is_blocked_before_provider(settings, in_history):
    service = AIService(replace(settings, gemini_web_search_enabled=True))
    provider = RecordingProvider()
    service._client = provider
    sensitive = "Contact student@example.com"
    current = "Public question" if in_history else sensitive
    history = [{"role": "user", "content": sensitive}] if in_history else []

    with pytest.raises(DLPPolicyViolation):
        service.generate(current, history, allow_external_ai=True,
                         data_class=DataClass.PUBLIC.value, use_web_search=True)
    assert provider.calls == []


def test_search_rejects_sensitive_grounded_output_without_redacting_or_returning_it(settings):
    service = AIService(replace(settings, gemini_web_search_enabled=True))
    service._client = RecordingProvider("Contact student@example.com")
    with pytest.raises(DLPPolicyViolation):
        service.generate("Public question", [], allow_external_ai=True,
                         data_class=DataClass.PUBLIC.value, use_web_search=True)


def test_search_flag_is_explicit_and_clean_grounded_text_is_not_modified(settings):
    response = "Ｗｉｄｅ text from a grounded result"
    service = AIService(replace(settings, gemini_web_search_enabled=True))
    provider = RecordingProvider(response)
    service._client = provider
    output, labels = service.generate("Public question", [], allow_external_ai=True,
                                      data_class=DataClass.PUBLIC.value, use_web_search=True)
    assert output == response and labels == []
    assert provider.calls[0][1]["use_web_search"] is True
    assert "chỉ được dùng Google Search" in provider.calls[0][1]["system_instruction"]
    service.generate("Ordinary question", [], allow_external_ai=True)
    assert "use_web_search" not in provider.calls[1][1]
