"""Stateless search authorization, quotas and persistence without provider traffic."""

from dataclasses import replace

import pytest

from src.app.models import AuditEvent
from src.core.ai_core.gemini_ai import GroundedAnswer
from tests.conftest import register_and_login

WIDGET = '<a href="https://www.google.com/search?q=public+fact">public fact</a>'


class SearchProvider:
    def __init__(self, response=None):
        self.calls = []
        self.response = response if response is not None else GroundedAnswer("A public fact.", WIDGET)

    def generate(self, prompt, **kwargs):
        self.calls.append((prompt, kwargs))
        return self.response


def setup_search(client, app, *, classification="public", consent=True, enabled=True):
    provider = SearchProvider()
    app.state.chat_service.ai._client = provider
    app.state.chat_service.ai.settings = replace(
        app.state.chat_service.ai.settings, gemini_web_search_enabled=enabled,
    )
    headers = {"Authorization": f"Bearer {register_and_login(client, 'search.owner')}"}
    if consent:
        assert client.patch("/api/auth/ai-consent", headers=headers,
                            json={"ai_data_consent": True}).status_code == 200
    created = client.post("/api/sessions", headers=headers, json={
        "title": "Public search", "data_classification": classification,
        "security_mode": ("private_e2ee" if classification == "e2ee_private" else
                          "confidential" if classification in {"confidential", "highly_confidential"}
                          else "secure"),
    })
    assert created.status_code == 201
    return headers, created.json()["id"], provider


def test_search_is_stateless_no_history_decryption_or_prompt_result_in_audit(client, app, monkeypatch):
    headers, sid, provider = setup_search(client, app)

    def history(*_args, **_kwargs):
        pytest.fail("Stateless search must not decrypt chat history")

    monkeypatch.setattr(app.state.chat_service, "recent_messages", history)
    query = "Synthetic unique public question"
    result = client.post(f"/api/sessions/{sid}/web-search", headers=headers,
                         json={"content": query})
    assert result.status_code == 200, result.text
    assert result.headers["cache-control"] == "no-store"
    assert result.json() == {"content": "A public fact.", "search_suggestions_html": WIDGET}
    assert provider.calls[0][1]["use_web_search"] is True
    assert '"conversation_history":[]' in provider.calls[0][0]
    assert client.get(f"/api/sessions/{sid}/messages", headers=headers).json() == []
    from sqlalchemy import select

    with app.state.database.session_factory() as db:
        audits = db.scalars(select(AuditEvent)).all()
        serialized = " ".join(item.details_json for item in audits)
        assert query not in serialized and WIDGET not in serialized and "A public fact" not in serialized
        assert any(item.event_type == "chat.web_search" and item.outcome == "success" for item in audits)


@pytest.mark.parametrize("classification,consent,enabled", [
    ("public", False, True), ("public", True, False),
    ("internal", True, True), ("confidential", True, True),
    ("highly_confidential", True, True), ("e2ee_private", True, True),
])
def test_policy_blocks_search_before_any_provider_call(client, app, classification, consent, enabled):
    headers, sid, provider = setup_search(
        client, app, classification=classification, consent=consent, enabled=enabled,
    )
    result = client.post(f"/api/sessions/{sid}/web-search", headers=headers,
                         json={"content": "A public question"})
    assert result.status_code == 403, result.text
    assert provider.calls == []


def test_search_requires_login_and_session_ownership(client, app):
    headers, sid, provider = setup_search(client, app)
    path = f"/api/sessions/{sid}/web-search"
    assert client.post(path, json={"content": "Question"}).status_code == 401
    other = {"Authorization": f"Bearer {register_and_login(client, 'search.other')}"}
    assert client.post(path, headers=other, json={"content": "Question"}).status_code in {403, 404}
    assert provider.calls == []


def test_ordinary_chat_cannot_store_grounded_results_by_forged_flag(client, app):
    headers, sid, provider = setup_search(client, app)
    result = client.post(f"/api/sessions/{sid}/messages", headers=headers,
                         json={"content": "Question", "use_web_search": True})
    assert result.status_code == 400
    assert provider.calls == []
    assert client.get(f"/api/sessions/{sid}/messages", headers=headers).json() == []


def test_search_and_chat_share_user_rate_limit(client, app):
    headers, sid, provider = setup_search(client, app)
    for _ in range(20):
        assert client.post(f"/api/sessions/{sid}/web-search", headers=headers,
                           json={"content": "Public question"}).status_code == 200
    blocked = client.post(f"/api/sessions/{sid}/messages", headers=headers,
                          json={"content": "Ordinary question"})
    assert blocked.status_code == 429
    assert "retry-after" in blocked.headers and len(provider.calls) == 20


@pytest.mark.parametrize("response", [
    GroundedAnswer("Sensitive contact user@example.com", WIDGET),
    GroundedAnswer("Public fact", '<a href="https://www.google.com/search?q=user@example.com">contact</a>'),
    GroundedAnswer("Public fact", '<script>alert(1)</script>' + WIDGET),
])
def test_sensitive_or_unsafe_search_output_is_withheld_and_not_stored(client, app, response):
    headers, sid, provider = setup_search(client, app)
    provider.response = response
    result = client.post(f"/api/sessions/{sid}/web-search", headers=headers,
                         json={"content": "Public question"})
    assert result.status_code in {422, 503}
    assert "user@example.com" not in result.text and "<script" not in result.text
    assert client.get(f"/api/sessions/{sid}/messages", headers=headers).json() == []


def test_sensitive_search_query_is_blocked_before_provider(client, app):
    headers, sid, provider = setup_search(client, app)
    result = client.post(f"/api/sessions/{sid}/web-search", headers=headers,
                         json={"content": "Find user@example.com"})
    assert result.status_code == 422
    assert provider.calls == []
