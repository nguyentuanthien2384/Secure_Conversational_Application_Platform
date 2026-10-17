"""Policy renewal gates provider egress and starts a new history boundary."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from src.app.models import AuditEvent, SecureMessage, User, utcnow
from src.app.services import EXTERNAL_AI_CONSENT_REQUIRED_MESSAGE
from tests.conftest import register_and_login


class RecordingProvider:
    def __init__(self):
        self.payloads = []

    def generate(self, prompt, **_kwargs):
        payload = prompt.split("UNTRUSTED_USER_DATA_JSON:\n", 1)[1]
        self.payloads.append(json.loads(payload))
        return "A safe answer."


@pytest.mark.parametrize("mode", ["secure", "confidential"])
def test_old_consent_cannot_send_current_or_history_until_explicit_policy_renewal(
    client, app, settings, monkeypatch, mode,
):
    assert settings.ai_consent_version == "2026-10"
    token = register_and_login(client, f"consent.revision.{mode}")
    headers = {"Authorization": f"Bearer {token}"}
    created = client.post("/api/sessions", headers=headers, json={
        "title": "Consent revision", "security_mode": mode,
        "data_classification": "confidential" if mode == "confidential" else "internal",
    })
    assert created.status_code == 201, created.text
    session_id = created.json()["id"]
    path = f"/api/sessions/{session_id}/messages"
    # Build real encrypted history offline, before installing the fake external
    # provider. This is the account state retained across a policy revision.
    old_history = "PRIVATE_HISTORY_FROM_PREVIOUS_POLICY"
    seeded = client.post(path, headers=headers, json={"content": old_history})
    assert seeded.status_code == 201, seeded.text
    old_consent_at = utcnow() - timedelta(days=1)
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == f"consent.revision.{mode}"))
        user.ai_data_consent = True
        user.ai_consent_version = "2026-09"
        user.ai_consent_at = old_consent_at
        user_id = user.id
        db.commit()

    provider = RecordingProvider()
    service = app.state.chat_service
    monkeypatch.setattr(service.ai, "_client", provider)
    history_reads = []
    real_history = service.recent_messages

    def observed_history(*args, **kwargs):
        history_reads.append(kwargs)
        return real_history(*args, **kwargs)

    monkeypatch.setattr(service, "recent_messages", observed_history)
    current = "Current message after revised consent"
    blocked = client.post(path, headers=headers, json={
        "content": current, "confirm_external_ai": True,
    })
    assert blocked.status_code == 403, blocked.text
    assert blocked.json()["detail"] == EXTERNAL_AI_CONSENT_REQUIRED_MESSAGE
    assert not provider.payloads and not history_reads
    with app.state.database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(SecureMessage).where(
            SecureMessage.session_id == session_id,
        )) == 2
        user = db.get(User, user_id)
        assert user.ai_data_consent and user.ai_consent_version == "2026-09"

    # Existing true consent is insufficient: an explicit action records the new
    # version and timestamp, so earlier history is not silently grandfathered.
    renewed = client.patch("/api/auth/ai-consent", headers=headers,
                           json={"ai_data_consent": True})
    assert renewed.status_code == 200, renewed.text
    assert renewed.json()["ai_consent_version"] == "2026-10"
    assert renewed.json()["ai_consent_at"] != old_consent_at.isoformat()
    sent = client.post(path, headers=headers, json={
        "content": current, "confirm_external_ai": True,
    })
    assert sent.status_code == 201, sent.text
    assert provider.payloads == [{"conversation_history": [], "current_user_message": current}]
    assert len(history_reads) == 1

    follow_up = client.post(path, headers=headers, json={
        "content": "Continue the new discussion", "confirm_external_ai": True,
    })
    assert follow_up.status_code == 201, follow_up.text
    assert provider.payloads[-1]["conversation_history"] == [
        {"role": "user", "content": current},
        {"role": "assistant", "content": "A safe answer."},
    ]
    assert old_history not in json.dumps(provider.payloads)
    with app.state.database.session_factory() as db:
        event = db.scalar(select(AuditEvent).where(
            AuditEvent.actor_id == user_id, AuditEvent.event_type == "privacy.ai_consent",
        ).order_by(AuditEvent.id.desc()))
        assert json.loads(event.details_json) == {"consented": True, "policy_version": "2026-10"}
