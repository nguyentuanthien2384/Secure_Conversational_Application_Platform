"""Explicitly sanitized file sends preserve useful context and never leak secrets."""

from __future__ import annotations

import base64
import json
from dataclasses import replace

import pytest
from sqlalchemy import select

from src.app import dlp
from src.app.dlp import DLPAction
from src.app.models import AuditEvent, ChatSession, SecureMessage
from src.app.services import AIService, DLPPolicyViolation


class RecordingProvider:
    def __init__(self, response="Kỹ năng chính: Python và SQL."):
        self.response = response
        self.calls = []

    def generate(self, prompt, **kwargs):
        self.calls.append((prompt, kwargs))
        return self.response


def _payload(provider, index=-1):
    return json.loads(provider.calls[index][0].split("UNTRUSTED_USER_DATA_JSON:\n", 1)[1])


def _install_provider(app, settings, response="Kỹ năng chính: Python và SQL."):
    service = AIService(replace(settings, dlp_custom_terms=("DU_AN_NOI_BO_SAO_DO",)))
    provider = RecordingProvider(response)
    service._client = provider
    app.state.chat_service.ai = service
    return provider


def _session(client, headers, *, consent=True, mode="confidential"):
    if consent:
        accepted = client.patch(
            "/api/auth/ai-consent", headers=headers, json={"ai_data_consent": True}
        )
        assert accepted.status_code == 200
    created = client.post(
        "/api/sessions",
        headers=headers,
        json={
            "title": "Phân tích CV",
            "security_mode": mode,
            "data_classification": "highly_confidential",
        },
    )
    assert created.status_code == 201, created.text
    return created.json()["id"]


def test_sanitized_highly_confidential_file_and_followup_keep_useful_context(
    client, app, settings, auth_headers,
):
    """Exercise the real HTTP -> encrypted history -> provider boundary twice."""
    email = "ungvien.synthetic@example.com"
    phone = "0912345678"
    citizen_id = "001203004567"
    tax_id = "1234567890"
    password = "SyntheticSecretForTest42"
    custom_term = "DU_AN_NOI_BO_SAO_DO"
    secrets = (email, phone, citizen_id, tax_id, password, custom_term)
    provider = _install_provider(
        app, settings, f"Kỹ năng: Python và SQL. Liên hệ {email}; password: {password}"
    )
    session_id = _session(client, auth_headers)
    filename = f"CV-{phone}.pdf"
    question = f"Tóm tắt kỹ năng trong CV; email của tôi: {email}"
    file_content = (
        "Kỹ năng: Python, SQL, quản lý dự án.\n"
        "Kinh nghiệm: 3 năm phát triển ứng dụng.\n"
        f"Email: {email}\nĐiện thoại: {phone}\n"
        f"CCCD: {citizen_id}\nMã số thuế: {tax_id}\n"
        f"password: {password}\nDự án: {custom_term}"
    )
    sent = client.post(
        f"/api/sessions/{session_id}/messages",
        headers=auth_headers,
        json={
            "content": question,
            "confirm_external_ai": True,
            "sanitize_external_ai": True,
            "file_name": filename,
            "file_content": file_content,
        },
    )
    assert sent.status_code == 201, sent.text
    assert len(provider.calls) == 1
    outgoing = _payload(provider)
    attached = outgoing["attached_file"]
    assert "Python, SQL, quản lý dự án" in attached["file_content"]
    assert "3 năm phát triển ứng dụng" in attached["file_content"]
    assert "Tóm tắt kỹ năng" in outgoing["current_user_message"]
    assert "[REDACTED:EMAIL]" in outgoing["current_user_message"]
    assert "[REDACTED:PHONE]" in attached["file_name"]
    for marker in ("EMAIL", "PHONE", "CCCD", "TAX_ID", "SECRET", "CUSTOM_DICTIONARY"):
        assert f"[REDACTED:{marker}]" in attached["file_content"]
    for secret in secrets:
        assert secret not in provider.calls[0][0]
        assert secret not in sent.json()["content"]
    assert "Python và SQL" in sent.json()["content"]
    assert {"email", "số điện thoại", "CCCD", "mã số thuế", "mật khẩu", "dữ liệu nội bộ"} <= set(
        sent.json()["dlp_redacted"]
    )

    followup = client.post(
        f"/api/sessions/{session_id}/messages",
        headers=auth_headers,
        json={
            "content": "Từ kinh nghiệm trên, hãy gợi ý công việc phù hợp.",
            "confirm_external_ai": True,
            "sanitize_external_ai": True,
        },
    )
    assert followup.status_code == 201, followup.text
    assert len(provider.calls) == 2
    next_payload = _payload(provider)
    assert "attached_file" not in next_payload
    assert [item["role"] for item in next_payload["conversation_history"]] == ["user", "assistant"]
    assert "3 năm phát triển ứng dụng" in next_payload["conversation_history"][0]["content"]
    for secret in secrets:
        assert secret not in provider.calls[1][0]

    # Authorized reads retain the original attachment; only the provider copy is redacted.
    messages = client.get(
        f"/api/sessions/{session_id}/messages", headers=auth_headers
    )
    assert messages.status_code == 200
    original = messages.json()[0]["content"]
    assert filename in original and file_content in original and question in original
    with app.state.database.session_factory() as db:
        conversation = db.get(ChatSession, session_id)
        assert conversation.security_mode == "confidential"
        assert conversation.data_classification == "highly_confidential"
        rows = db.scalars(select(SecureMessage).where(SecureMessage.session_id == session_id)).all()
        assert len(rows) == 4
        for row in rows:
            assert all(secret not in row.ciphertext for secret in secrets)
        audit_rows = db.scalars(select(AuditEvent)).all()
        audit_text = "\n".join(event.details_json for event in audit_rows)
        assert all(secret not in audit_text for secret in secrets)
        send_events = [event for event in audit_rows if event.event_type == "chat.message.send"]
        assert len(send_events) == 2
        assert all(json.loads(event.details_json)["sanitize_external_ai"] for event in send_events)
        assert any(event.event_type == "dlp.redacted" for event in audit_rows)


@pytest.mark.parametrize(
    ("case", "expected_status", "expected_code"),
    [
        ("default_api", 422, "dlp_block"),
        ("unconfirmed", 409, "dlp_confirm"),
        ("no_consent", 403, None),
        ("e2ee", 403, None),
    ],
)
def test_sanitized_send_preserves_api_consent_confirmation_and_e2ee_guards(
    client, app, settings, auth_headers, case, expected_status, expected_code,
):
    provider = _install_provider(app, settings)
    session_id = _session(
        client, auth_headers, consent=case != "no_consent",
        mode="private_e2ee" if case == "e2ee" else "confidential",
    )
    body = {
        "content": "Tóm tắt kỹ năng.",
        "confirm_external_ai": case != "unconfirmed",
        "file_name": "cv.txt",
        "file_content": "Kỹ năng Python. CCCD: 001203004567",
    }
    if case != "default_api":
        body["sanitize_external_ai"] = True
    result = client.post(
        f"/api/sessions/{session_id}/messages", headers=auth_headers, json=body
    )
    assert result.status_code == expected_status, result.text
    if expected_code is not None:
        assert result.json()["detail"]["code"] == expected_code
    assert not provider.calls
    with app.state.database.session_factory() as db:
        assert not db.scalars(
            select(SecureMessage).where(SecureMessage.session_id == session_id)
        ).all()


@pytest.mark.parametrize("source", ["current", "attachment", "history"])
def test_sanitized_send_redacts_encoded_personal_identifiers(settings, source):
    service = AIService(settings)
    provider = RecordingProvider()
    service._client = provider
    raw = "CCCD: 001203004567; Mã số thuế: 1234567890; mail: synthetic@example.com"
    encoded = base64.b64encode(raw.encode()).decode()
    content = f"Kỹ năng Python. Dữ liệu: {encoded}"
    service.generate(
        content if source == "current" else "Tóm tắt kỹ năng",
        [{"role": "user", "content": content}] if source == "history" else [],
        allow_external_ai=True,
        data_class="highly_confidential",
        confirmed=True,
        sanitize_external_ai=True,
        **({"file_name": "cv.txt", "file_content": content} if source == "attachment" else {}),
    )
    assert len(provider.calls) == 1
    prompt = provider.calls[0][0]
    assert encoded not in prompt and "001203004567" not in prompt
    assert "1234567890" not in prompt and "synthetic@example.com" not in prompt
    assert "Kỹ năng Python" in prompt and "[REDACTED:" in prompt


@pytest.mark.parametrize("source", ["current", "file_name", "attachment", "history"])
def test_sanitized_send_fails_closed_when_any_source_exceeds_inspection_limit(
    settings, monkeypatch, source,
):
    monkeypatch.setattr(dlp, "MAX_SCAN_CHARACTERS", 50)
    service = AIService(settings)
    provider = RecordingProvider()
    service._client = provider
    oversized = "x" * 51
    kwargs = {}
    if source in {"file_name", "attachment"}:
        kwargs = {
            "file_name": oversized + ".txt" if source == "file_name" else "cv.txt",
            "file_content": oversized if source == "attachment" else "Python",
        }
    with pytest.raises(DLPPolicyViolation) as error:
        service.generate(
            oversized if source == "current" else "Tóm tắt",
            [{"role": "user", "content": oversized}] if source == "history" else [],
            allow_external_ai=True,
            data_class="highly_confidential",
            confirmed=True,
            sanitize_external_ai=True,
            **kwargs,
        )
    assert error.value.action is DLPAction.BLOCK
    assert "dữ liệu vượt giới hạn kiểm tra" in error.value.categories
    assert oversized not in str(error.value)
    assert not provider.calls
