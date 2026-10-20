"""Chat send flow: system prompt, consent on first send and confidential confirmation.

The UI callbacks run against an in-memory fake API; nothing reaches a provider.
"""

from __future__ import annotations

import gradio as gr
import pytest

from src.app import gradio_ui
from src.app.config import Settings
from src.app.services import EXTERNAL_AI_CONSENT_REQUIRED_MESSAGE, AIService


def test_system_instruction_matches_safe_markdown_chat_view(tmp_path):
    captured = {}

    class Recorder:
        def generate(self, prompt, **kwargs):
            captured.update(kwargs)
            return "ok"

    service = AIService(Settings(environment="test", database_url=f"sqlite:///{tmp_path / 'p.db'}"))
    service._client = Recorder()
    service.generate("Xin chào", [], allow_external_ai=True)
    assert "Dùng Markdown" in captured["system_instruction"]
    assert "Không dùng HTML thô hoặc ảnh" in captured["system_instruction"]
    # Calculations: numbered steps, verified result, LaTeX the chat view typesets.
    assert "từng bước" in captured["system_instruction"]
    assert "kiểm tra lại kết quả" in captured["system_instruction"]
    assert "$...$" in captured["system_instruction"] and "$$...$$" in captured["system_instruction"]


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


def _send(demo, session_id, message):
    """Bước gửi sau begin_send: tin đang chờ và lịch sử cũ nằm trong State."""
    return _callback(demo, "send_pending")("token", session_id, {"message": message, "history": []})


class FakeApi:
    """Server semantics that matter here: consent first, then confidential confirmation."""

    def __init__(self, *, consent: bool, mode: str = "secure", reported_consent=None,
                 refuse=None):
        self.consent = consent
        # Consent ghi theo phiên bản chính sách cũ: /me vẫn báo True nhưng máy
        # chủ không chấp nhận khi gửi tới AI.
        self.reported_consent = consent if reported_consent is None else reported_consent
        self.mode = mode
        self.refuse = refuse
        self.sessions: list[dict] = []
        self.sent: list[dict] = []
        self.calls: list[tuple[str, str]] = []

    def __call__(self, _token, method, path, body=None, *, params=None):
        del params
        self.calls.append((method, path))
        if (method, path) == ("GET", "/api/auth/me"):
            return {"ai_data_consent": self.reported_consent}
        if (method, path) == ("PATCH", "/api/auth/ai-consent"):
            self.consent = self.reported_consent = body["ai_data_consent"]
            return {"ai_data_consent": self.consent}
        if (method, path) == ("POST", "/api/sessions"):
            session = {"id": f"s{len(self.sessions) + 1}", "title": body["title"],
                       "security_mode": self.mode}
            self.sessions.append(session)
            return session
        if (method, path) == ("GET", "/api/sessions/page"):
            return {"items": self.sessions, "total": len(self.sessions), "offset": 0,
                    "limit": 100, "has_more": False, "next_offset": None}
        if method == "GET" and path.endswith("/messages"):
            return []
        if method == "GET" and path.startswith("/api/sessions/"):
            return {"id": path.rsplit("/", 1)[-1], "title": "Conversation", "security_mode": self.mode}
        if method == "POST" and path.endswith("/messages"):
            if self.refuse:
                raise gr.Error(self.refuse)
            if not self.consent:
                raise gr.Error(EXTERNAL_AI_CONSENT_REQUIRED_MESSAGE)
            if self.mode == "confidential" and not body["confirm_external_ai"]:
                raise gr.Error("Nội dung mật cần xác nhận riêng trước khi gửi tới AI bên ngoài.")
            self.sent.append(body)
            return {"dlp_redacted": []}
        raise AssertionError(f"Unexpected API call {method} {path}")


def test_first_send_records_consent_in_the_auto_created_conversation(demo, monkeypatch):
    api = FakeApi(consent=False)
    monkeypatch.setattr(gradio_ui, "_api", api)

    outputs = _send(demo, None, "Xin chào")
    assert [session["id"] for session in api.sessions] == ["s1"]  # no orphan, no retry
    assert outputs[0]["value"] == "s1"  # the new conversation is now selected
    assert api.consent is True and len(api.sent) == 1
    assert outputs[3] == "" and outputs[4]["visible"] is False
    assert outputs[5] == gr.update(value=True)  # Account tab checkbox follows


def test_send_button_confirms_a_confidential_message_without_a_second_prompt(demo, monkeypatch):
    """Tapping Send is the per-message confirmation; the API still requires the flag."""
    api = FakeApi(consent=True, mode="confidential")
    monkeypatch.setattr(gradio_ui, "_api", api)
    outputs = _send(demo, "s9", "Kế hoạch nội bộ")
    assert api.sent == [{
        "content": "Kế hoạch nội bộ", "confirm_external_ai": True,
        "sanitize_external_ai": True,
    }]
    assert ("PATCH", "/api/auth/ai-consent") not in api.calls
    assert outputs[3] == "" and outputs[4]["visible"] is False and outputs[5] == gr.skip()


@pytest.mark.parametrize("reported_consent", [False, True])
def test_send_without_current_consent_needs_no_confirmation_button(
    demo, monkeypatch, reported_consent,
):
    """reported_consent=True: consent ghi theo phiên bản chính sách cũ.

    /me vẫn báo đã đồng ý nên nút "Đồng ý và gửi" cũ bỏ qua bước ghi consent và
    tin nhắn bị từ chối mãi. Gửi giờ luôn ghi lại consent khi máy chủ đòi.
    """
    api = FakeApi(consent=False, mode="confidential", reported_consent=reported_consent)
    monkeypatch.setattr(gradio_ui, "_api", api)
    outputs = _send(demo, "s9", "Kế hoạch nội bộ")
    assert api.consent is True
    assert api.sent == [{
        "content": "Kế hoạch nội bộ", "confirm_external_ai": True,
        "sanitize_external_ai": True,
    }]
    assert outputs[3] == "" and outputs[4]["visible"] is False
    assert not any(isinstance(item, gr.Button) and item.value == "Đồng ý và gửi"
                   for item in demo.blocks.values())


def test_other_refusals_are_not_retried_as_consent(demo, monkeypatch):
    api = FakeApi(consent=False, refuse="DLP đã chặn nội dung Highly confidential.")
    monkeypatch.setattr(gradio_ui, "_api", api)
    outputs = _send(demo, "s9", "Bí mật")
    assert api.calls.count(("POST", "/api/sessions/s9/messages")) == 1
    assert ("PATCH", "/api/auth/ai-consent") not in api.calls and api.consent is False
    assert outputs[3] == "Bí mật"  # the text returns to the composer
    assert outputs[2] == []  # and the optimistic bubble is removed
    assert "DLP đã chặn" in outputs[4]["value"] and outputs[5] == gr.skip()
