from __future__ import annotations

import gradio as gr
import pytest
from pydantic import ValidationError

from src.app import gradio_ui
from src.app.schemas import UNSAFE_BIDI_CONTROLS, MessageSend, SessionCreate, SessionUpdate


def test_untrusted_chat_history_is_escaped_at_the_display_boundary(monkeypatch):
    malicious = (
        '<img src="https://tracker.example/pixel" onerror="alert(1)"> '
        "![beacon](https://tracker.example/pixel) "
        "[Đăng nhập](https://phishing.example/)"
    )

    def fake_api(_token, _method, path, _body=None, *, params=None):
        del params
        if path == "/api/sessions/session-1":
            return {"security_mode": "secure"}
        if path == "/api/sessions/session-1/messages":
            return [{"role": "assistant", "content": malicious}]
        raise AssertionError(f"Unexpected API path: {path}")

    monkeypatch.setattr(gradio_ui, "_api", fake_api)
    history = gradio_ui._chat_history("token", "session-1")

    rendered = history[0]["content"]
    assert "<img" not in rendered
    assert "&lt;img" in rendered
    # Markdown remains in the value only as inert text; the Chatbot below has
    # rich rendering disabled explicitly.
    assert "![beacon](https://tracker.example/pixel)" in rendered
    assert "[Đăng nhập](https://phishing.example/)" in rendered


@pytest.mark.parametrize("control", sorted(UNSAFE_BIDI_CONTROLS))
def test_display_boundary_exposes_bidi_controls_in_legacy_or_provider_text(control):
    rendered = gradio_ui._safe_chat_text(f"invoice{control}gpj.exe")

    assert control not in rendered
    assert f"\\u{ord(control):04X}" in rendered


def test_chatbot_explicitly_disables_untrusted_rich_content():
    demo = gradio_ui.build_ui()
    chatbots = [
        component for component in demo.blocks.values() if isinstance(component, gr.Chatbot)
    ]

    assert len(chatbots) == 1
    chatbot = chatbots[0]
    assert chatbot.render_markdown is False
    assert chatbot.sanitize_html is True
    assert chatbot.allow_tags is False
    assert chatbot.allow_file_downloads is False


@pytest.mark.parametrize("control", sorted(UNSAFE_BIDI_CONTROLS))
@pytest.mark.parametrize(
    ("schema", "field", "prefix"),
    [
        (MessageSend, "content", "Mở https://example.test/"),
        (SessionCreate, "title", "Báo cáo "),
        (SessionUpdate, "title", "Báo cáo "),
    ],
)
def test_bidi_override_and_isolate_controls_are_rejected(schema, field, prefix, control):
    with pytest.raises(ValidationError, match="ký tự điều hướng Unicode không an toàn"):
        schema(**{field: prefix + control + "gpj.exe"})


def test_normal_vietnamese_and_right_to_left_text_remain_valid():
    content = "Tài liệu tiếng Việt — مرحبا بالعالم — שלום עולם"
    assert MessageSend(content=content).content == content
