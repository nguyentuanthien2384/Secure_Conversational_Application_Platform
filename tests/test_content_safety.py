from __future__ import annotations

from html.parser import HTMLParser

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
    assert "<img" not in rendered
    assert "beacon" in rendered
    assert '<a href="https://phishing.example/"' in rendered
    assert 'rel="noopener noreferrer"' in rendered
    assert 'referrerpolicy="no-referrer"' in rendered


@pytest.mark.parametrize("control", sorted(UNSAFE_BIDI_CONTROLS))
def test_display_boundary_exposes_bidi_controls_in_legacy_or_provider_text(control):
    rendered = gradio_ui._safe_chat_text(f"invoice{control}gpj.exe")

    assert control not in rendered
    assert f"\\u{ord(control):04X}" in rendered


def test_chatbot_keeps_html_sanitization_without_file_or_custom_renderers():
    demo = gradio_ui.build_ui()
    chatbots = [
        component for component in demo.blocks.values() if isinstance(component, gr.Chatbot)
    ]

    assert len(chatbots) == 1
    chatbot = chatbots[0]
    assert chatbot.render_markdown is True
    assert chatbot.sanitize_html is True
    assert chatbot.allow_tags is False
    assert chatbot.allow_file_downloads is False
    assert chatbot.latex_delimiters == []


class _Elements(HTMLParser):
    def __init__(self, content):
        super().__init__()
        self.elements = []
        self.feed(content)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


@pytest.mark.parametrize("slashes", range(9))
@pytest.mark.parametrize("image", [
    "![pixel](https://tracker.example/pixel)",
    "![pixel][tracking]\n\n[tracking]: https://tracker.example/pixel",
    "![tracking]\n\n[tracking]: https://tracker.example/pixel",
    "[![pixel](https://tracker.example/pixel)](https://example.test/source)",
    "![nested [label]](https://tracker.example/pixel)",
])
def test_markdown_images_never_become_browser_image_requests(slashes, image):
    rendered = gradio_ui._safe_chat_text("\\" * slashes + image)
    elements = _Elements(rendered).elements
    assert not any(tag in {"img", "image", "iframe", "video", "audio", "source"}
                   for tag, _attrs in elements)
    assert not any("src" in attrs or "srcset" in attrs for _tag, attrs in elements)


@pytest.mark.parametrize("destination", [
    "javascript:alert%281%29", "JaVaScRiPt:alert%281%29", "jav&#x61;script:alert%281%29",
    "data:text/html;base64,PHNjcmlwdD4=", "vbscript:msgbox%281%29", "file:///etc/passwd",
    "//tracker.example/pixel", "/gradio_api/file=/etc/passwd", "mailto:private@example.test",
    "https://trusted.example@tracker.example/", "https://tracker.example\\@trusted.example/",
])
def test_chat_links_only_navigate_to_absolute_http_destinations(destination):
    rendered = gradio_ui._safe_chat_text(f"[source]({destination})")
    assert not any(tag == "a" for tag, _attrs in _Elements(rendered).elements)


def test_safe_markdown_keeps_code_bold_lists_tables_and_source_links():
    content = (
        "**Kết quả**\n\n- Một ý\n- Hai ý\n\n"
        "| Cột | Giá trị |\n| --- | --- |\n| A | B |\n\n"
        "```html\n<img src='https://tracker.example/pixel'>\nprint('![x](url)')\n```\n\n"
        "`a < b && c`\n\n[Nguồn](https://example.test/path?q=1&lang=vi)"
    )
    rendered = gradio_ui._safe_chat_text(content)
    elements = _Elements(rendered).elements
    tags = {tag for tag, _attrs in elements}
    assert {"strong", "ul", "li", "table", "th", "td", "pre", "code", "a"} <= tags
    assert "img" not in tags
    assert "&lt;img" in rendered
    assert "print('![x](url)')" in rendered
    assert "a &lt; b &amp;&amp; c" in rendered
    assert next(attrs for tag, attrs in elements if tag == "a")["href"] == (
        "https://example.test/path?q=1&lang=vi"
    )


def test_mermaid_and_raw_html_remain_inert_display_content():
    rendered = gradio_ui._safe_chat_text(
        "```mermaid\ngraph TD; A-->B\n```\n\n"
        '<script>alert(1)</script><svg><image href="https://tracker.example/pixel"></svg>'
    )
    elements = _Elements(rendered).elements
    assert not any(tag in {"script", "svg", "image"} for tag, _attrs in elements)
    assert not any("mermaid" in attrs.get("class", "") for _tag, attrs in elements)
    assert "&lt;script&gt;" in rendered


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
