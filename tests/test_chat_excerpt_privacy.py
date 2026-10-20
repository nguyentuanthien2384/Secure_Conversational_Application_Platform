"""File excerpt selection must never remove the context needed to mask a secret."""

from __future__ import annotations

import json
from dataclasses import replace

import gradio as gr
import pytest

from src.app import gradio_ui
from src.app.chat_files import ChatFile, ChatFileStore, select_file_excerpts, token_digest
from src.app.dlp import MAX_SCAN_CHARACTERS, DLPScanner, FindingType
from src.app.schemas import MAX_CHAT_FILE_CONTENT_CHARS
from src.app.services import AIService


@pytest.fixture(scope="module")
def demo():
    return gradio_ui.build_ui()


@pytest.fixture(autouse=True)
def isolate_uploads_and_notices(monkeypatch):
    monkeypatch.setattr(gradio_ui, "CHAT_FILES", ChatFileStore())
    monkeypatch.setattr(gr, "Info", lambda *args, **kwargs: None)
    monkeypatch.setattr(gr, "Warning", lambda *args, **kwargs: None)


def _callback(demo, name):
    return next(
        item.fn for item in demo.fns.values()
        if item.fn is not None and item.fn.__name__ == name
    )


def _stage(demo, token, text):
    upload_id = gradio_ui.CHAT_FILES.put_pending(
        token_digest(token), ChatFile.from_text("tai_lieu.txt", text)
    )
    updates = _callback(demo, "stage_chat_file")(
        token, json.dumps({"upload_id": upload_id})
    )
    assert updates[1]["visible"] is True
    assert updates[2]["visible"] is True


def _send(demo, token, message, history=()):
    *_, pending = _callback(demo, "begin_send")(token, message, list(history))
    return _callback(demo, "send_pending")(token, "session-1", pending)


class RecordingApi:
    def __init__(self):
        self.calls = []
        self.sent = []

    def __call__(self, _token, method, path, body=None, *, params=None):
        self.calls.append((method, path))
        session = {
            "id": "session-1", "title": "Tài liệu", "security_mode": "confidential",
            "data_classification": "highly_confidential",
        }
        if method == "GET" and path == "/api/sessions/session-1":
            return session
        if method == "POST" and path == "/api/sessions/session-1/messages":
            self.sent.append(body)
            # No server labels: the UI must retain labels from the complete-file pass.
            return {"content": "Đã đọc tài liệu", "dlp_redacted": []}
        if method == "GET" and path == "/api/sessions/page":
            return {
                "items": [session], "total": 1, "offset": 0, "limit": 100,
                "has_more": False, "next_offset": None,
            }
        if method == "GET" and path == "/api/sessions/session-1/messages":
            return [{"role": "assistant", "content": "Đã đọc tài liệu"}]
        raise AssertionError(f"Unexpected API call {method} {path}")


def _boundary_document(secret):
    chunks = ["x" * 1799 + "\n" for _ in range(34)]
    useful = "Kỹ năng: Python và SQL.\n"
    chunks[0] = useful + "x" * (1799 - len(useful)) + "\n"
    # The key is in chunk 6, while the plain value begins chunk 7. Excerpt
    # selection retains chunk 7 and omits chunk 6 in this 61,200-character file.
    chunks[6] = "x" * 1789 + " password: "
    chunks[7] = secret + "\n" + "x" * (1798 - len(secret)) + "\n"
    return "".join(chunks), useful.strip()


def test_complete_source_is_masked_before_excerpt_selection(demo, monkeypatch):
    secret = "ultraPrivateSecret123!"
    source, useful = _boundary_document(secret)
    assert len(source) == 61_200
    scanner = DLPScanner()
    assert FindingType.SECRET in {item.finding_type for item in scanner.scan(source)}

    # Establish the actual regression: inspecting only the selected text loses
    # the password label, so even a second DLP pass cannot detect this value.
    unsafe_excerpt = select_file_excerpts(source)
    unsafe_redacted, findings = scanner.redact(unsafe_excerpt)
    assert secret in unsafe_redacted and not findings

    api = RecordingApi()
    monkeypatch.setattr(gradio_ui, "_api", api)
    token = "boundary-file-owner"
    _stage(demo, token, source)
    outputs = _send(demo, token, "")

    assert len(api.sent) == 1
    outgoing = api.sent[0]
    assert outgoing["sanitize_external_ai"] is True
    assert outgoing["confirm_external_ai"] is True
    assert len(outgoing["file_content"]) <= MAX_CHAT_FILE_CONTENT_CHARS
    assert useful in outgoing["file_content"]
    assert secret not in json.dumps(outgoing, ensure_ascii=False)
    assert outputs[3] == ""
    assert outputs[4]["visible"] is True
    assert "mật khẩu" in outputs[4]["value"]
    assert secret not in outputs[4]["value"]
    assert gradio_ui._get_staged_chat_file(token) is None


def test_file_over_full_inspection_budget_retains_attachment_and_draft(demo, monkeypatch):
    api = RecordingApi()
    monkeypatch.setattr(gradio_ui, "_api", api)
    token = "oversized-file-owner"
    secret = "NeverEchoThisFileSecret42"
    source = "x" * (MAX_SCAN_CHARACTERS + 1) + " password: " + secret
    question = "Hãy phân tích tài liệu này"
    history = [{"role": "assistant", "content": "Nội dung trước đó"}]
    _stage(demo, token, source)
    outputs = _send(demo, token, question, history)

    assert not api.sent
    assert not any(method == "POST" for method, _ in api.calls)
    assert outputs[2] == history
    assert outputs[3] == question
    assert outputs[4]["visible"] is True
    notice = outputs[4]["value"]
    assert "kiểm tra" in notice
    assert "chia" in notice.lower() or "tách" in notice.lower()
    assert secret not in notice
    retained = gradio_ui._get_staged_chat_file(token)
    assert retained is not None and retained.text == source
    _, _, attachment_notice, clear_button = _callback(demo, "finish_send")(token)
    assert attachment_notice["visible"] is True
    assert clear_button["visible"] is True


def test_complete_source_uses_deployment_configured_sanitizer(settings, monkeypatch):
    custom_term = "DU_AN_HOA_LAC"
    service = AIService(replace(settings, dlp_custom_terms=(custom_term,)))
    inspected = []

    def configured_sanitizer(content):
        inspected.append(content)
        return service._sanitize_external_projection(content)

    demo = gradio_ui.build_ui(file_sanitizer=configured_sanitizer)
    useful = "Kỹ năng: Python và SQL."
    source = f"{useful}\nDự án: {custom_term}\n" + "Tham khảo quy trình.\n" * 1800
    assert MAX_CHAT_FILE_CONTENT_CHARS < len(source) <= MAX_SCAN_CHARACTERS
    api = RecordingApi()
    monkeypatch.setattr(gradio_ui, "_api", api)
    token = "custom-policy-file-owner"
    _stage(demo, token, source)
    outputs = _send(demo, token, "Tóm tắt kỹ năng")

    assert inspected == [source]
    assert len(api.sent) == 1
    outgoing = api.sent[0]["file_content"]
    assert useful in outgoing
    assert custom_term not in outgoing
    assert "[REDACTED:CUSTOM_DICTIONARY]" in outgoing
    assert outputs[4]["visible"] is True
    assert "dữ liệu nội bộ" in outputs[4]["value"]
    assert custom_term not in outputs[4]["value"]
