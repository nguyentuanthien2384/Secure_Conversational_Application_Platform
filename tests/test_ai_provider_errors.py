"""Kiểm thử đường xử lý lỗi của nhà cung cấp AI bên ngoài.

Trước bản vá này, lời gọi ``GeminiClient.generate`` không được bọc trong
``try/except``. Khi Gemini trả 401 (key sai), 429 (hết quota) hoặc khi mạng
hỏng, exception của SDK lọt thẳng ra ngoài và FastAPI biến nó thành HTTP 500
kèm traceback — vừa sai mã trạng thái (đây là lỗi tạm thời phía nhà cung cấp,
không phải lỗi lập trình), vừa là information disclosure (OWASP A09 / CWE-209:
thông điệp của SDK thường chứa tên model, endpoint và mã lỗi hạ tầng).

Các test dưới đây khoá lại hành vi mới:
  1. Lỗi nhà cung cấp → ``AIProviderError`` với thông điệp chung chung.
  2. Chi tiết lỗi gốc không bao giờ rò ra response HTTP.
  3. API trả 503 kèm ``Retry-After`` thay vì 500.
  4. Không có tin nhắn nào bị ghi vào DB khi lời gọi AI thất bại.
  5. Key sai định dạng không làm sập ứng dụng lúc khởi động.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from src.app.config import Settings
from src.app.models import SecureMessage
from src.app.services import AI_UNAVAILABLE_MESSAGE, AIProviderError, AIService
from tests.conftest import register_and_login

# Chuỗi mô phỏng thông tin nhạy cảm mà SDK hay nhét vào thông điệp lỗi.
LEAKY_DETAIL = "401 UNAUTHENTICATED: API key AIzaSyLEAKED123 invalid at generativelanguage.googleapis.com"


class _ExplodingGeminiClient:
    """Đóng vai ``GeminiClient`` nhưng luôn ném lỗi như SDK thật."""

    def __init__(self, exc: Exception | None = None):
        self._exc = exc or RuntimeError(LEAKY_DETAIL)

    def generate(self, *args, **kwargs):
        raise self._exc


def _ai_service_with_failing_client(settings: Settings) -> AIService:
    service = AIService(settings)
    service._client = _ExplodingGeminiClient()
    return service


def test_provider_failure_becomes_aiprovidererror(settings: Settings):
    service = _ai_service_with_failing_client(settings)
    with pytest.raises(AIProviderError) as excinfo:
        service.generate("xin chào", [], allow_external_ai=True)
    assert str(excinfo.value) == AI_UNAVAILABLE_MESSAGE


def test_provider_failure_message_hides_infrastructure_detail(settings: Settings):
    """Thông điệp trả cho người dùng không được chứa chi tiết của SDK."""
    service = _ai_service_with_failing_client(settings)
    with pytest.raises(AIProviderError) as excinfo:
        service.generate("xin chào", [], allow_external_ai=True)

    message = str(excinfo.value)
    assert "AIzaSy" not in message
    assert "googleapis.com" not in message
    assert "401" not in message
    # Nguyên nhân gốc vẫn phải giữ được để log/debug phía máy chủ.
    assert LEAKY_DETAIL in str(excinfo.value.__cause__)


def test_missing_key_with_demo_disabled_raises_aiprovidererror(settings: Settings):
    """Không key + ALLOW_DEMO_AI=false: vẫn là lỗi dịch vụ, không phải crash."""
    offline = replace(settings, allow_demo_ai=False)
    service = AIService(offline)
    with pytest.raises(AIProviderError):
        service.generate("xin chào", [], allow_external_ai=True)


def test_chat_endpoint_returns_503_not_500(client: TestClient, app):
    """API phải trả 503 + Retry-After, và không lộ chi tiết lỗi gốc."""
    app.state.chat_service.ai._client = _ExplodingGeminiClient()

    token = register_and_login(client, "ai.loi.provider")
    headers = {"Authorization": f"Bearer {token}"}
    client.patch("/api/auth/ai-consent", headers=headers, json={"ai_data_consent": True})
    session_id = client.post(
        "/api/sessions", headers=headers, json={"title": "Phiên lỗi AI"}
    ).json()["id"]

    response = client.post(
        f"/api/sessions/{session_id}/messages",
        headers=headers,
        json={"content": "Câu hỏi bất kỳ"},
    )

    assert response.status_code == 503
    assert response.headers.get("Retry-After") == "30"
    assert response.json()["detail"] == AI_UNAVAILABLE_MESSAGE
    assert "AIzaSy" not in response.text
    assert "Traceback" not in response.text


def test_no_message_persisted_when_provider_fails(client: TestClient, app):
    """Lỗi AI không được để lại tin nhắn user mồ côi trong DB."""
    app.state.chat_service.ai._client = _ExplodingGeminiClient()

    token = register_and_login(client, "ai.loi.khong.ghi")
    headers = {"Authorization": f"Bearer {token}"}
    client.patch("/api/auth/ai-consent", headers=headers, json={"ai_data_consent": True})
    session_id = client.post(
        "/api/sessions", headers=headers, json={"title": "Không ghi nửa vời"}
    ).json()["id"]

    client.post(
        f"/api/sessions/{session_id}/messages",
        headers=headers,
        json={"content": "Tin nhắn này không được lưu"},
    )

    with app.state.database.session_factory() as db:
        count = db.scalar(
            select(func.count())
            .select_from(SecureMessage)
            .where(SecureMessage.session_id == session_id)
        )
    assert count == 0


def test_client_construction_failure_does_not_crash_startup(settings: Settings, monkeypatch):
    """Khởi tạo client thất bại chỉ làm suy giảm tính năng AI, không sập app.

    Thay module ``gemini_ai`` bằng một stub luôn ném lỗi ở constructor, mô phỏng
    key sai định dạng hoặc SDK không khởi tạo được.
    """
    import sys
    import types

    stub = types.ModuleType("src.core.ai_core.gemini_ai")

    def _boom(*args, **kwargs):
        raise ValueError("API key sai định dạng")

    stub.GeminiClient = _boom
    monkeypatch.setitem(sys.modules, "src.core.ai_core.gemini_ai", stub)

    broken = replace(settings, google_genai_api_key="khong-phai-key-hop-le")
    service = AIService(broken)  # không được ném exception
    assert service._client is None
    # allow_demo_ai=True nên vẫn trả lời được ở chế độ ngoại tuyến.
    reply, _ = service.generate("xin chào", [], allow_external_ai=True)
    assert "[DEMO AI]" in reply
