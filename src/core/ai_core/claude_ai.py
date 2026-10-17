import os
import re

import anthropic
from dotenv import load_dotenv

_ = load_dotenv()

# Cổng tương thích Anthropic Messages API mà nhà cung cấp key hướng dẫn dùng.
DEFAULT_BASE_URL = "https://1gw.gwai.cloud"
DEFAULT_MODEL = "claude-opus-5"
EFFORT_LEVELS = frozenset({"low", "medium", "high", "xhigh", "max"})
# Các model này từ chối output_config.effort bằng 400, nên không gửi trường đó.
_MODELS_WITHOUT_EFFORT = re.compile(r"^claude-(?:3|(?:haiku|sonnet)-4-5)")
_COMPLETE_STOP_REASONS = frozenset({"end_turn", "stop_sequence", "max_tokens"})


class ClaudeClient:
    """Wrapper gọn nhẹ cho Anthropic Messages API (Claude), cùng giao diện với GeminiClient.

    Chỉ đọc biến riêng của dự án (`CLAUDE_API_KEY`, `CLAUDE_BASE_URL`). Key, base URL
    và timeout luôn được truyền tường minh cho SDK, nên SDK KHÔNG tự lấy
    `ANTHROPIC_API_KEY`/`ANTHROPIC_AUTH_TOKEN`/`ANTHROPIC_BASE_URL` hay profile
    `ant auth` trên máy: cấu hình Claude Code/VSCode không lẫn vào ứng dụng.

    Args:
        api_key: Key của cổng (dạng `sk-...`). Nếu None, đọc `CLAUDE_API_KEY`.
            Gửi bằng header `Authorization: Bearer`, giống `ANTHROPIC_AUTH_TOKEN`
            trong hướng dẫn của nhà cung cấp.
        model: Tên model mặc định, ví dụ "claude-opus-5".
        base_url: Địa chỉ cổng. Nếu None, đọc `CLAUDE_BASE_URL` rồi mới tới mặc định.
        timeout_seconds: Thời hạn mỗi lần gọi. None giữ mặc định 10 phút của SDK,
            quá lâu cho một request web, nên ứng dụng luôn truyền giá trị này.
        retry_attempts: Tổng số lần thử (kể cả lần đầu). SDK tự thử lại khi gặp
            lỗi mạng, timeout, 408/409/429/5xx.
        max_output_tokens: Trần token đầu ra (`max_tokens`), gồm cả token suy nghĩ.
        effort: Mức suy nghĩ `output_config.effort`; None để model dùng mặc định.

    Raises:
        ValueError: Nếu thiếu key hoặc tham số không hợp lệ.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        *,
        base_url: str | None = None,
        timeout_seconds: float | None = None,
        retry_attempts: int = 1,
        max_output_tokens: int | None = None,
        effort: str | None = None,
    ):
        if api_key is None:
            api_key = os.getenv("CLAUDE_API_KEY", "")
        self.api_key: str = api_key.strip()
        if not self.api_key:
            raise ValueError(
                "Thiếu API key. Truyền `api_key=` hoặc đặt biến môi trường CLAUDE_API_KEY."
            )
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds phải dương.")
        if retry_attempts < 1:
            raise ValueError("retry_attempts phải ít nhất là 1.")
        if max_output_tokens is not None and (
            type(max_output_tokens) is not int or max_output_tokens < 1
        ):
            raise ValueError("max_output_tokens phải là số nguyên dương.")
        if effort is not None and effort not in EFFORT_LEVELS:
            raise ValueError("effort phải là low, medium, high, xhigh hoặc max.")
        self.model = model
        self.max_output_tokens = max_output_tokens
        self.effort = effort
        self.client = anthropic.Anthropic(
            auth_token=self.api_key,
            base_url=base_url or os.getenv("CLAUDE_BASE_URL", "").strip() or DEFAULT_BASE_URL,
            max_retries=retry_attempts - 1,
            **({"timeout": float(timeout_seconds)} if timeout_seconds is not None else {}),
        )

    def generate(
        self,
        user_content: str,
        *,
        system_instruction: str | None = None,
        temperature: float | None = None,
        model: str | None = None,
        use_web_search: bool = False,
    ) -> str:
        """Gọi `messages.create` và trả về phần text của câu trả lời.

        Args:
            user_content: Nội dung lượt người dùng.
            system_instruction: Chỉ thị hệ thống (tùy chọn), gửi ở trường `system`.
            temperature: Nhiệt độ sampling. Các model Claude mới từ chối giá trị
                khác mặc định, nên để None.
            model: Ghi đè model mặc định cho lần gọi này (tùy chọn).
            use_web_search: Không hỗ trợ; Google Search grounding chỉ có ở Gemini.

        Raises:
            NotImplementedError: Khi yêu cầu tìm kiếm web.
            RuntimeError: Khi câu trả lời không hoàn tất hoặc không có text.
        """
        if use_web_search:
            raise NotImplementedError("Tìm kiếm web chỉ hỗ trợ với nhà cung cấp Gemini.")
        model = model or self.model
        options = {}
        if system_instruction:
            options["system"] = system_instruction
        if temperature is not None:
            options["temperature"] = temperature
        if self.effort and not _MODELS_WITHOUT_EFFORT.match(model):
            options["output_config"] = {"effort": self.effort}

        resp = self.client.messages.create(
            model=model,
            max_tokens=self.max_output_tokens or 2048,
            messages=[{"role": "user", "content": user_content}],
            **options,
        )

        # refusal (bộ lọc an toàn), pause_turn hay tool_use (ứng dụng không cấp
        # công cụ nào) đều không phải câu trả lời hoàn chỉnh để hiển thị.
        if resp.stop_reason not in _COMPLETE_STOP_REASONS:
            raise RuntimeError("Nhà cung cấp không hoàn tất câu trả lời an toàn.")
        # Bỏ qua khối thinking; chỉ ghép các khối text hiển thị được.
        out = "".join(block.text for block in resp.content if block.type == "text").strip()
        if not out:
            raise RuntimeError("Phản hồi không chứa phần text nào.")
        if resp.stop_reason == "max_tokens":
            out += (
                '\n\n[Câu trả lời đã đạt giới hạn token và có thể chưa đầy đủ. '
                'Bạn có thể yêu cầu tiếp tục phần còn lại.]'
            )
        return out


if __name__ == "__main__":
    # Cách dùng: đặt CLAUDE_API_KEY trong .env rồi chạy
    #   uv run python -m src.core.ai_core.claude_ai
    client = ClaudeClient(model=os.getenv("CLAUDE_MODEL", DEFAULT_MODEL), timeout_seconds=25)
    print(client.generate("hello"))
