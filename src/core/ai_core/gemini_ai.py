import os
from collections.abc import Sequence
from google import genai
from google.genai import types

from dotenv import load_dotenv

_ = load_dotenv()


class GeminiClient:
    """Wrapper gọn nhẹ cho Google GenAI (gemini) theo hướng OOP.

    Class này quản lý vòng đời `genai.Client`, cấu hình model mặc định
    và cung cấp hàm `generate` để gọi `models.generate_content`.

    Ưu điểm:
      - Không hardcode API key: ưu tiên đọc từ biến môi trường `GOOGLE_GENAI_API_KEY`.
      - Cho phép thêm `system_instruction`, `thinking_budget`, `temperature`.
      - Xử lý `user_content` linh hoạt: `str`, list[str], hoặc list[types.Part].

    Args:
        api_key: Khóa truy cập Google GenAI. Nếu None, sẽ đọc từ
            biến môi trường `GOOGLE_GENAI_API_KEY`.
        model: Tên model mặc định. Ví dụ: "gemini-2.5-flash-lite".

    Raises:
        ValueError: Nếu không tìm thấy `api_key`.
    """

    def __init__(self, api_key: str | None = None, model: str = "gemini-2.5-flash-lite"):
        if api_key is None:
            api_key = os.getenv("GOOGLE_GENAI_API_KEY", "")
        self.api_key: str = api_key
        if not self.api_key:
            raise ValueError(
                "Thiếu API key. Truyền `api_key=` hoặc đặt biến môi trường GOOGLE_GENAI_API_KEY."
            )
        self.client = genai.Client(api_key=self.api_key)
        self.model = model

    # ------------------------ helpers ------------------------

    @staticmethod
    def _to_parts(
        text_or_parts: str | Sequence[str] | Sequence[types.Part]
    ) -> Sequence[types.Part]:
        """Chuẩn hoá input user thành danh sách `types.Part`.

        Args:
            text_or_parts: Một chuỗi, danh sách chuỗi, hoặc danh sách `types.Part`.

        Returns:
            List `types.Part`.

        Raises:
            TypeError: Nếu phần tử không phải `str` hay `types.Part`.
        """
        if isinstance(text_or_parts, str):
            return [types.Part.from_text(text=text_or_parts)]

        parts: list[types.Part] = []
        for p in text_or_parts:
            if isinstance(p, types.Part):
                parts.append(p)
            elif isinstance(p, str):
                parts.append(types.Part.from_text(text=p))
            else:
                raise TypeError("Mỗi phần phải là `str` hoặc `google.genai.types.Part`.")
        return parts

    # ------------------------ main API ------------------------

    def generate(
        self,
        user_content: str | Sequence[str] | Sequence[types.Part],
        *,
        system_instruction: str | None = None,
        thinking_budget: int | None = 0,
        temperature: float | None = None,
        extra_config: dict | None = None,
        model: str | None = None,
    ) -> str:
        """Gọi `models.generate_content` và trả về text.

        Args:
            user_content: Nội dung người dùng. Hỗ trợ `str`, list[str] hoặc list[types.Part].
            system_instruction: Chuỗi hướng dẫn hệ thống (tùy chọn).
            thinking_budget: Ngân sách “thinking” (nếu model hỗ trợ). Mặc định 0.
            temperature: Nhiệt độ sampling (nếu model hỗ trợ).
            extra_config: Dict bổ sung vào `GenerateContentConfig` (advanced).
            model: Ghi đè model mặc định cho lần gọi này (tùy chọn).

        Returns:
            Chuỗi văn bản tổng hợp từ các `parts` dạng text của candidate đầu tiên.

        Raises:
            RuntimeError: Khi không có candidate/parts hợp lệ.
        """
        contents: list[types.Content] = [
            types.Content(role="user", parts=self._to_parts(user_content))
        ]

        cfg_kwargs = {}
        if system_instruction:
            # Google GenAI SDK expects system instructions in GenerateContentConfig,
            # not as an untrusted content message.
            cfg_kwargs["system_instruction"] = system_instruction
        if thinking_budget is not None:
            cfg_kwargs["thinking_config"] = types.ThinkingConfig(thinking_budget=thinking_budget)
        if temperature is not None:
            cfg_kwargs["temperature"] = temperature
        if extra_config:
            cfg_kwargs.update(extra_config)

        generate_content_config = types.GenerateContentConfig(**cfg_kwargs) if cfg_kwargs else None

        resp = self.client.models.generate_content(
            model=(model or self.model),
            contents=contents,
            config=generate_content_config,
        )

        # Rút trích text an toàn
        try:
            cand = resp.candidates[0]
            parts = getattr(cand, "content", None).parts  # type: ignore[attr-defined]
        except Exception as e:
            raise RuntimeError(f"Không có candidate hợp lệ trong phản hồi: {e}") from e

        texts: list[str] = []
        for p in parts:
            t = getattr(p, "text", None)
            if t:
                texts.append(t)
        out = "".join(texts).strip()
        if not out:
            raise RuntimeError("Candidate không chứa phần text nào.")
        return out


if __name__ == "__main__":
    # Cách dùng:
    #   export GOOGLE_GENAI_API_KEY="..."  # hoặc đặt trong .env rồi load trước đó
    client = GeminiClient(model="gemini-2.5-flash-lite")
    print(client.generate("hello", thinking_budget=0))
    