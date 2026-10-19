import ipaddress
import os
import re
from collections.abc import Sequence
from html.parser import HTMLParser
from urllib.parse import urlsplit

from dotenv import load_dotenv
from google import genai
from google.genai import types

_ = load_dotenv()

_MAX_GROUNDING_LINKS = 20
_MAX_SEARCH_SUGGESTIONS = 5


def _grounding_url(value: object, *, google_search: bool = False) -> str | None:
    """Validate a display-only URL; the application never fetches these links."""
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        return None
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 or char in '<>\\' for char in value):
        return None
    try:
        parts = urlsplit(value)
        host = (parts.hostname or '').lower().rstrip('.')
        if parts.scheme != 'https' or not host or parts.username or parts.password:
            return None
        if parts.port not in {None, 443}:
            return None
        if google_search:
            direct_search = host in {'google.com', 'www.google.com'} and parts.path == '/search'
            # Google's widget can use its signed grounding redirect instead of
            # a direct google.com/search URL. Preserve that provider URL exactly.
            signed_redirect = (
                host == 'vertexaisearch.cloud.google.com'
                and re.fullmatch(r'/grounding-api-redirect/[A-Za-z0-9_=-]+', parts.path)
                and not parts.query and not parts.fragment
            )
            if not (direct_search or signed_redirect):
                return None
        else:
            try:
                if not ipaddress.ip_address(host).is_global:
                    return None
            except ValueError:
                if '.' not in host or host.endswith(('.localhost', '.local', '.internal', '.lan')):
                    return None
    except ValueError:
        return None
    return value


def _grounding_label(value: object) -> str:
    if not isinstance(value, str):
        return ''
    label = ' '.join(value.split())
    if not label or len(label) > 500:
        return ''
    # Captions are data. Escape Markdown so they cannot add markup or images.
    return re.sub(r'([\\`*_{}\[\]()#!<>|~])', r'\\\1', label)


def _inert_css(value: str) -> bool:
    # Preserve the widget verbatim or reject it. Escapes are not needed by the
    # Google widget; rejecting them prevents obfuscating network-capable CSS.
    if '\\' in value or any(ord(c) < 32 and c not in '\t\r\n' for c in value):
        return False
    css = re.sub(r'/\*.*?\*/', '', value, flags=re.S).lower()
    if re.search(r'(?:url|image(?:-set)?|cross-fade|element|expression|src)\s*\(', css):
        return False
    return all(match.group(1) in {'media', 'supports'}
               for match in re.finditer(r'@([a-z-]+)', css))


class _SearchWidgetValidator(HTMLParser):
    """Validate the original widget; never sanitize, rewrite or fetch it."""

    tags = {'div', 'span', 'p', 'a', 'style', 'svg', 'g', 'path', 'rect',
            'circle', 'line', 'polyline', 'polygon', 'br'}
    attributes = {'class', 'id', 'style', 'aria-label', 'aria-hidden', 'role', 'title',
                  'href', 'target', 'rel', 'xmlns', 'viewbox', 'width', 'height',
                  'fill', 'fill-rule', 'clip-rule', 'd', 'stroke', 'stroke-width',
                  'stroke-linecap', 'stroke-linejoin', 'opacity', 'fill-opacity',
                  'stroke-opacity', 'transform', 'x', 'y', 'rx', 'ry', 'cx', 'cy',
                  'r', 'x1', 'x2', 'y1', 'y2', 'points', 'version', 'focusable'}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.valid = True
        self.stack: list[str] = []
        self.links = 0

    def handle_starttag(self, tag, attrs):
        if tag not in self.tags:
            self.valid = False
        names = [name for name, _ in attrs]
        if len(names) != len(set(names)):
            self.valid = False
        for name, value in attrs:
            if name not in self.attributes or value is None or not _inert_css(value):
                self.valid = False
            if name == 'href' and (tag != 'a' or not _grounding_url(value, google_search=True)):
                self.valid = False
            if name == 'target' and value not in {'_blank', '_self'}:
                self.valid = False
            if name == 'xmlns' and value != 'http://www.w3.org/2000/svg':
                self.valid = False
        if tag == 'a':
            if not _grounding_url(dict(attrs).get('href'), google_search=True):
                self.valid = False
            self.links += 1
        if tag != 'br':
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag != 'br':
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack.pop() != tag:
            self.valid = False

    def handle_data(self, data):
        if self.stack and self.stack[-1] == 'style' and not _inert_css(data):
            self.valid = False

    def handle_decl(self, decl):
        self.valid = False

    def unknown_decl(self, data):
        self.valid = False

    def handle_pi(self, data):
        self.valid = False


def validate_search_suggestions_html(value: object) -> bool:
    """Allow only an inert, self-contained Google widget for a scoped DOM root."""
    if not isinstance(value, str) or not 1 <= len(value) <= 32000:
        return False
    try:
        if len(value.encode('utf-8')) > 32000:
            return False
    except UnicodeEncodeError:
        return False
    parser = _SearchWidgetValidator()
    try:
        parser.feed(value)
        parser.close()
    except (ValueError, AssertionError):
        return False
    return parser.valid and not parser.stack and 1 <= parser.links <= _MAX_SEARCH_SUGGESTIONS


class GroundedAnswer(str):
    """Text plus transient widget, for the stateless authenticated search UI."""

    def __new__(cls, text: str, search_suggestions_html: str | None = None):
        result = super().__new__(cls, text)
        result.search_suggestions_html = search_suggestions_html
        return result


def _grounded_answer(candidate, visible_parts: list[tuple[int, str]]) -> GroundedAnswer:
    metadata = getattr(candidate, 'grounding_metadata', None)
    chunks = getattr(metadata, 'grounding_chunks', None) or []
    text = ''.join(part for _, part in visible_parts)
    if not chunks:
        entry = getattr(metadata, 'search_entry_point', None)
        if getattr(entry, 'rendered_content', None) or getattr(metadata, 'web_search_queries', None):
            raise RuntimeError('Kết quả tra cứu thiếu thông tin nguồn đầy đủ.')
        return GroundedAnswer(text + '\n\nTra cứu Internet: lần trả lời này không có nguồn kiểm chứng từ Google Search.')
    if len(chunks) > _MAX_GROUNDING_LINKS:
        raise RuntimeError('Số nguồn tra cứu vượt giới hạn hiển thị an toàn.')
    sources: list[tuple[str, str]] = []
    for chunk in chunks:
        web = getattr(chunk, 'web', None)
        if web is None:
            raise RuntimeError('Nhà cung cấp không trả nguồn web kiểm chứng được.')
        uri = _grounding_url(getattr(web, 'uri', None))
        label = _grounding_label(getattr(web, 'title', None))
        if not uri:
            raise RuntimeError('Nhà cung cấp trả nguồn tra cứu không an toàn.')
        sources.append((label or _grounding_label(urlsplit(uri).hostname), uri))
    entry = getattr(metadata, 'search_entry_point', None)
    html = getattr(entry, 'rendered_content', None)
    if not validate_search_suggestions_html(html):
        raise RuntimeError('Thiếu liên kết gợi ý Google Search hợp lệ.')
    # SDK segment offsets are UTF-8 bytes in the original Part, not Python
    # character offsets. Add citations only to the exact supported segment.
    supports = getattr(metadata, 'grounding_supports', None) or []
    if len(supports) > 100:
        raise RuntimeError('Số trích dẫn vượt giới hạn hiển thị an toàn.')
    visible = dict(visible_parts)
    inserts: dict[int, dict[int, set[int]]] = {}
    for support in supports:
        segment = getattr(support, 'segment', None)
        part_index = getattr(segment, 'part_index', None) or 0
        start, end = getattr(segment, 'start_index', None), getattr(segment, 'end_index', None)
        if start is None:
            # Protobuf JSON omits a zero startIndex for the first segment.
            start = 0
        indices = getattr(support, 'grounding_chunk_indices', None) or []
        if not indices:
            continue
        if (type(part_index) is not int or part_index not in visible
                or type(start) is not int or type(end) is not int or not 0 <= start < end
                or any(type(i) is not int or not 0 <= i < len(sources) for i in indices)):
            raise RuntimeError('Thông tin trích dẫn không hợp lệ.')
        encoded = visible[part_index].encode('utf-8')
        if end > len(encoded):
            raise RuntimeError('Thông tin trích dẫn không hợp lệ.')
        try:
            segment_text = encoded[start:end].decode('utf-8')
            position = len(encoded[:end].decode('utf-8'))
        except UnicodeDecodeError as exc:
            raise RuntimeError('Thông tin trích dẫn không hợp lệ.') from exc
        provided_text = getattr(segment, 'text', None)
        if provided_text is not None and provided_text != segment_text:
            raise RuntimeError('Thông tin trích dẫn không khớp câu trả lời.')
        inserts.setdefault(part_index, {}).setdefault(position, set()).update(indices)
    cited_parts = []
    for part_index, part in visible_parts:
        for position, indices in sorted(inserts.get(part_index, {}).items(), reverse=True):
            citations = ' '.join(f'[{i + 1}](<{sources[i][1]}>)' for i in sorted(indices))
            part = part[:position] + citations + part[position:]
        cited_parts.append(part)
    source_lines = [f'- [{i + 1}: {label}](<{uri}>)' for i, (label, uri) in enumerate(sources)]
    return GroundedAnswer(
        ''.join(cited_parts) + '\n\nNguồn Google Search trả về:\n' + '\n'.join(source_lines),
        html,
    )


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
        model: Tên model mặc định. Ví dụ: "gemini-flash-lite-latest".
        timeout_seconds: Thời hạn mỗi lần gọi. SDK mặc định KHÔNG có timeout,
            nên một kết nối treo giữ luồng xử lý của máy chủ vô thời hạn.
        retry_attempts: Tổng số lần thử (kể cả lần đầu) khi gặp lỗi tạm thời
            408/429/5xx hoặc mạng. SDK mặc định chỉ thử một lần, nên một lỗi
            "model overloaded" thoáng qua cũng trả lỗi cho người dùng.
        max_output_tokens: Trần token đầu ra cho mọi lần gọi từ client này.
            ``extra_config`` có thể hạ nhưng không tăng giới hạn đã cấu hình.

    Raises:
        ValueError: Nếu không tìm thấy `api_key`.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gemini-flash-lite-latest",
        *,
        timeout_seconds: float | None = None,
        retry_attempts: int = 1,
        max_output_tokens: int | None = None,
    ):
        if api_key is None:
            api_key = os.getenv("GOOGLE_GENAI_API_KEY", "")
        self.api_key: str = api_key
        if not self.api_key:
            raise ValueError(
                "Thiếu API key. Truyền `api_key=` hoặc đặt biến môi trường GOOGLE_GENAI_API_KEY."
            )
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("timeout_seconds phải dương.")
        if retry_attempts < 1:
            raise ValueError("retry_attempts phải ít nhất là 1.")
        if max_output_tokens is not None and (
            type(max_output_tokens) is not int or max_output_tokens < 1
        ):
            raise ValueError("max_output_tokens phải là số nguyên dương.")
        self.max_output_tokens = max_output_tokens
        http_options = types.HttpOptions(
            # HttpOptions.timeout tính bằng mili giây.
            timeout=int(timeout_seconds * 1000) if timeout_seconds is not None else None,
            retry_options=(
                types.HttpRetryOptions(attempts=retry_attempts, initial_delay=1.0, max_delay=4.0)
                if retry_attempts > 1
                else None
            ),
        )
        self.client = genai.Client(api_key=self.api_key, http_options=http_options)
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
        thinking_budget: int | None = None,
        temperature: float | None = None,
        extra_config: dict | None = None,
        model: str | None = None,
        use_web_search: bool = False,
    ) -> str:
        """Gọi `models.generate_content` và trả về text.

        Args:
            user_content: Nội dung người dùng. Hỗ trợ `str`, list[str] hoặc list[types.Part].
            system_instruction: Chuỗi hướng dẫn hệ thống (tùy chọn).
            thinking_budget: Ngân sách “thinking” (nếu model hỗ trợ). Mặc định
                `None` = không gửi `ThinkingConfig`, để model dùng mặc định.
                LƯU Ý: giá trị `0` (tắt hẳn thinking) bị các model thế hệ mới
                từ chối bằng 400 INVALID_ARGUMENT — chỉ dùng với model cũ.
            temperature: Nhiệt độ sampling (nếu model hỗ trợ).
            extra_config: Dict bổ sung vào `GenerateContentConfig` (advanced).
            model: Ghi đè model mặc định cho lần gọi này (tùy chọn).
            use_web_search: Bật Google Search khi ứng dụng đã kiểm tra quyền,
                đồng thuận và dữ liệu công khai. Công cụ có thể tính phí.

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
        if use_web_search:
            # This interface grants only the built-in search tool, never custom
            # actions, code execution or unrestricted URL fetching by our app.
            cfg_kwargs['tools'] = [types.Tool(google_search=types.GoogleSearch())]

        generate_content_config = (
            types.GenerateContentConfig(**cfg_kwargs)
            if cfg_kwargs or self.max_output_tokens is not None else None
        )
        if generate_content_config is not None and self.max_output_tokens is not None:
            # Clamp the parsed field, after aliases/extra_config have been
            # applied, so a caller cannot override the deployment's ceiling.
            requested = generate_content_config.max_output_tokens
            if requested is not None and requested < 1:
                raise ValueError("max_output_tokens phải là số nguyên dương.")
            generate_content_config.max_output_tokens = (
                min(requested, self.max_output_tokens)
                if requested is not None else self.max_output_tokens
            )

        resp = self.client.models.generate_content(
            model=(model or self.model),
            contents=contents,
            config=generate_content_config,
        )

        # Rút trích text an toàn. Prompt bị bộ lọc an toàn chặn không có
        # candidate; candidate dừng vì SAFETY/MAX_TOKENS có thể có content mà
        # parts=None — cả hai đều phải thành RuntimeError rõ ràng, không TypeError.
        try:
            cand = resp.candidates[0]
            parts = getattr(cand, "content", None).parts or []  # type: ignore[attr-defined]
        except Exception as e:
            raise RuntimeError("Không có candidate hợp lệ trong phản hồi.") from e

        reason = getattr(cand, 'finish_reason', None)
        reason = getattr(reason, 'value', reason)
        if reason and str(reason) not in {'STOP', 'MAX_TOKENS', 'FINISH_REASON_UNSPECIFIED'}:
            raise RuntimeError('Nhà cung cấp không hoàn tất câu trả lời an toàn.')

        visible_parts: list[tuple[int, str]] = []
        for index, p in enumerate(parts):
            if getattr(p, 'thought', False):
                continue
            t = getattr(p, "text", None)
            if t:
                visible_parts.append((index, t))
        out = "".join(text for _, text in visible_parts)
        if not out.strip():
            raise RuntimeError("Candidate không chứa phần text nào.")
        if use_web_search:
            # Never label a partial grounded result complete or modify its
            # text with a truncation notice. The caller can retry a smaller query.
            if reason == 'MAX_TOKENS':
                raise RuntimeError('Kết quả tra cứu chưa hoàn tất; hãy thu gọn câu hỏi.')
            return _grounded_answer(cand, visible_parts)
        out = out.strip()
        if reason == 'MAX_TOKENS':
            out += (
                '\n\n[Câu trả lời đã đạt giới hạn token và có thể chưa đầy đủ. '
                'Bạn có thể yêu cầu tiếp tục phần còn lại.]'
            )
        return out


if __name__ == "__main__":
    import sys

    for _stream in (sys.stdout, sys.stderr):
        if hasattr(_stream, "reconfigure"):
            _stream.reconfigure(encoding="utf-8", errors="replace")
    # Cách dùng:
    #   export GOOGLE_GENAI_API_KEY="..."  # hoặc đặt trong .env rồi load trước đó
    client = GeminiClient(model="gemini-flash-lite-latest")
    print(client.generate("hello"))

