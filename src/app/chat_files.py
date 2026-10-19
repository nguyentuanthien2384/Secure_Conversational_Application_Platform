"""Tài liệu đính kèm hội thoại: tải lên tối đa 10 MiB, trích văn bản, chọn đoạn gửi AI.

Nhận tệp văn bản/mã nguồn (UTF-8 hoặc UTF-16 có BOM), .docx và .pdf có lớp chữ.

Trình duyệt gửi nhị phân thô tới một route riêng (``CHAT_FILE_UPLOAD_PATH``)
thay vì nhét base64 vào hàng đợi Gradio, nên chỉ route này được vượt giới hạn
body 1 MiB chung (request_limits.py và Caddyfile). Văn bản trích ra chỉ nằm
trong bộ nhớ tiến trình, ở dạng nén, có hạn dùng và tổng dung lượng giới hạn;
không bao giờ ghi ra đĩa.

Tệp đi qua hai bước để luôn thuộc đúng phiên của tab đã chọn nó:

1. route upload xác thực bằng cookie phiên UI, trích văn bản và giữ ở trạng
   thái "chờ" dưới một mã ngẫu nhiên, gắn với token của cookie;
2. callback Gradio của tab nhận mã đó và chỉ nhận tệp khi token của tab trùng
   chủ sở hữu, nên tab của tài khoản khác không thể nhận nhầm.

Tài liệu dài hơn ``MAX_CHAT_FILE_CONTENT_CHARS`` không bị cắt cụt mù quáng: mỗi
lần gửi chỉ chuyển cho AI các đoạn liên quan nhất tới câu hỏi (xếp hạng BM25
trên chữ đã bỏ dấu), kèm một dòng ghi chú để người dùng lẫn AI biết đó là trích
đoạn.
"""

from __future__ import annotations

import base64
import codecs
import hashlib
import html
import io
import logging
import math
import re
import secrets
import threading
import time
import unicodedata
import zipfile
import zlib
from collections import Counter, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from pypdf import PasswordType, PdfReader

from src.app.schemas import (
    ALLOWED_CHAT_FILE_EXTENSIONS,
    MAX_CHAT_FILE_CONTENT_CHARS,
    MAX_CHAT_FILE_NAME_CHARS,
    UNSAFE_BIDI_CONTROLS,
)

CHAT_FILE_UPLOAD_PATH = "/api/ui-session/chat-file"
MAX_CHAT_FILE_UPLOAD_BYTES = 10 * 1024 * 1024
# Một .docx 10 MiB gần như toàn ảnh; phần chữ giải nén hiếm khi quá vài MiB.
# Trần này chặn zip bomb mà vẫn đủ cho tài liệu hàng nghìn trang.
MAX_DOCX_XML_BYTES = 20 * 1024 * 1024
MAX_DOCX_MEMBERS = 10_000
# PDF: pypdf đã tự giới hạn dữ liệu giải nén của mỗi luồng (75 MB). Thêm trần
# số trang, tổng số chữ và thời gian để một tệp dựng sẵn không chiếm lâu một
# trong hai luồng phân tích dùng chung (max_parallel của ChatFileStore). Thời
# gian phải dưới response_header_timeout 30s của Caddy (tính từ lúc nhận xong
# body); PDF chữ dày mất khoảng 25 ms/trang, tức vài trăm trang trong 20 giây.
MAX_PDF_PAGES = 2_000
MAX_PDF_TEXT_CHARS = 5_000_000
PDF_EXTRACT_SECONDS = 20.0
UPLOAD_ID_RE = re.compile(r"^[A-Za-z0-9_-]{32}$")
# Tên tệp đi trong header dạng base64url(UTF-8): header chỉ chứa ASCII và
# tên tiếng Việt không bị proxy hay IDS hiểu sai.
FILE_NAME_HEADER = "x-scap-file-name"
_FILE_NAME_HEADER_RE = re.compile(r"^[A-Za-z0-9_-]{1,1024}$")
# Khớp read_body 60s của Caddy: 10 MiB cần đường lên khoảng 1,5 Mbit/s.
UPLOAD_READ_SECONDS = 60.0

_MAX_MB = MAX_CHAT_FILE_UPLOAD_BYTES // (1024 * 1024)
_BIDI_RE = re.compile("[" + "".join(sorted(UNSAFE_BIDI_CONTROLS)) + "]")
# Sau khi chuẩn hóa xuống dòng, chỉ \n và \t là ký tự điều khiển hợp lệ.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
# Cảnh báo của pypdf về tệp hỏng nhẹ là chuyện thường với tệp người dùng tải
# lên; không để chúng làm ngập log máy chủ.
logging.getLogger("pypdf").setLevel(logging.ERROR)

ERROR_MESSAGES: dict[str, str] = {
    "too_large": f"Tệp vượt quá giới hạn {_MAX_MB} MB. Hãy chọn tệp nhỏ hơn.",
    "empty": "Tệp đính kèm không có nội dung văn bản để phân tích.",
    "unsupported_type": (
        "Định dạng tệp không được hỗ trợ. Hãy chọn tệp văn bản "
        "(.txt, .md, .csv, .json, mã nguồn…), .docx hoặc .pdf."
    ),
    "invalid_name": (
        f"Tên tệp phải từ 1 đến {MAX_CHAT_FILE_NAME_CHARS} ký tự, "
        "không chứa '..' hay ký tự điều khiển."
    ),
    "not_utf8": "Tệp không phải văn bản UTF-8 hợp lệ. Hãy lưu lại tệp với mã hóa UTF-8.",
    "binary": (
        "Tệp chứa ký tự nhị phân hoặc ký tự điều khiển không hợp lệ. "
        "Hãy chọn tệp văn bản, .docx hoặc .pdf."
    ),
    "bidi": "Nội dung tệp chứa ký tự điều hướng hai chiều (Bidi) không an toàn.",
    "docx_invalid": "Không đọc được tệp .docx. Hãy kiểm tra lại định dạng tệp.",
    "docx_too_large": "Nội dung giải nén của tệp .docx vượt quá giới hạn an toàn.",
    "pdf_invalid": "Không đọc được tệp PDF. Tệp có thể bị hỏng hoặc không đúng định dạng.",
    "pdf_encrypted": "Tệp PDF được đặt mật khẩu. Hãy gỡ mật khẩu rồi đính kèm lại.",
    "pdf_no_text": (
        "Tệp PDF không có lớp chữ (thường là bản scan hoặc ảnh chụp) và hệ thống chưa "
        "hỗ trợ nhận dạng chữ (OCR). Hãy dùng PDF có chữ chọn được, hoặc chuyển sang .docx/.txt."
    ),
    "pdf_too_large": (
        "Tệp PDF quá nhiều trang hoặc quá phức tạp để trích xuất "
        f"(tối đa {MAX_PDF_PAGES} trang, {PDF_EXTRACT_SECONDS:.0f} giây xử lý)."
    ),
    "read_failed": "Trình duyệt không đọc được tệp đã chọn. Vui lòng thử lại.",
    "upload_failed": "Không tải được tệp lên máy chủ. Kiểm tra kết nối rồi thử lại.",
    "session": (
        "Phiên trình duyệt chưa sẵn sàng để nhận tệp. "
        "Hãy tải lại trang (F5) rồi đính kèm lại."
    ),
    "busy": "Máy chủ đang xử lý tệp khác. Vui lòng thử lại sau ít giây.",
    "rate_limited": "Bạn tải tệp lên quá nhanh. Vui lòng đợi vài phút rồi thử lại.",
    "timeout": "Tải tệp lên quá lâu nên máy chủ đã ngắt. Hãy thử lại với kết nối ổn định hơn.",
    "expired": (
        "Tệp vừa tải lên đã hết hạn hoặc không thuộc phiên đăng nhập của tab này. "
        "Hãy đính kèm lại."
    ),
    "invalid": "Không thể xử lý tệp đính kèm.",
}


class ChatFileError(ValueError):
    """Lỗi có mã cố định; chỉ mã đi qua trình duyệt, thông điệp tra ở máy chủ."""

    def __init__(self, code: str) -> None:
        self.code = code if code in ERROR_MESSAGES else "invalid"
        super().__init__(ERROR_MESSAGES[self.code])


def error_message(code: object) -> str:
    return ERROR_MESSAGES.get(code if isinstance(code, str) else "", ERROR_MESSAGES["invalid"])


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ChatFile:
    name: str
    size: int
    chars: int
    blob: bytes = field(repr=False)

    @property
    def text(self) -> str:
        return zlib.decompress(self.blob).decode("utf-8")

    @property
    def excerpted(self) -> bool:
        return self.chars > MAX_CHAT_FILE_CONTENT_CHARS

    @classmethod
    def from_text(cls, name: str, text: str, size: int | None = None) -> ChatFile:
        encoded = text.encode("utf-8")
        return cls(name, len(encoded) if size is None else size, len(text),
                   zlib.compress(encoded, 6))


def format_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.0f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


# ────────────────────────── trích văn bản ──────────────────────────
def decode_file_name_header(values: list[str]) -> str:
    if len(values) != 1 or not _FILE_NAME_HEADER_RE.fullmatch(values[0]):
        raise ChatFileError("invalid_name")
    value = values[0]
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ChatFileError("invalid_name") from exc


def normalize_file_name(raw_name: object) -> str:
    name = str(raw_name or "").replace("\\", "/").split("/")[-1].strip()
    if (
        not name
        or len(name) > MAX_CHAT_FILE_NAME_CHARS
        or ".." in name
        or _BIDI_RE.search(name)
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in name)
    ):
        raise ChatFileError("invalid_name")
    lowered = name.lower()
    matched = next((ext for ext in ALLOWED_CHAT_FILE_EXTENSIONS if lowered.endswith(ext)), None)
    if matched is None or len(name) <= len(matched):
        raise ChatFileError("unsupported_type")
    return name


# Một lượt quét tuyến tính qua các thẻ cần thiết. [^<>]* dừng ở dấu '<' kế
# tiếp, nên XML cố tình hỏng (thẻ không đóng) cũng không làm regex quét lại
# phần đuôi tệp nhiều lần. Không dùng parser XML: không có thực thể ngoài/DTD.
_DOCX_TAG = re.compile(r"<(/?)w:(tab|br|cr|p|t)(?=[\s/>])[^<>]*>")


def extract_docx_text(raw: bytes | bytearray) -> str:
    """Trích văn bản thuần của word/document.xml mà không mở thực thể XML ngoài."""
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            if len(archive.infolist()) > MAX_DOCX_MEMBERS:
                raise ChatFileError("docx_invalid")
            info = archive.getinfo("word/document.xml")
            if info.file_size > MAX_DOCX_XML_BYTES:
                raise ChatFileError("docx_too_large")
            with archive.open(info) as member:
                # Đọc có trần phòng khi header khai sai kích thước giải nén.
                xml_bytes = member.read(MAX_DOCX_XML_BYTES + 1)
    except ChatFileError:
        raise
    except Exception as exc:
        raise ChatFileError("docx_invalid") from exc
    if len(xml_bytes) > MAX_DOCX_XML_BYTES:
        raise ChatFileError("docx_too_large")
    xml_text = xml_bytes.decode("utf-8", errors="replace")
    del xml_bytes

    paragraphs: list[str] = []
    parts: list[str] = []
    text_start: int | None = None

    def flush() -> None:
        line = "".join(parts).strip()
        parts.clear()
        if line:
            paragraphs.append(line)

    for match in _DOCX_TAG.finditer(xml_text):
        closing, tag = match.group(1), match.group(2)
        self_closing = match.group(0).endswith("/>")
        if tag == "t":
            if closing:
                if text_start is not None:
                    parts.append(html.unescape(xml_text[text_start:match.start()]))
                text_start = None
            elif not self_closing:
                text_start = match.end()
        elif closing:
            if tag == "p":
                flush()
        elif tag == "p":
            flush()
        elif tag == "tab":
            parts.append("\t")
        else:
            parts.append("\n")
    flush()
    return "\n".join(paragraphs)


def _clean_pdf_page(text: str) -> str:
    """Chữ trích từ PDF hay lẫn ký tự điều khiển/Bidi do bảng mã của font.

    Người dùng không sửa được bên trong PDF như với tệp văn bản, nên bỏ các ký
    tự đó thay vì từ chối cả tệp; kết quả vẫn đi qua ``normalize_text``.
    """
    text = unicodedata.normalize("NFC", text).replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL_RE.sub(" ", _BIDI_RE.sub("", text.replace("\f", "\n")))
    lines = [line.rstrip() for line in text.split("\n")]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def extract_pdf_text(
    raw: bytes | bytearray, *, clock: Callable[[], float] = time.monotonic
) -> str:
    """Trích lớp chữ từng trang, đánh dấu ``[Trang N]`` để AI trích dẫn đúng trang."""
    # Chuẩn PDF cho phép rác trước header, nhưng chỉ trong 1024 byte đầu.
    if b"%PDF-" not in bytes(raw[:1024]):
        raise ChatFileError("pdf_invalid")
    deadline = clock() + PDF_EXTRACT_SECONDS
    pages: list[str] = []
    total = 0
    try:
        reader = PdfReader(io.BytesIO(raw))
        if reader.is_encrypted:
            # PDF chỉ đặt mật khẩu chủ sở hữu (chặn in/sửa) mở được bằng mật khẩu rỗng.
            try:
                opened = reader.decrypt("")
            except Exception as exc:
                raise ChatFileError("pdf_encrypted") from exc
            if opened == PasswordType.NOT_DECRYPTED:
                raise ChatFileError("pdf_encrypted")
        if len(reader.pages) > MAX_PDF_PAGES:
            raise ChatFileError("pdf_too_large")
        for number, page in enumerate(reader.pages, start=1):
            if clock() > deadline:
                raise ChatFileError("pdf_too_large")
            text = _clean_pdf_page(page.extract_text() or "")
            if not text:
                continue
            total += len(text)
            if total > MAX_PDF_TEXT_CHARS:
                raise ChatFileError("pdf_too_large")
            pages.append(f"[Trang {number}]\n{text}")
    except ChatFileError:
        raise
    except Exception as exc:
        raise ChatFileError("pdf_invalid") from exc
    if not pages:
        raise ChatFileError("pdf_no_text")
    return "\n\n".join(pages)


def _decode_text(raw: bytes | bytearray) -> str:
    try:
        if raw.startswith(codecs.BOM_UTF8):
            return raw[len(codecs.BOM_UTF8):].decode("utf-8")
        # Notepad "Unicode" và PowerShell 5 Out-File ghi UTF-16 có BOM.
        if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            return raw.decode("utf-16")
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ChatFileError("not_utf8") from exc


def normalize_text(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if _BIDI_RE.search(normalized):
        raise ChatFileError("bidi")
    if _CONTROL_RE.search(normalized):
        raise ChatFileError("binary")
    cleaned = normalized.strip()
    if not cleaned:
        raise ChatFileError("empty")
    return cleaned


def parse_chat_file(raw_name: object, raw: bytes | bytearray) -> ChatFile:
    """Kiểm tra tên, dung lượng, định dạng rồi trích văn bản của một tệp tải lên."""
    name = normalize_file_name(raw_name)
    if len(raw) > MAX_CHAT_FILE_UPLOAD_BYTES:
        raise ChatFileError("too_large")
    if not raw:
        raise ChatFileError("empty")
    lowered = name.lower()
    if lowered.endswith(".docx"):
        text = extract_docx_text(raw)
    elif lowered.endswith(".pdf"):
        text = extract_pdf_text(raw)
    else:
        text = _decode_text(raw)
    return ChatFile.from_text(name, normalize_text(text), size=len(raw))


# ────────────────────────── kho tạm trong bộ nhớ ──────────────────────────
@dataclass
class _Pending:
    owner: str
    expires_at: float
    file: ChatFile = field(repr=False)


@dataclass
class _Staged:
    expires_at: float
    file: ChatFile = field(repr=False)


class ChatFileStore:
    """Tệp đã tải lên (chờ nhận) và tệp đã gắn vào ô soạn tin, có giới hạn.

    Khóa của tệp đã gắn là sha256 của token (một tệp có thể nằm dưới cả token
    cũ lẫn token đã xoay). Tổng dung lượng nén được tính một lần cho mỗi tệp;
    vượt ngân sách thì bỏ tệp cũ nhất, tệp chờ trước rồi tới tệp đã gắn.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_bytes: int = 96 * 1024 * 1024,
        max_pending: int = 64,
        max_staged: int = 512,
        pending_ttl: float = 600,
        staged_ttl: float = 3600,
        max_parallel: int = 2,
        uploads_per_window: int = 20,
        window_seconds: float = 300,
    ) -> None:
        self._clock = clock
        self._max_bytes = max_bytes
        self._max_pending = max_pending
        self._max_staged = max_staged
        self._pending_ttl = pending_ttl
        self._staged_ttl = staged_ttl
        self._uploads_per_window = uploads_per_window
        self._window = window_seconds
        self._pending: dict[str, _Pending] = {}
        self._staged: dict[str, _Staged] = {}
        self._recent: dict[str, deque[float]] = {}
        self._parsing = threading.BoundedSemaphore(max_parallel)
        self._lock = threading.Lock()

    # Một upload giữ tối đa 10 MiB thô cộng phần giải nén; giới hạn số upload
    # xử lý đồng thời để vài người dùng không đẩy tiến trình vượt mem_limit.
    def try_begin(self) -> bool:
        return self._parsing.acquire(blocking=False)

    def end(self) -> None:
        self._parsing.release()

    def admit(self, owner: str) -> bool:
        with self._lock:
            now = self._clock()
            recent = self._recent.setdefault(owner, deque())
            while recent and recent[0] <= now - self._window:
                recent.popleft()
            if len(recent) >= self._uploads_per_window:
                return False
            recent.append(now)
            for key in [key for key, rows in self._recent.items() if not rows]:
                del self._recent[key]
            if len(self._recent) > 4096:
                self._recent.pop(next(iter(self._recent)))
            return True

    def _prune(self, now: float) -> None:
        for key in [key for key, row in self._pending.items() if row.expires_at <= now]:
            del self._pending[key]
        for key in [key for key, row in self._staged.items() if row.expires_at <= now]:
            del self._staged[key]

    def _enforce_budget(self) -> None:
        while len(self._pending) > self._max_pending:
            del self._pending[next(iter(self._pending))]
        while len(self._staged) > self._max_staged:
            del self._staged[next(iter(self._staged))]
        while True:
            files = {id(row.file): len(row.file.blob)
                     for row in (*self._pending.values(), *self._staged.values())}
            if sum(files.values()) <= self._max_bytes:
                return
            table = self._pending if self._pending else self._staged
            if not table:
                return
            del table[next(iter(table))]

    def put_pending(self, owner: str, file: ChatFile) -> str:
        with self._lock:
            now = self._clock()
            self._prune(now)
            # Mỗi phiên chỉ giữ một tệp chờ: chọn tệp mới thì bỏ tệp cũ.
            for key in [key for key, row in self._pending.items() if row.owner == owner]:
                del self._pending[key]
            upload_id = secrets.token_urlsafe(24)
            self._pending[upload_id] = _Pending(owner, now + self._pending_ttl, file)
            self._enforce_budget()
            return upload_id

    def claim(self, upload_id: object, keys: Iterable[str]) -> ChatFile:
        keys = tuple(dict.fromkeys(keys))
        if not keys or not isinstance(upload_id, str) or not UPLOAD_ID_RE.fullmatch(upload_id):
            raise ChatFileError("expired")
        with self._lock:
            now = self._clock()
            self._prune(now)
            row = self._pending.pop(upload_id, None)
            if row is None or not any(secrets.compare_digest(row.owner, key) for key in keys):
                raise ChatFileError("expired")
            staged = _Staged(now + self._staged_ttl, row.file)
            for key in keys:
                self._staged.pop(key, None)
                self._staged[key] = staged
            self._enforce_budget()
            return row.file

    def stage(self, keys: Iterable[str], file: ChatFile) -> None:
        with self._lock:
            now = self._clock()
            self._prune(now)
            staged = _Staged(now + self._staged_ttl, file)
            for key in dict.fromkeys(keys):
                self._staged.pop(key, None)
                self._staged[key] = staged
            self._enforce_budget()

    def staged(self, keys: Iterable[str]) -> ChatFile | None:
        with self._lock:
            self._prune(self._clock())
            for key in keys:
                row = self._staged.get(key)
                if row is not None:
                    return row.file
        return None

    def clear(self, keys: Iterable[str]) -> None:
        keys = set(keys)
        with self._lock:
            for key in keys:
                self._staged.pop(key, None)
            for key in [key for key, row in self._pending.items() if row.owner in keys]:
                del self._pending[key]


CHAT_FILES = ChatFileStore()


# ────────────────────────── chọn đoạn gửi AI ──────────────────────────
EXCERPT_CHUNK_CHARS = 1_800
_GAP_MARKER = "\n\n[…]\n\n"
_HEADER_RESERVE = 400
_WORD_RE = re.compile(r"\w+")
_COMBINING_RE = re.compile(r"[̀-ͯ]")
# Từ khung câu hỏi, so trên chữ còn dấu (bỏ "bạn" nhưng giữ "bán", "bản").
_STOPWORDS = frozenset("""
là gì của và các những có không trong cho với được này đó kia về thế nào sao bao nhiêu
hãy giúp tôi mình bạn một như khi thì mà ở từ theo trên dưới đã sẽ đang nên cần phải hay
hoặc tại vì nếu nhé ạ ơi xin vui lòng cho biết tệp tài liệu file nội dung phân tích tóm tắt
trả lời dựa vừa tải lên đây đâu ai
the a an of and or to in on for with is are was were be what which who how why does do
this that it please tell me about from file document
""".split())


def _fold(text: str) -> str:
    return _COMBINING_RE.sub("", unicodedata.normalize("NFD", text.lower())).replace("đ", "d")


def _query_terms(question: str) -> list[str]:
    terms = []
    # NFC trước: \w không khớp dấu tổ hợp, chữ NFD (macOS) sẽ bị tách đôi.
    for word in _WORD_RE.findall(unicodedata.normalize("NFC", question.lower())):
        if word in _STOPWORDS or (len(word) < 2 and not word.isdigit()):
            continue
        terms.append(_fold(word))
    return terms[:32]


def _chunks(text: str, size: int = EXCERPT_CHUNK_CHARS) -> list[str]:
    """Cắt theo xuống dòng (hoặc khoảng trắng) gần nhất để đoạn không đứt giữa câu."""
    pieces, start, total = [], 0, len(text)
    while start < total:
        end = min(start + size, total)
        if end < total:
            cut = text.rfind("\n", start + size // 2, end)
            if cut == -1:
                cut = text.rfind(" ", start + size // 2, end)
            if cut != -1:
                end = cut + 1
        pieces.append(text[start:end])
        start = end
    return pieces


def _rank(chunks: list[str], terms: list[str]) -> list[int]:
    """BM25 trên từ đã bỏ dấu, cộng điểm khi hai từ liền nhau của câu hỏi đứng cạnh nhau."""
    wanted = set(terms)
    stats: list[tuple[Counter, int, list[str] | None]] = []
    df: Counter = Counter()
    total_len = 0
    for chunk in chunks:
        tokens = _WORD_RE.findall(_fold(chunk))
        tf = Counter(token for token in tokens if token in wanted)
        df.update(tf.keys())
        total_len += len(tokens)
        stats.append((tf, len(tokens), tokens if len(tf) > 1 else None))
    if not df:
        return []
    count = len(chunks)
    average = max(1.0, total_len / count)
    idf = {term: math.log(1 + (count - df[term] + 0.5) / (df[term] + 0.5)) for term in df}
    bigrams = [(a, b) for a, b in zip(terms, terms[1:], strict=False) if a in df and b in df and a != b]
    k1, b = 1.5, 0.75
    scored = []
    for index, (tf, length, tokens) in enumerate(stats):
        if not tf:
            continue
        score = sum(
            idf[term] * freq * (k1 + 1) / (freq + k1 * (1 - b + b * length / average))
            for term, freq in tf.items()
        )
        if tokens is not None and bigrams:
            pairs = set(zip(tokens, tokens[1:], strict=False))
            score += sum(0.5 * (idf[a] + idf[b]) for a, b in bigrams if (a, b) in pairs)
        scored.append((score, index))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [index for _score, index in scored]


def select_file_excerpts(
    text: str, question: str = "", budget: int = MAX_CHAT_FILE_CONTENT_CHARS
) -> str:
    """Trả nguyên văn nếu vừa ngân sách; nếu không, ghép các đoạn liên quan nhất.

    Luôn giữ đoạn mở đầu (tiêu đề/mục lục), rồi tới các đoạn điểm cao, đoạn kề
    của chúng, cuối cùng rải đều phần còn lại. Câu hỏi trống hoặc không khớp từ
    nào thì rải đều toàn tài liệu. Kết quả luôn dài không quá ``budget``.
    """
    if len(text) <= budget:
        return text
    chunks = _chunks(text)
    ranked = _rank(chunks, _query_terms(question or ""))
    available = budget - _HEADER_RESERVE
    slots = max(2, available // (EXCERPT_CHUNK_CHARS + len(_GAP_MARKER)))
    last = len(chunks) - 1
    spread = [round(i * last / (slots - 1)) for i in range(slots)]
    neighbours = [n for index in ranked for n in (index + 1, index - 1) if 0 <= n <= last]
    selected: set[int] = set()
    used = 0
    for index in (0, *ranked, *neighbours, *spread):
        if index in selected:
            continue
        cost = len(chunks[index]) + len(_GAP_MARKER)
        if used + cost > available:
            continue
        selected.add(index)
        used += cost

    pieces: list[str] = []
    previous = -1
    for index in sorted(selected):
        if index != previous + 1:
            pieces.append(_GAP_MARKER if pieces else "[…]\n\n")
        pieces.append(chunks[index])
        previous = index
    if previous != last:
        pieces.append(_GAP_MARKER.rstrip())
    mode = "liên quan nhất tới câu hỏi" if ranked else "rải đều toàn bộ tài liệu"
    header = (
        f"[SCAP: tài liệu gốc dài {len(text):,} ký tự, vượt giới hạn {budget:,} ký tự "
        f"cho mỗi lần gửi AI. Dưới đây là {len(selected)}/{len(chunks)} đoạn trích "
        f"{mode}, giữ nguyên thứ tự; dấu […] đánh dấu phần đã lược bớt.]\n\n"
    )
    return (header + "".join(pieces))[:budget].strip()
