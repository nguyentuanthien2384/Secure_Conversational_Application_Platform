"""Chat attachments up to 10 MiB: extraction, upload route, edge limits, excerpts."""

from __future__ import annotations

import base64
import codecs
import io
import re
import shutil
import subprocess
import time
import zipfile
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.app import chat_files
from src.app.chat_files import (
    CHAT_FILE_UPLOAD_PATH,
    ERROR_MESSAGES,
    MAX_CHAT_FILE_UPLOAD_BYTES,
    ChatFile,
    ChatFileError,
    ChatFileStore,
    decode_file_name_header,
    extract_docx_text,
    parse_chat_file,
    select_file_excerpts,
    token_digest,
)
from src.app.request_limits import (
    MAX_BODY_BYTES,
    RequestLimitsMiddleware,
    StreamedBodyLimitExceeded,
)
from src.app.schemas import MAX_CHAT_FILE_CONTENT_CHARS, MessageSend
from src.app.ui_session import COOKIE_NAME, BrowserSessionStore, register_ui_session_routes

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://chat.example"


def _docx(xml: str | bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", xml)
        # Embedded media is what makes real .docx files large.
        archive.writestr("word/media/image1.png", b"\x89PNG" + bytes(range(256)) * 64)
    return buffer.getvalue()


def _pdf(*pages: str) -> bytes:
    """PDF tối thiểu hợp lệ, mỗi trang một dòng Helvetica (chỉ ký tự WinAnsi)."""
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
    ]
    kids = []
    for text in pages:
        escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        stream = f"BT /F1 12 Tf 72 720 Td ({escaped}) Tj ET" if text else ""
        objects.append(
            f"<< /Length {len(stream.encode('latin-1'))} >>\nstream\n{stream}\nendstream"
        )
        objects.append(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {len(objects)} 0 R >>"
        )
        kids.append(f"{len(objects)} 0 R")
    objects[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>"
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n{body}\nendobj\n".encode("latin-1")
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    out += "".join(f"{offset:010d} 00000 n \n" for offset in offsets).encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def _encrypted_pdf(user_password: str, text: str = "Mat khau") -> bytes:
    from pypdf import PdfWriter

    writer = PdfWriter(clone_from=io.BytesIO(_pdf(text)))
    writer.encrypt(user_password=user_password, owner_password="chu-so-huu")
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


def _code(callable_, *args) -> str:
    with pytest.raises(ChatFileError) as caught:
        callable_(*args)
    return caught.value.code


def _name_header(name: str) -> str:
    return base64.urlsafe_b64encode(name.encode("utf-8")).decode("ascii").rstrip("=")


# ────────────────────────── extraction ──────────────────────────
def test_docx_text_keeps_paragraphs_tabs_breaks_and_entities():
    xml = (
        '<w:document><w:body>'
        '<w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:t>Báo cáo quý 3</w:t></w:r></w:p>'
        '<w:p><w:r><w:t xml:space="preserve">Doanh thu </w:t></w:r><w:r><w:t>tăng 25%.</w:t></w:r></w:p>'
        '<w:tbl><w:tr><w:tc><w:p><w:r><w:t>A</w:t><w:tab/><w:t>B&amp;C</w:t>'
        '<w:br/><w:t>dòng 2</w:t></w:r></w:p></w:tc></w:tr></w:tbl>'
        '<w:p><w:r><w:delText>đã xóa</w:delText><w:instrText>PAGE</w:instrText></w:r></w:p>'
        '<w:p/></w:body></w:document>'
    )
    assert extract_docx_text(_docx(xml)) == "Báo cáo quý 3\nDoanh thu tăng 25%.\nA\tB&C\ndòng 2"


def test_docx_scan_is_linear_on_unclosed_tags():
    # Thousands of unterminated tags made the old lazy regex rescan the tail.
    hostile = "<w:document>" + "<w:p <w:t " * 200_000 + "</w:document>"
    started = time.perf_counter()
    assert extract_docx_text(_docx(hostile)) == ""
    assert time.perf_counter() - started < 5


def test_docx_bombs_and_garbage_are_rejected(monkeypatch):
    monkeypatch.setattr(chat_files, "MAX_DOCX_XML_BYTES", 4096)
    bomb = _docx("<w:p><w:t>" + "a" * 10_000 + "</w:t></w:p>")
    assert _code(extract_docx_text, bomb) == "docx_too_large"
    assert _code(extract_docx_text, b"PK\x03\x04 not a zip") == "docx_invalid"
    no_body = io.BytesIO()
    with zipfile.ZipFile(no_body, "w") as archive:
        archive.writestr("word/other.xml", "<x/>")
    assert _code(extract_docx_text, no_body.getvalue()) == "docx_invalid"


def test_pdf_text_is_extracted_per_page_with_page_markers():
    raw = _pdf("Bao cao quy 3 (ban nhap)", "", "Doanh thu tang 25% - cafe")
    parsed = parse_chat_file("báo cáo.PDF", raw)
    # Trang trống bị bỏ qua nhưng số trang vẫn theo đúng tệp gốc.
    assert parsed.text == (
        "[Trang 1]\nBao cao quy 3 (ban nhap)\n\n[Trang 3]\nDoanh thu tang 25% - cafe"
    )
    assert (parsed.name, parsed.size, parsed.chars) == ("báo cáo.PDF", len(raw), len(parsed.text))


def test_pdf_page_text_drops_control_and_bidi_characters():
    # Font PDF hay ánh xạ glyph ra ký tự điều khiển; người dùng không sửa được.
    assert chat_files._clean_pdf_page("A\x00B‮C\fD\r\n\n\n\nE  ") == "A BC\nD\n\nE"


def test_pdf_with_owner_password_only_opens_and_user_password_is_refused():
    assert parse_chat_file("han_che_in.pdf", _encrypted_pdf("")).text == "[Trang 1]\nMat khau"
    assert _code(parse_chat_file, "khoa.pdf", _encrypted_pdf("bi-mat")) == "pdf_encrypted"


def test_scanned_or_broken_pdfs_fail_with_fixed_codes():
    assert _code(parse_chat_file, "scan.pdf", _pdf("", "")) == "pdf_no_text"
    assert _code(parse_chat_file, "fake.pdf", b"MZ\x90\x00 not a pdf") == "pdf_invalid"
    truncated = _pdf("Bao cao")[:40]
    assert _code(parse_chat_file, "cut.pdf", truncated) == "pdf_invalid"


def test_pdf_extraction_is_bounded_by_pages_text_and_time(monkeypatch):
    raw = _pdf("mot", "hai", "ba")
    monkeypatch.setattr(chat_files, "MAX_PDF_PAGES", 2)
    assert _code(parse_chat_file, "dai.pdf", raw) == "pdf_too_large"
    monkeypatch.setattr(chat_files, "MAX_PDF_PAGES", 10)
    monkeypatch.setattr(chat_files, "MAX_PDF_TEXT_CHARS", 5)  # "mot" + "hai" = 6
    assert _code(parse_chat_file, "dai.pdf", raw) == "pdf_too_large"
    monkeypatch.setattr(chat_files, "MAX_PDF_TEXT_CHARS", 1_000)
    ticks = iter([0.0, 1.0, chat_files.PDF_EXTRACT_SECONDS + 1])
    with pytest.raises(ChatFileError) as caught:
        chat_files.extract_pdf_text(raw, clock=lambda: next(ticks))
    assert caught.value.code == "pdf_too_large"


@pytest.mark.parametrize(("raw", "expected"), [
    ("Xin chào\r\nthế giới\r".encode(), "Xin chào\nthế giới"),
    (codecs.BOM_UTF8 + "có BOM".encode(), "có BOM"),
    ("Notepad Unicode".encode("utf-16"), "Notepad Unicode"),
    (codecs.BOM_UTF16_BE + "big endian".encode("utf-16-be"), "big endian"),
])
def test_text_files_decode_utf8_and_utf16_with_bom(raw, expected):
    parsed = parse_chat_file("ghi_chu.txt", raw)
    assert (parsed.name, parsed.text, parsed.size, parsed.chars) == (
        "ghi_chu.txt", expected, len(raw), len(expected)
    )


@pytest.mark.parametrize(("name", "raw", "code"), [
    ("a.txt", b"\xff\xfe\xfd not utf8"[2:], "not_utf8"),
    ("a.txt", b"header\x00\x01binary", "binary"),
    ("a.txt", "safe \u202e txt.exe".encode(), "bidi"),
    ("a.txt", b"  \n\t ", "empty"),
    ("a.txt", b"", "empty"),
    ("a.pptx", b"PK\x03\x04", "unsupported_type"),
    ("a.pdf", b"%PDF-1.7", "pdf_invalid"),
    (".txt", b"x", "unsupported_type"),
    ("a..txt", b"x", "invalid_name"),
    ("x" * 181 + ".txt", b"x", "invalid_name"),
    ("bad\u2066name.txt", b"x", "invalid_name"),
    ("tab\tname.txt", b"x", "invalid_name"),
])
def test_invalid_files_fail_with_fixed_codes(name, raw, code):
    assert _code(parse_chat_file, name, raw) == code


def test_ten_mebibytes_is_accepted_and_one_byte_more_is_not():
    line = b"Dong du lieu CSV;123;456\n"
    raw = (line * (MAX_CHAT_FILE_UPLOAD_BYTES // len(line) + 1))[:MAX_CHAT_FILE_UPLOAD_BYTES]
    parsed = parse_chat_file("C:\\Users\\me\\du_lieu.csv", raw)
    assert parsed.name == "du_lieu.csv" and parsed.size == MAX_CHAT_FILE_UPLOAD_BYTES
    # Stored compressed: a 10 MiB text costs far less than 10 MiB of memory.
    assert len(parsed.blob) < MAX_CHAT_FILE_UPLOAD_BYTES // 20
    assert _code(parse_chat_file, "du_lieu.csv", raw + b"x") == "too_large"


def test_file_name_header_roundtrips_vietnamese_and_rejects_anything_else():
    assert decode_file_name_header([_name_header("Báo cáo tài chính.docx")]) == "Báo cáo tài chính.docx"
    for values in ([], ["a", "b"], ["not base64!"], ["x" * 1025], [_name_header("x")[:-1] + "+"]):
        assert _code(decode_file_name_header, values) == "invalid_name"
    assert _code(decode_file_name_header, ["_w"]) == "invalid_name"  # invalid UTF-8


def test_unknown_error_codes_map_to_a_generic_message():
    assert ChatFileError("<script>").code == "invalid"
    assert chat_files.error_message({"x": 1}) == ERROR_MESSAGES["invalid"]
    assert "10 MB" in ERROR_MESSAGES["too_large"]


# ────────────────────────── in-memory store ──────────────────────────
def _file(text: str = "nội dung", name: str = "a.txt") -> ChatFile:
    return ChatFile.from_text(name, text)


def test_store_binds_uploads_to_their_owner_and_ids_are_single_use():
    store = ChatFileStore()
    owner, other = token_digest("tab-token"), token_digest("other-token")
    upload_id = store.put_pending(owner, _file("bí mật"))
    assert re.fullmatch(r"[A-Za-z0-9_-]{32}", upload_id)
    with pytest.raises(ChatFileError, match="hết hạn"):
        store.claim(upload_id, [other])
    with pytest.raises(ChatFileError):
        store.claim(upload_id, [owner])
    upload_id = store.put_pending(owner, _file("bí mật"))
    # A rotated token: the tab presents both its old and current digests.
    claimed = store.claim(upload_id, ["old-digest", owner])
    assert store.staged(["old-digest"]) is claimed and store.staged([owner]) is claimed
    assert claimed.text == "bí mật"
    for bad in (None, "", "../" * 11, upload_id):
        with pytest.raises(ChatFileError):
            store.claim(bad, [owner])


def test_store_keeps_one_pending_upload_per_login_and_clear_drops_everything():
    store = ChatFileStore()
    owner = token_digest("t")
    first = store.put_pending(owner, _file("1"))
    second = store.put_pending(owner, _file("2"))
    with pytest.raises(ChatFileError):
        store.claim(first, [owner])
    third = store.put_pending(owner, _file("3"))
    store.stage([owner], _file("staged"))
    store.clear([owner])
    assert store.staged([owner]) is None
    for upload_id in (second, third):
        with pytest.raises(ChatFileError):
            store.claim(upload_id, [owner])


def test_store_expires_entries_and_enforces_its_byte_budget():
    now = [100.0]
    store = ChatFileStore(clock=lambda: now[0], pending_ttl=10, staged_ttl=20, max_bytes=4096)
    owner = token_digest("t")
    store.stage([owner], _file("x"))
    upload_id = store.put_pending(owner, _file("y"))
    now[0] += 11
    with pytest.raises(ChatFileError):
        store.claim(upload_id, [owner])
    assert store.staged([owner]) is not None
    now[0] += 10
    assert store.staged([owner]) is None

    import os
    noisy = lambda: ChatFile.from_text("n.txt", os.urandom(1500).hex())  # noqa: E731
    store.stage(["a"], noisy())
    store.stage(["b"], noisy())
    store.stage(["c"], noisy())
    total = sum(len(store.staged([key]).blob) for key in "abc" if store.staged([key]))
    assert total <= 4096 and store.staged(["c"]) is not None and store.staged(["a"]) is None


def test_store_rate_limits_and_caps_parallel_parsing():
    now = [0.0]
    store = ChatFileStore(clock=lambda: now[0], uploads_per_window=2, window_seconds=60,
                          max_parallel=1)
    assert store.admit("o") and store.admit("o") and not store.admit("o")
    assert store.admit("someone-else")
    now[0] += 61
    assert store.admit("o")
    assert store.try_begin() and not store.try_begin()
    store.end()
    assert store.try_begin()
    store.end()


# ────────────────────────── excerpts for the AI ──────────────────────────
def _long_document() -> tuple[str, str]:
    paragraphs = [f"Phần {i}. Quy trình vận hành tiêu chuẩn số {i} của đơn vị.\n" for i in range(3000)]
    needle = "Chỉ tiêu doanh thu năm 2025 của chi nhánh Đà Nẵng là 812 tỷ đồng.\n"
    paragraphs.insert(1700, needle)
    return "MỤC LỤC TÀI LIỆU\n" + "".join(paragraphs) + "KẾT LUẬN CUỐI TÀI LIỆU\n", needle.strip()


def test_short_text_is_sent_verbatim():
    assert select_file_excerpts("ngắn gọn", "câu hỏi") == "ngắn gọn"


@pytest.mark.parametrize("question", [
    "Chỉ tiêu doanh thu năm 2025 ở Đà Nẵng?",
    "chi tieu doanh thu nam 2025 o da nang",  # typed without diacritics
    "DOANH THU ĐÀ NẴNG",
])
def test_long_text_sends_the_passage_matching_the_question(question):
    text, needle = _long_document()
    excerpt = select_file_excerpts(text, question)
    assert len(excerpt) <= MAX_CHAT_FILE_CONTENT_CHARS
    assert needle in excerpt
    assert excerpt.startswith("[SCAP: tài liệu gốc dài") and "liên quan nhất" in excerpt
    assert "MỤC LỤC TÀI LIỆU" in excerpt and "[…]" in excerpt
    # Exactly what the REST API accepts for an attachment.
    MessageSend(content="Hỏi", file_name="a.txt", file_content=excerpt)


def test_generic_question_samples_the_whole_document_in_order():
    text, _needle = _long_document()
    excerpt = select_file_excerpts(text, "")
    assert "rải đều toàn bộ tài liệu" in excerpt
    assert "MỤC LỤC TÀI LIỆU" in excerpt and "KẾT LUẬN CUỐI TÀI LIỆU" in excerpt
    numbers = [int(n) for n in re.findall(r"Phần (\d+)\.", excerpt)]
    assert numbers == sorted(numbers) and numbers[-1] - numbers[0] > 2000


@pytest.mark.parametrize("size", [30_001, 45_000, 1_000_000])
def test_excerpt_never_exceeds_budget_even_without_line_breaks(size):
    text = ("từkhóa " * size)[:size]
    for question in ("từkhóa", "", "không khớp gì"):
        assert len(select_file_excerpts(text, question)) <= MAX_CHAT_FILE_CONTENT_CHARS


# ────────────────────────── upload route ──────────────────────────
@pytest.fixture
def clock():
    return [1_900_000_000.0]


@pytest.fixture
def session_store(clock):
    return BrowserSessionStore(clock=lambda: clock[0])


def _client(session_store, files, *, limits=False):
    app = FastAPI()
    register_ui_session_routes(app, session_store, chat_files=files)
    if limits:
        app.add_middleware(RequestLimitsMiddleware)
    return TestClient(app, base_url=ORIGIN)


def _login(client, session_store, clock, token="jwt-token"):
    ticket = session_store.issue(token, clock[0] + 600)
    response = client.post("/api/ui-session/attach", json={"ticket": ticket},
                           headers={"X-SCAP-UI": "1", "Origin": ORIGIN})
    assert response.status_code == 204
    return token


def _upload(client, body, name="tài liệu.txt", **headers):
    return client.post(CHAT_FILE_UPLOAD_PATH, content=body, headers={
        "X-SCAP-UI": "1", "Origin": ORIGIN, "Content-Type": "application/octet-stream",
        "X-SCAP-File-Name": _name_header(name), **headers,
    })


def test_upload_route_parses_and_hands_back_a_claimable_id(session_store, clock):
    files = ChatFileStore()
    with _client(session_store, files, limits=True) as client:
        token = _login(client, session_store, clock)
        docx = _docx("<w:p><w:r><w:t>" + "Nội dung hợp đồng. " * 120_000 + "</w:t></w:r></w:p>")
        big_text = ("Dòng dữ liệu báo cáo\n" * 300_000).encode()
        assert len(big_text) > 4 * MAX_BODY_BYTES
        for name, body in (("hop_dong.docx", docx), ("bao cao.csv", big_text)):
            response = _upload(client, body, name)
            assert response.status_code == 200, response.text
            assert response.headers["cache-control"] == "no-store"
            data = response.json()
            assert set(data) == {"upload_id", "name", "size", "chars"}
            assert (data["name"], data["size"]) == (name, len(body))
            claimed = files.claim(data["upload_id"], [token_digest(token)])
            assert claimed.chars == data["chars"] and claimed.text.startswith(
                "Nội dung hợp đồng." if name.endswith(".docx") else "Dòng dữ liệu"
            )
        # Every other route keeps the 1 MiB ceiling.
        response = client.post("/api/ui-session/attach", content=b"x" * (MAX_BODY_BYTES + 1),
                               headers={"X-SCAP-UI": "1", "Content-Type": "application/json"})
        assert response.status_code == 413


def test_upload_route_extracts_pdf_text_and_reports_pdf_errors(session_store, clock):
    files = ChatFileStore()
    with _client(session_store, files, limits=True) as client:
        token = _login(client, session_store, clock)
        response = _upload(client, _pdf("Hop dong thue nha", "Dieu 2: gia thue"), "hợp đồng.pdf")
        assert response.status_code == 200, response.text
        claimed = files.claim(response.json()["upload_id"], [token_digest(token)])
        assert claimed.text == "[Trang 1]\nHop dong thue nha\n\n[Trang 2]\nDieu 2: gia thue"
        MessageSend(content="Hỏi", file_name=claimed.name, file_content=claimed.text)
        for body, code in ((_encrypted_pdf("bi-mat"), "pdf_encrypted"),
                           (_pdf(""), "pdf_no_text")):
            response = _upload(client, body, "tai lieu.pdf")
            assert (response.status_code, response.json()["code"]) == (422, code)


@pytest.mark.parametrize(("headers", "status", "code"), [
    ({"X-SCAP-UI": ""}, 403, None),
    ({"Origin": "https://evil.example"}, 403, None),
    ({"Sec-Fetch-Site": "cross-site"}, 403, None),
    ({"Content-Type": "multipart/form-data"}, 415, None),
    ({"X-SCAP-File-Name": "%2E%2E"}, 400, "invalid_name"),
    ({"X-SCAP-File-Name": _name_header("virus.exe")}, 400, "unsupported_type"),
])
def test_upload_route_rejects_before_reading_the_body(session_store, clock, headers, status, code):
    files = ChatFileStore()
    with _client(session_store, files) as client:
        _login(client, session_store, clock)
        response = _upload(client, b"hello", **headers)
        assert response.status_code == status
        if code:
            assert response.json()["code"] == code
        assert not files._pending


def test_upload_route_requires_the_browser_session_cookie(session_store, clock):
    files = ChatFileStore()
    with _client(session_store, files) as client:
        response = _upload(client, b"hello")
        assert response.status_code == 401 and response.json()["code"] == "session"
        client.cookies.set(COOKIE_NAME, "a" * 43)
        assert _upload(client, b"hello").json()["code"] == "session"


def test_upload_route_bounds_size_rate_and_concurrency(session_store, clock):
    files = ChatFileStore(uploads_per_window=3, max_parallel=1)
    with _client(session_store, files) as client:
        _login(client, session_store, clock)

        def chunked():
            for _ in range(11):
                yield b"a" * (1024 * 1024)

        response = _upload(client, chunked())
        assert response.status_code == 413 and response.json()["code"] == "too_large"
        response = _upload(client, b"\x00\x01\x02 binary")
        assert response.status_code == 422 and response.json()["code"] == "binary"
        assert files.try_begin()
        try:
            assert _upload(client, b"ok").json()["code"] == "busy"
        finally:
            files.end()
        response = _upload(client, b"ok")
        assert response.status_code == 429 and response.json()["code"] == "rate_limited"


def test_middleware_streams_only_the_exact_upload_route():
    import asyncio

    def run(path, method, chunks, headers=()):
        sent, seen = [], []
        remaining = iter(chunks)

        async def downstream(scope, receive, send):
            while True:
                message = await receive()
                seen.append(message)
                if not message.get("more_body"):
                    break
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        async def receive():
            return next(remaining)

        async def send(message):
            sent.append(message)

        scope = {"type": "http", "path": path, "method": method, "headers": list(headers),
                 "query_string": b""}
        try:
            asyncio.run(RequestLimitsMiddleware(downstream)(scope, receive, send))
        except StreamedBodyLimitExceeded:
            sent.append("backstop")
        return sent, seen

    two_mib = [{"type": "http.request", "body": b"x" * (2 * MAX_BODY_BYTES), "more_body": False}]
    content_type = ((b"content-type", b"application/octet-stream"),)
    sent, seen = run(CHAT_FILE_UPLOAD_PATH, "POST", two_mib, content_type)
    assert sent[0]["status"] == 204 and len(seen[0]["body"]) == 2 * MAX_BODY_BYTES
    for path, method in ((CHAT_FILE_UPLOAD_PATH + "/", "POST"), (CHAT_FILE_UPLOAD_PATH, "PATCH"),
                         ("/api/sessions/x/messages", "POST")):
        sent, _ = run(path, method, two_mib, content_type)
        assert sent[0]["status"] == 413, (path, method)
    too_long = ((b"content-length", str(MAX_CHAT_FILE_UPLOAD_BYTES + 1).encode()),)
    sent, seen = run(CHAT_FILE_UPLOAD_PATH, "POST", two_mib, too_long)
    assert sent[0]["status"] == 413 and not seen
    # A route that ignored its own limit cannot keep reading past it.
    over = [{"type": "http.request", "body": b"x" * MAX_CHAT_FILE_UPLOAD_BYTES, "more_body": True},
            {"type": "http.request", "body": b"x", "more_body": True},
            {"type": "http.request", "body": b"x", "more_body": False}]
    sent, seen = run(CHAT_FILE_UPLOAD_PATH, "POST", over, content_type)
    assert sent == ["backstop"] and len(seen) == 2


# ────────────────────────── edge proxy and browser bridge ──────────────────────────
def test_caddy_allows_ten_mebibytes_only_on_the_upload_route():
    for name in ("Caddyfile", "Caddyfile.shared-proxy"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert f"@chat_file_upload path {CHAT_FILE_UPLOAD_PATH}\n" in text, name
        assert f"@ordinary_body not path {CHAT_FILE_UPLOAD_PATH}\n" in text, name
        upload = re.search(r"request_body @chat_file_upload \{\s*max_size (\S+)\s*\}", text)
        ordinary = re.search(r"request_body @ordinary_body \{\s*max_size (\S+)\s*\}", text)
        assert upload[1] == "10MiB" and ordinary[1] == "1MB", name
        # No unmatched request_body may wrap the upload route with the 1MB limit.
        assert len(re.findall(r"^\s*request_body\b", text, re.MULTILINE)) == 2, name


def test_bridge_and_picker_agree_with_server_limits_and_codes():
    from src.app.gradio_ui import CHAT_FILE_PICKER_HTML

    script = (ROOT / "src/app/ui_assets/session_bridge.js").read_text(encoding="utf-8")
    assert f'const CHAT_FILE_UPLOAD_PATH = "{CHAT_FILE_UPLOAD_PATH}";' in script
    assert "const DEFAULT_CHAT_FILE_MAX_BYTES = 10 * 1024 * 1024;" in script
    assert f'data-scap-max-bytes="{MAX_CHAT_FILE_UPLOAD_BYTES}"' in CHAT_FILE_PICKER_HTML
    assert "(tối đa 10 MB)" in CHAT_FILE_PICKER_HTML
    codes = re.search(r"CHAT_FILE_ERRORS = new Set\(\[(.*?)\]\)", script, re.DOTALL)[1]
    assert set(re.findall(r'"([a-z_]+)"', codes)) <= set(ERROR_MESSAGES)
    # Mã máy chủ trả mà bridge không biết sẽ bị đổi thành "upload_failed" chung chung.
    server_codes = {code for code in ERROR_MESSAGES if code.startswith(("pdf_", "docx_"))}
    assert server_codes <= set(re.findall(r'"([a-z_]+)"', codes))
    assert ".pdf" in CHAT_FILE_PICKER_HTML
    assert {"read_failed", "upload_failed"} <= set(ERROR_MESSAGES)
    assert "base64:" not in script and "arrayBuffer" not in script


def test_bridge_uploads_raw_file_with_progress_and_hands_over_only_the_id():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is unavailable; browser QA covers the static bridge.")
    script = r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
let change, requests = [], clicks = 0;
const hint = {textContent: 'idle hint', dataset: {}};
const label = {attrs: {}, setAttribute(k, v) { this.attrs[k] = v; }};
const bar = {querySelector: sel => sel === '[data-scap-file-label]' ? hint : label};
const payloadBox = {value: '', dispatchEvent() {}};
class HTMLInputElement {
  constructor(file) { this.id = 'chat-file-input'; this.files = [file]; this.value = 'C:\\fake';
    this.disabled = false; this.dataset = {scapMaxBytes: '1000'}; }
  closest() { return bar; }
}
class XMLHttpRequest {
  constructor() { this.headers = {}; this.upload = {}; requests.push(this); }
  open(method, url) { this.method = method; this.url = url; }
  setRequestHeader(k, v) { this.headers[k] = v; }
  send(body) { this.body = body; }
}
const document = {readyState: 'complete', body: {},
  getElementById: () => null, querySelectorAll: () => [],
  querySelector: sel => sel.startsWith('#chat-file-payload') ? payloadBox
    : sel === '#btn-chat-file-stage' ? {click: () => clicks++} : null,
  addEventListener: (name, fn) => { if (name === 'change') change = fn; }};
const context = {document, Element: class {}, HTMLInputElement, XMLHttpRequest, URL, Promise,
  Set, WeakMap, TextEncoder, btoa, Event: class { constructor(type) { this.type = type; } },
  performance: {now: () => 0}, MutationObserver: class { observe() {} },
  setInterval: () => 0, setTimeout: fn => fn(), navigator: {}};
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), context);
const tick = () => new Promise(resolve => setImmediate(resolve));
(async () => {
  // Over the limit advertised by the server markup: no request at all.
  change({target: new HTMLInputElement({name: 'big.txt', size: 1001})});
  await tick();
  assert.equal(requests.length, 0);
  assert.deepEqual(JSON.parse(payloadBox.value), {error: 'too_large'});

  const file = {name: 'Báo cáo.docx', size: 900};
  const picker = new HTMLInputElement(file);
  change({target: picker});
  await tick();
  const xhr = requests[0];
  assert.equal(xhr.method, 'POST');
  assert.equal(xhr.url, '/api/ui-session/chat-file');
  assert.equal(xhr.body, file);  // the File itself, streamed by the browser
  assert.equal(xhr.headers['Content-Type'], 'application/octet-stream');
  assert.equal(xhr.headers['X-SCAP-UI'], '1');
  assert.equal(Buffer.from(xhr.headers['X-SCAP-File-Name'], 'base64url').toString(), 'Báo cáo.docx');
  assert.equal(picker.value, '');
  assert.equal(picker.disabled, true);
  xhr.upload.onprogress({lengthComputable: true, loaded: 450, total: 900});
  assert.equal(hint.textContent, 'Đang tải tệp lên… 50%');
  // A second pick while busy is ignored.
  change({target: new HTMLInputElement({name: 'b.txt', size: 1})});
  await tick();
  assert.equal(requests.length, 1);
  xhr.status = 200; xhr.response = {upload_id: 'A'.repeat(32), name: 'x', chars: 1};
  xhr.onload();
  await tick();
  assert.deepEqual(JSON.parse(payloadBox.value), {upload_id: 'A'.repeat(32)});
  assert.equal(hint.textContent, 'idle hint');
  assert.equal(picker.disabled, false);
  assert.equal(label.attrs['aria-disabled'], 'false');

  // Server error codes pass through only when known; anything else is generic.
  for (const [status, response, expected] of [
      [422, {code: 'binary'}, 'binary'], [400, {code: '<img>'}, 'upload_failed'],
      [413, null, 'too_large'], [200, {upload_id: '../x'}, 'upload_failed']]) {
    change({target: new HTMLInputElement({name: 'a.txt', size: 5})});
    await tick();
    const request = requests.at(-1);
    request.status = status; request.response = response; request.onload();
    await tick();
    assert.deepEqual(JSON.parse(payloadBox.value), {error: expected});
  }
  change({target: new HTMLInputElement({name: 'a.txt', size: 5})});
  await tick();
  requests.at(-1).onerror();
  await tick();
  assert.deepEqual(JSON.parse(payloadBox.value), {error: 'upload_failed'});
  assert.ok(clicks >= 7);
})().catch(err => { console.error(err); process.exitCode = 1; });
"""
    bridge = ROOT / "src/app/ui_assets/session_bridge.js"
    result = subprocess.run([node, "-e", script, str(bridge)], capture_output=True,
                            text=True, encoding="utf-8", timeout=60)
    assert result.returncode == 0, result.stderr + result.stdout
