# Kịch bản demo

## Chuẩn bị

```bash
cp .env.example .env
python scripts/generate_secrets.py  # điền vào .env
uv sync --group dev
uv run python run_app.py
```

Mở `http://127.0.0.1:8000`.

## 1. Đăng ký và đăng nhập

1. Nhập username `demo-user` và password `DemoPass123!` → bấm **Tạo tài khoản mới**.
2. Toast thông báo thành công → bấm **Đăng nhập**.
3. Giao diện chuyển sang dashboard chính với sidebar và chat area.
4. Chú ý: token chỉ giữ trong memory, không lưu localStorage.

## 2. Tạo phiên và gửi tin nhắn

1. Bấm **＋ Phiên hội thoại mới** → nhập tên phiên.
2. Gõ tin nhắn, bấm **Gửi** hoặc nhấn Enter.
3. Typing indicator (3 chấm) xuất hiện khi chờ AI phản hồi.
4. Tin nhắn hiển thị dạng bubble với avatar và timestamp.

## 3. Xem dữ liệu mã hóa AES-GCM

1. Chọn tab **🔒 AES‑GCM**.
2. Nội dung hiển thị là ciphertext, nonce, key_version — plaintext không xuất hiện.
3. Minh chứng dữ liệu trong DB được mã hóa hoàn toàn.

## 4. Tìm kiếm trong tin nhắn đã mã hóa

1. Quay lại tab **💬 Chat**.
2. Dùng thanh tìm kiếm phía trên — hệ thống giải mã server-side rồi lọc.
3. Toast hiển thị số kết quả.

## 5. Demo bảo mật: IDOR

1. Mở tab ẩn danh mới, đăng ký user `attacker`.
2. Thử truy cập session ID của `demo-user` → nhận 404 (không 403, giảm enumeration).

## 6. Demo admin dashboard

1. Đăng nhập admin (bootstrap từ `.env`).
2. Chọn tab **📋 Audit** → xem bảng audit log có thời gian, sự kiện, outcome, IP.
3. Chọn tab **📊 Stats** → xem 6 stat cards: users, sessions, messages, failures.
4. Chọn tab **⚠️ Alerts** → xem cảnh báo bảo mật real-time.

## 7. Demo rate limiting

1. Đăng nhập sai 6 lần liên tiếp → nhận 429 với Retry-After.
2. Toast hiển thị lỗi.

## 8. Đổi mật khẩu

1. Bấm nút **🔑** trên topbar → modal mở ra.
2. Nhập mật khẩu cũ và mới → token cũ bị vô hiệu, yêu cầu đăng nhập lại.

## 9. Chạy kiểm thử tự động

```bash
uv run pytest --cov=src.app --cov-report=term-missing
uv run bandit -r src/app
uv run pip-audit
```

## 10. So sánh với legacy

```bash
uv run python run_legacy_app.py
```

Mở Streamlit → chỉ ra Vigenère yếu, đơn người dùng, không audit.
