# Ma trận yêu cầu bảo mật

| Mã | Yêu cầu | Trạng thái | Vị trí |
|---|---|---|---|
| SR-AUTH-01 | Không lưu mật khẩu plaintext | Đạt | `PasswordService`, bảng `users` |
| SR-AUTH-02 | Thông báo login không phân biệt user tồn tại | Đạt | `/api/auth/login` |
| SR-AUTH-03 | Giới hạn brute force | Đạt cho single instance | `SlidingWindowRateLimiter` |
| SR-AUTH-04 | Password complexity (uppercase, lowercase, digit) | Đạt | `RegisterRequest.validate_password` |
| SR-AUTH-05 | Blocklist mật khẩu phổ biến mở rộng | Đạt | `RegisterRequest.validate_password` |
| SR-AUTHZ-01 | User chỉ đọc/sửa session của mình | Đạt | `require_owned_session` |
| SR-AUTHZ-02 | Admin endpoint chỉ role admin | Đạt | `admin_user` dependency |
| SR-CRYPTO-01 | Message mã hóa authenticated encryption | Đạt | `CryptoService`, AES-GCM |
| SR-CRYPTO-02 | Key không lưu cùng database | Đạt | `MASTER_ENCRYPTION_KEY` env |
| SR-INPUT-01 | Validate server-side | Đạt | Pydantic schemas |
| SR-XSS-01 | Không render input bằng HTML | Đạt | `textContent` trong `app.js` |
| SR-LOG-01 | Ghi auth success/failure và authz denied | Đạt | `audit_events` |
| SR-LOG-02 | Audit không chứa plaintext chat/password/token | Đạt | chỉ ghi length/reason/IDs |
| SR-ADMIN-01 | Admin dashboard thống kê hệ thống | Đạt | `/api/admin/stats` |
| SR-ADMIN-02 | Admin security alerts real-time | Đạt | `/api/admin/security-alerts` |
| SR-ERR-01 | Không lộ stack trace | Đạt | global exception handler |
| SR-NET-01 | HTTPS bắt buộc ở production | Cần reverse proxy | HSTS được bật khi `APP_ENV=production` |
| SR-SUPPLY-01 | Scan dependency/source/secrets/image | Có cấu hình | GitHub Actions |
| SR-IR-01 | Có playbook xử lý sự cố | Đạt tài liệu | `INCIDENT_RESPONSE.md` |
| SR-DLP-01 | Che dữ liệu nhạy cảm trước khi gửi AI bên ngoài | **Đạt (v2 — trước đó lỗi, xem GAP_ANALYSIS §1)** | `AIService._redact_for_external_ai` |
| SR-LOG-03 | Audit log chống giả mạo (tamper-evident) | Đạt (v2) | `audit_chain.py`, `GET /api/admin/audit/verify` |
| SR-LOG-04 | Log bảo mật JSON cho SIEM tập trung | Đạt (v2) | `siem.py` |
| SR-CRYPTO-03 | Xoay vòng khóa mã hóa không downtime | Đạt (v2) | keyring trong `CryptoService`, `scripts/rotate_encryption_key.py` |
| SR-IDS-01 | Phát hiện mẫu tấn công đã biết ở tầng ứng dụng | Đạt (v2) | `ids.py` — engine chữ ký |
| SR-IDS-02 | Phát hiện bất thường (brute force, spraying, dò IDOR) | Đạt (v2) | `ids.py` — engine bất thường |
| SR-IDS-03 | Tự động chặn nguồn tấn công có thời hạn | Đạt (v2) | `IntrusionState`, middleware trong `main.py` |
| SR-DB-01 | Ứng dụng chạy bằng vai trò CSDL quyền tối thiểu | Có script, cần áp dụng khi deploy | `scripts/db_least_privilege.sql` |
| SR-DB-02 | `audit_events` không cho UPDATE/DELETE ở tầng CSDL | Có script, cần áp dụng khi deploy | `scripts/db_least_privilege.sql` §5 |
| SR-NET-02 | Phân đoạn mạng: DB/Redis không ra Internet | Đạt (v2) | `docker-compose.yml` — network `internal: true` |
| SR-AUTH-06 | Rate limit endpoint đổi mật khẩu | Đạt (v2) | `/api/auth/password` |
| SR-SUPPLY-02 | Build tái lập được bằng lockfile | **Chưa — cần chạy `uv lock`** | `Dockerfile`, `pyproject.toml` |
| SR-OPS-01 | Kênh báo cáo lỗ hổng RFC 9116 | Đạt (v2) | `Caddyfile` → `/.well-known/security.txt` |
