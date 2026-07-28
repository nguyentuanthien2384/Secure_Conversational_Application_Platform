# Secure Conversational Application Platform

## Authentication security additions

- Successful logins are recorded server-side as device sessions. Use `GET /api/auth/sessions` to review active sessions, `DELETE /api/auth/sessions/{session_jti}` to revoke one, or `POST /api/auth/logout-all` to immediately invalidate every session.
- Failed sign-ins now lock an existing account temporarily after the configured threshold. Configure `LOGIN_LOCKOUT_SECONDS`; public registration is also rate-limited with `REGISTRATION_WINDOW_SECONDS` and `REGISTRATION_MAX_ATTEMPTS`.
- Password changes, account locking, and role changes revoke all existing sessions. The database startup upgrade adds the required fields and table without discarding existing users.

Đồ án môn **Bảo mật ứng dụng và hệ thống** là nền tảng trò chuyện AI đa người dùng, xây dựng bằng FastAPI và Gradio.

## 1. Những gì đã được phát triển

- Xác thực nhiều người dùng, mật khẩu băm bằng **Argon2id**.
- Xác thực hai lớp **TOTP (RFC 6238)** tùy chọn: đăng nhập hai bước, seed mã hóa tại chỗ, mã khôi phục dùng một lần, chống replay.
- Token truy cập JWT có `exp`, `nbf`, `iat`, `jti`, `issuer` và `audience`.
- Phân quyền `user/admin`; kiểm tra quyền sở hữu từng phiên để chống **IDOR/BOLA**.
- Nội dung chat mã hóa khi lưu bằng **AES-256-GCM**; AAD ràng buộc bản mã với `session_id`, vai trò và phiên bản khóa.
- Generic login errors, rate limiting đăng nhập và gửi tin nhắn.
- Audit trail cho đăng ký, đăng nhập, từ chối phân quyền, tạo/xóa phiên và gửi tin.
- Validate input phía server; giao diện dùng `textContent` thay vì chèn HTML đầu vào.
- Security headers, giới hạn request body, CORS allowlist và xử lý exception không lộ stack trace.
- Giao diện web demo, API OpenAPI/Swagger, chế độ AI ngoại tuyến khi chưa có Gemini key.
- Unit/integration/security regression tests.
- Docker, PostgreSQL tùy chọn, CI security scan và tài liệu threat model/pentest/incident response.

## 2. Chạy nhanh bằng SQLite

Yêu cầu Python 3.10+ và `uv`.

```bash
cp .env.example .env
```

Tạo bí mật riêng rồi điền vào `.env`:

```bash
python scripts/generate_secrets.py
```

Cài dependency và chạy:

```bash
uv sync --group dev
uv run python run_app.py
```

Mở:

- Web demo: `http://127.0.0.1:8000`
- Swagger API: `http://127.0.0.1:8000/docs`

Không có `GOOGLE_GENAI_API_KEY`, ứng dụng vẫn chạy bằng **DEMO AI** để phục vụ chấm bài.

## 3. Chạy với PostgreSQL bằng Docker

```bash
cp .env.example .env
# Bắt buộc đặt POSTGRES_PASSWORD, APP_DB_PASSWORD, AUDITOR_DB_PASSWORD,
# PUBLIC_DOMAIN, CADDY_EMAIL, SECURITY_TXT_EXPIRES và các khóa ứng dụng.

docker compose up --build
```

Truy cập qua tên miền HTTPS đã đặt trong `PUBLIC_DOMAIN`. Chỉ Caddy công khai
cổng 80/443; ứng dụng, PostgreSQL và Redis không publish cổng ra host.

## 4. Tài khoản admin

Cách đơn giản cho demo lần đầu:

```env
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD=mot-mat-khau-dai-va-rieng-biet
```

Khởi động ứng dụng một lần để tạo admin, sau đó xóa hai biến bootstrap khỏi môi trường triển khai.

## 5. Chạy kiểm thử và scan

```bash
uv lock --check
uv run python -m pytest --cov=src.app --cov-report=term-missing
uv run ruff check src/app tests scripts/migrate_database.py
uv run bandit -q -r src/app -ll -ii
uv export --frozen --no-dev --no-emit-project --output-file /tmp/scap-requirements.txt
uv run pip-audit -r /tmp/scap-requirements.txt
```

DAST khi app đang chạy:

```bash
bash scripts/run_zap_baseline.sh http://host.docker.internal:8000
```

## 6. Cấu trúc chính

```text
src/app/                 FastAPI secure application
tests/                   Security regression tests
scripts/                 Tạo secret và chạy ZAP
.github/workflows/       CI và security scanning
```

## 7. Bản nâng cấp bảo mật v2

- **Sửa lỗi nghiêm trọng:** lớp DLP che dữ liệu nhạy cảm trước khi gửi tới nhà
  cung cấp AI bên ngoài trước đây **không hoạt động** (regex bị escape hai lần
  trong chuỗi raw). Đã sửa và khóa lại bằng test.
- **Audit log chống giả mạo:** chuỗi băm HMAC-SHA256; xác minh qua
  `GET /api/admin/audit/verify`.
- **IDS/IPS tầng ứng dụng:** 10 nhóm chữ ký + engine bất thường phân biệt brute
  force với password spraying; tự chặn nguồn tấn công có thời hạn.
- **Log SIEM:** mọi sự kiện bảo mật ra stdout dạng JSON một dòng theo chuẩn ECS.
- **Xoay vòng khóa mã hóa:** keyring nhiều phiên bản + `scripts/rotate_encryption_key.py`.
- **Hạ tầng:** hardening Postgres, phân đoạn mạng, `HEALTHCHECK`, `security.txt`,
  vai trò CSDL quyền tối thiểu.
- **Bản gia cố 2026:** DLP không còn dùng trạng thái dùng chung giữa request;
  MFA challenge chỉ dùng một lần; SPA không giữ bearer token trong Web Storage;
  migration tách khỏi tài khoản runtime; production từ chối demo seed và tài
  khoản owner; `uv.lock` cùng SCA là cổng bắt buộc trong CI.

## 8. Giới hạn có chủ đích

- Development một instance dùng rate limiter in-memory; cấu hình production bắt
  buộc Redis để giới hạn dùng chung giữa nhiều worker/instance.
- JWT access token có gia hạn trượt qua `POST /api/auth/refresh` (xoay jti, thu
  hồi token cũ, trần tuyệt đối `SESSION_ABSOLUTE_HOURS`) và thu hồi phía máy chủ (AuthSession + RevokedToken + token_version, logout-all, per-device revoke). Thời hạn access token mặc định 30 phút; gia hạn bị chặn cứng sau 8 giờ kể từ lần đăng nhập gốc.
- Ứng dụng hỗ trợ keyring và xoay khóa AES-GCM; production thật vẫn nên chuyển
  vật liệu khóa khỏi biến môi trường sang KMS/Vault và envelope encryption.
- SQLite là mặc định để chạy nhanh; Docker Compose cung cấp PostgreSQL cho bản trình diễn gần production hơn.
- Giao diện Gradio vẫn cần `'unsafe-inline'` trong CSP; `'unsafe-eval'` đã tắt.
  Muốn CSP strict bằng nonce/hash cần thay hoặc tách frontend.
- DAST cần chạy trong môi trường lab được phép, không quét hệ thống của bên thứ ba.

## Giao diện (v3 — thuần Python)

- Giao diện chính tại `/` được viết lại **hoàn toàn bằng Gradio** (`src/app/gradio_ui.py`) — thuần Python, đồng bộ với toàn bộ dự án. Mọi thao tác trên UI gọi chính REST API của hệ thống qua httpx, nên đều đi qua đầy đủ JWT, RBAC, rate limiting và audit trail.
- Tính năng bao phủ 100% API: đăng ký / đăng nhập kèm bước 2FA, trò chuyện (tạo / đổi tên / xóa / xuất JSON / tìm trong hội thoại / tự tạo hội thoại khi gửi tin đầu tiên), xem bản mã trong DB, tìm kiếm toàn cục, tài khoản (đổi mật khẩu, đồng ý AI, thiết lập 2FA với mã QR + mã khôi phục, quản lý thiết bị đăng nhập, đăng xuất tất cả), quản trị (thống kê, cảnh báo an ninh, quản lý người dùng, nhật ký kiểm toán — moderator chỉ thấy nhật ký).
- Đồng hồ đếm ngược vòng đời token cập nhật mỗi 10 giây trên banner.
- Endpoint mới: `GET /api/search/messages?q=` — tìm kiếm toàn cục trên mọi hội thoại thuộc sở hữu của người gọi (giải mã phía máy chủ, ghi audit `chat.message.search`).

## Dữ liệu mẫu (demo data)

Tạo nhanh 3 tài khoản demo (3 vai trò RBAC), 4 hội thoại đã mã hóa AES-256-GCM có nội dung giải thích chính các cơ chế bảo mật của dự án, và chuỗi sự kiện audit mô phỏng (brute-force, IDOR bị chặn) để trang quản trị có dữ liệu:

```bash
uv run python scripts/seed_demo_data.py           # tạo dữ liệu mẫu
uv run python scripts/seed_demo_data.py --reset   # xóa demo cũ rồi tạo lại
```

Hoặc **tự động nạp khi khởi động server**: thêm `SEED_DEMO_DATA=true` vào `.env`
(idempotent). Cấu hình production sẽ từ chối khởi động nếu biến này được bật.

Tài khoản demo (mật khẩu chung `Phenikaa-Vault#2026-Lab`):

| Tài khoản  | Vai trò    | Xem được gì |
|------------|-----------|-------------|
| demo.user  | user      | 4 hội thoại mẫu, bản mã, tìm kiếm |
| demo.mod   | moderator | như user + nhật ký kiểm toán |
| demo.boss  | admin     | toàn bộ bảng quản trị: thống kê, cảnh báo, quản lý người dùng |

Lưu ý: chạy script với cùng file `.env` mà server dùng — tin nhắn mẫu được mã hóa bằng đúng `MASTER_ENCRYPTION_KEY` nên nếu đổi khóa, dữ liệu cũ sẽ không giải mã được (đúng như thiết kế).
