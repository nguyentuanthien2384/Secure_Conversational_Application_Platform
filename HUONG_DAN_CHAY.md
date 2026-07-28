# Hướng dẫn chạy dự án từ đầu đến khi demo được

Tài liệu này bổ sung cho `README.md`, viết theo hướng "làm theo từng bước là chạy".
Đã kèm sẵn file `.env` với secrets sinh riêng, nên bạn **không cần cấu hình gì thêm**.

---

## 0. Điều kiện

| Thứ cần có | Ghi chú |
|---|---|
| Internet | Bắt buộc cho lần cài dependency đầu tiên |
| Python 3.10+ | Không có cũng được — `uv` sẽ tự tải Python 3.12 |
| ~1 GB đĩa trống | Gradio và các thư viện AI/QR |
| Docker | **Chỉ khi** muốn chạy bản PostgreSQL (mục 4) |

---

## 1. Chạy nhanh nhất — 1 lệnh

### macOS / Linux / WSL

```bash
cd <thư-mục-dự-án>
bash setup.sh
```

### Windows PowerShell

```powershell
cd <thư-mục-dự-án>
powershell -ExecutionPolicy Bypass -File setup.ps1
```

Script sẽ: kiểm tra Python → cài `uv` nếu thiếu → giữ/tạo `.env` → `uv sync --group dev`
→ khởi động server.

Tuỳ chọn thêm:

- `bash setup.sh --test` / `setup.ps1 -Test` — chạy pytest + ruff + bandit trước khi start.
- `bash setup.sh --no-run` / `setup.ps1 -NoRun` — chỉ cài, không chạy.

Khi thấy dòng `Uvicorn running on http://127.0.0.1:8000`, mở trình duyệt:

| Địa chỉ | Nội dung |
|---|---|
| <http://127.0.0.1:8000> | Giao diện chính (Gradio, thuần Python) |
| <http://127.0.0.1:8000/docs> | Swagger / OpenAPI |

---

## 2. Làm thủ công (nếu không muốn dùng script)

```bash
# 1) Cài uv
curl -LsSf https://astral.sh/uv/install.sh | sh          # macOS/Linux
# hoặc: powershell -c "irm https://astral.sh/uv/install.ps1 | iex"   # Windows

# 2) Cài dependency theo uv.lock
uv sync --group dev

# 3) Chạy
uv run python run_app.py
```

File `.env` đã có sẵn trong thư mục dự án. Nếu bạn muốn tự sinh lại secrets:

```bash
python scripts/generate_secrets.py
# rồi dán 2 dòng kết quả vào .env, ghi đè APP_SECRET_KEY và MASTER_ENCRYPTION_KEY
```

> Lưu ý: đổi `MASTER_ENCRYPTION_KEY` sẽ làm **dữ liệu chat cũ không giải mã được**
> — đúng theo thiết kế AES-256-GCM. Muốn đổi khóa mà giữ dữ liệu thì dùng
> `scripts/rotate_encryption_key.py` với `MASTER_ENCRYPTION_KEYS`.

---

## 3. Tài khoản đăng nhập

`.env` đang bật `SEED_DEMO_DATA=true`, nên khi server khởi động lần đầu sẽ tự tạo
3 tài khoản demo, 4 hội thoại đã mã hóa và một chuỗi sự kiện audit mô phỏng
(brute-force, IDOR bị chặn) để trang quản trị có dữ liệu.

**Mật khẩu chung:** `Phenikaa-Vault#2026-Lab`

| Tài khoản | Vai trò | Xem được gì |
|---|---|---|
| `demo.user` | user | 4 hội thoại mẫu, bản mã trong DB, tìm kiếm |
| `demo.mod` | moderator | như user + nhật ký kiểm toán |
| `demo.boss` | admin | toàn bộ bảng quản trị: thống kê, cảnh báo, quản lý user |

Ngoài ra `.env` có `BOOTSTRAP_ADMIN_USERNAME=admin` cùng mật khẩu ngẫu nhiên —
mở file `.env` để xem. Sau khi demo xong nên xoá 2 dòng `BOOTSTRAP_ADMIN_*`.

Muốn tạo lại dữ liệu mẫu sạch:

```bash
uv run python scripts/seed_demo_data.py --reset
```

---

## 4. Chạy bản PostgreSQL bằng Docker (tùy chọn, nâng cao)

Bản Docker Compose là cấu hình **production**: `APP_ENV=production`, Caddy tự xin
chứng chỉ Let's Encrypt, nên nó **cần một tên miền thật trỏ về máy bạn**. Không
dùng được với `localhost`.

```bash
# Điền vào .env: PUBLIC_DOMAIN, CADDY_EMAIL, SECURITY_TXT_EXPIRES
# (POSTGRES_PASSWORD, APP_DB_PASSWORD, AUDITOR_DB_PASSWORD đã có sẵn)
docker compose up --build
```

Kiến trúc: chỉ Caddy publish cổng 80/443; app, PostgreSQL, Redis nằm trong mạng
`backend` nội bộ (`internal: true`), không publish cổng ra host. Container
`migrate` chạy một lần với tài khoản chủ schema, còn app chạy bằng vai trò
`scap_app` quyền tối thiểu.

**Nếu chỉ cần demo cho giảng viên** → dùng cách SQLite ở mục 1, không cần Docker.

---

## 5. Chạy kiểm thử và quét bảo mật (phần cần cho báo cáo)

```bash
uv run pytest --cov=src.app --cov-report=term-missing      # unit + security regression
uv run ruff check src/app tests scripts/migrate_database.py # lint
uv run bandit -q -r src/app -ll -ii                        # SAST
uv export --frozen --no-dev --no-emit-project --output-file /tmp/req.txt
uv run pip-audit -r /tmp/req.txt                           # SCA (CVE dependency)
```

DAST bằng OWASP ZAP khi server đang chạy (cần Docker):

```bash
bash scripts/run_zap_baseline.sh http://host.docker.internal:8000
```

Hoặc dùng `make`: `make install`, `make run`, `make test`, `make security`.

---

## 6. Xử lý sự cố thường gặp

| Triệu chứng | Nguyên nhân & cách xử lý |
|---|---|
| `uv: command not found` sau khi cài | Mở terminal mới, hoặc `export PATH="$HOME/.local/bin:$PATH"` |
| `uv sync` treo hoặc timeout | Mạng chậm/proxy. Thử lại, hoặc `uv sync --group dev --no-cache` |
| `Address already in use` cổng 8000 | Đổi cổng: `PORT=8080 uv run python run_app.py` |
| Đăng nhập báo sai dù mật khẩu đúng | Đã bị lockout do nhập sai 5 lần. Chờ 15 phút (`LOGIN_LOCKOUT_SECONDS`) hoặc xoá `secure_chat.db` để reset |
| Hội thoại cũ hiện lỗi giải mã | `MASTER_ENCRYPTION_KEY` đã bị đổi. Khôi phục khóa cũ, hoặc xoá `secure_chat.db` rồi seed lại |
| Bot chỉ trả lời chung chung | Chưa có `GOOGLE_GENAI_API_KEY` → đang ở chế độ DEMO AI. Điền key vào `.env` nếu muốn Gemini thật |
| Bị chặn khi đang thử tấn công | IDS/IPS đã tự chặn IP 15 phút. Chờ, hoặc tạm đặt `IDS_ENABLED=false` |
| Muốn reset toàn bộ | Dừng server, xoá `secure_chat.db`, chạy lại |

---

## 7. Kịch bản demo gợi ý (~10 phút)

1. **Đăng nhập** `demo.user` → chỉ ra mật khẩu băm Argon2id, mọi lỗi đăng nhập đều generic.
2. **Gửi tin nhắn**, rồi mở tab xem **bản mã trong DB** → chứng minh AES-256-GCM at-rest.
3. **Bật 2FA** cho `demo.user`: quét QR bằng Google Authenticator, đăng xuất, đăng nhập lại 2 bước, cho xem mã khôi phục.
4. **Thử IDOR**: lấy `session_id` của user khác gọi qua Swagger → bị 403/404, audit ghi lại.
5. **Brute-force**: nhập sai mật khẩu 6 lần → tài khoản bị lock, IDS ghi cảnh báo.
6. **Đăng nhập `demo.boss`** → trang quản trị: thống kê, cảnh báo an ninh, nhật ký kiểm toán.
7. **Xác minh audit chain**: gọi `GET /api/admin/audit/verify` → chuỗi HMAC-SHA256 nguyên vẹn.

Chi tiết hơn: `docs/DEMO_SCRIPT.md`, `docs/HARDENING_V2.md`, `BAO_CAO_RA_SOAT_BAO_MAT.md`.
