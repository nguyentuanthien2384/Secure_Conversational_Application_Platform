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

## 3b. Bật Gemini API thật (thay cho DEMO AI)

Mặc định app chạy chế độ **Offline Demo AI**. Để dùng Gemini thật:

1. Lấy API key tại Google AI Studio (`aistudio.google.com` → *Get API key*).
2. Điền vào `.env`:

   ```bash
   GOOGLE_GENAI_API_KEY=<key-cua-ban>
   GEMINI_MODEL=gemini-flash-lite-latest
   ALLOW_DEMO_AI=false   # tùy chọn: báo lỗi rõ ràng thay vì âm thầm về demo
   ```

   Nên dùng alias `-latest` thay vì tên model có số phiên bản. Google khai tử
   model cũ theo thời gian: bản ghim `gemini-2.5-flash-lite` nay trả **404**
   *"no longer available to new users"*, trong khi alias tự trỏ sang thế hệ
   còn hiệu lực.

3. **Khởi động lại server.** `AIService` chỉ khởi tạo một lần lúc app start,
   sửa `.env` khi đang chạy không có tác dụng.
4. **Bật đồng ý gửi dữ liệu.** Đăng nhập `demo.user` / `Phenikaa-Vault#2026-Lab`
   → tab **Tài khoản** → tick ô *"Cho phép gửi nội dung … tới AI bên ngoài"*.
   Chưa tick thì API trả **403** — đây là cơ chế đồng thuận (`ai_data_consent`),
   cố ý chứ không phải lỗi.
5. **Gửi thử một tin nhắn.** Nếu câu trả lời **không** có tiền tố `[DEMO AI]`
   thì Gemini thật đã chạy.

Kiểm tra nhanh key trước khi chạy cả app:

```bash
uv run python src/core/ai_core/gemini_ai.py
```

**Lưu ý về DLP:** trước khi rời biên tin cậy, `_REDACTION_RULES` trong
`src/app/services.py` che email, số điện thoại, số thẻ và mọi dãy 9–12 chữ số.
Bot sẽ không "nhìn thấy" các giá trị đó — đúng thiết kế, nhưng nên biết trước
khi demo trực tiếp.

**Khi nhà cung cấp AI lỗi** (key sai, hết quota, mất mạng): API trả **503** kèm
`Retry-After: 30` và thông điệp chung chung; chi tiết lỗi chỉ ghi vào log máy
chủ để tránh information disclosure (CWE-209). Xem
`tests/test_ai_provider_errors.py`.

---

## 3c. Ba chốt kiểm tra trước khi demo

Làm **lần lượt**, chốt trước pass rồi mới sang chốt sau. Nếu chốt nào hỏng, sửa
xong hẵng đi tiếp — chạy cả ba cùng lúc chỉ làm khó việc khoanh vùng lỗi.

| # | Lệnh | Đạt khi thấy |
|---|---|---|
| 1 | `uv run python src/core/ai_core/gemini_ai.py` | In ra một câu trả lời thật (vd. *"Hello! How can I help you today?"*) |
| 2 | `uv run pytest -q` | `106 passed`, không có `F` hay `E` |
| 3 | `uv run python run_app.py` | `Uvicorn running on http://127.0.0.1:8000` |

**Chốt 1 — key sống.** Gọi thẳng Gemini, không qua app. Hỏng ở đây nghĩa là vấn
đề nằm ở key/model/mạng chứ không phải ở mã nguồn ứng dụng, xem bảng sự cố mục 6.

**Chốt 2 — bộ kiểm thử.** Quan trọng nhất với đồ án: **ảnh chụp màn hình kết quả
`pytest` là bằng chứng trực tiếp cho phần kiểm thử trong báo cáo**. Nên chụp cả
dòng tổng kết `106 passed`. Muốn kèm độ phủ thì dùng lệnh đầy đủ ở mục 5.

**Chốt 3 — server.** Lên được là xong; mở <http://127.0.0.1:8000> để chắc chắn
giao diện render chứ không chỉ tiến trình sống.

> **Nếu máy chưa cài `uv`** (`uv: command not found`): chạy `bash setup.sh --no-run`
> để cài, hoặc dùng thẳng môi trường ảo có sẵn — thay `uv run` bằng
> `.venv\Scripts\python.exe` (Windows) / `.venv/bin/python` (macOS, Linux).
> Ví dụ: `.venv\Scripts\python.exe -m pytest -q`.

---

## 4. Chạy bản PostgreSQL bằng Docker (tùy chọn, nâng cao)

Có **hai** cấu hình, đừng nhầm:

| Cấu hình | Lệnh | Dùng khi |
|---|---|---|
| **Local — demo được ngay** | `docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build` | Demo trên laptop |
| **Production thật** | `docker compose up -d --build` | Deploy VPS có tên miền thật |

### Cách local (khuyến nghị nếu muốn demo bằng Docker)

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build
```

Xong. Vào <http://localhost:8000>, đăng nhập `demo.user` / `Phenikaa-Vault#2026-Lab`
— **3 tài khoản demo, 4 hội thoại đã mã hoá và chuỗi audit đều được nạp tự động**,
Swagger có ở `/docs`. Không phải tạo tài khoản thủ công.

Overlay local hạ `APP_ENV` xuống `development` vì guard trong `src/app/config.py`
cấm `DOCS_ENABLED=true` và `SEED_DEMO_DATA=true` ở production — mà kịch bản demo
cần cả hai. Đây là khác biệt **có chủ đích và nên nói ra** khi bảo vệ.

Reset sạch: `down -v` rồi `up -d` (đừng dùng `seed_demo_data.py --reset` trên DB
đang chạy — nó xoá bản ghi audit giữa chuỗi và làm gãy chuỗi băm).

### Cách production

Cấu hình gốc `docker-compose.yml` là **production thật**: `APP_ENV=production`,
Caddy tự xin chứng chỉ Let's Encrypt, nên nó **cần một tên miền thật trỏ về máy**.
Với `localhost` thì Caddy không gọi ACME mà tự sinh CA nội bộ — xem
`HUONG_DAN_DOCKER.md` Phần 4.

Kiến trúc: chỉ Caddy publish cổng 80/443; app, PostgreSQL, Redis nằm trong mạng
`backend` nội bộ (`internal: true`), không publish cổng ra host. Container
`migrate` chạy một lần với tài khoản chủ schema, còn app chạy bằng vai trò
`scap_app` quyền tối thiểu.

**Nếu chỉ cần demo nhanh nhất** → dùng cách SQLite ở mục 1, không cần Docker.
Chi tiết Docker đầy đủ: `HUONG_DAN_DOCKER.md`.

---

## 5. Chạy kiểm thử và quét bảo mật (phần cần cho báo cáo)

```bash
uv run pytest --cov=src.app --cov-report=term-missing      # unit + security regression
uv run ruff check src tests scripts                      # lint
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
| Gửi tin nhắn báo 403 "Cần đồng ý…" | Chưa tick ô đồng ý ở tab **Tài khoản** (`ai_data_consent`) |
| Gửi tin nhắn báo 503 "Dịch vụ AI tạm thời không khả dụng" | Key sai / hết quota / mất mạng. Xem log máy chủ (`secure_chat.ai`) để biết nguyên nhân thật |
| Bị chặn khi đang thử tấn công | IDS/IPS đã tự chặn IP 15 phút. Chờ, hoặc tạm đặt `IDS_ENABLED=false` |
| Muốn reset toàn bộ | Dừng server, xoá `secure_chat.db`, chạy lại |

---

## 7. Chuẩn bị cho buổi demo

**Dữ liệu mẫu** đã tự tạo khi server khởi động lần đầu (`SEED_DEMO_DATA=true`):
3 tài khoản, 4 hội thoại đã mã hóa, và một chuỗi sự kiện audit mô phỏng
brute-force + IDOR bị chặn — để trang quản trị có dữ liệu thật mà xem. Muốn làm
lại sạch:

```bash
uv run python scripts/seed_demo_data.py --reset
```

Ba tài khoản dùng chung mật khẩu `Phenikaa-Vault#2026-Lab`: `demo.user` (user),
`demo.mod` (moderator), `demo.boss` (admin).

**Cần chuẩn bị thêm:**

| Thứ cần có | Dùng cho | Ghi chú |
|---|---|---|
| Điện thoại có Google Authenticator | Bước 4 — demo 2FA quét QR | Quét không ra thì dùng ô *Khóa thủ công* |
| Tab 1: <http://127.0.0.1:8000> | Giao diện chính | |
| Tab 2: <http://127.0.0.1:8000/docs> | Bước 5 — tấn công IDOR qua Swagger | Cho giảng viên thấy bạn gọi API trực tiếp |
| Cửa sổ ẩn danh | Đăng nhập tài khoản thứ hai | Để lấy `session_id` của user khác mà không mất phiên đầu |
| Terminal đang chạy server | Bước 9 — chỉ vào log | Chứng minh chi tiết lỗi nằm ở phía máy chủ |

> **Biết trước đường thoát IDS/IPS.** Bước 5 và 6 rất dễ khiến bạn **tự chặn IP
> của chính mình**. Khi đó: chờ 15 phút, hoặc dừng server → đặt `IDS_ENABLED=false`
> trong `.env` → chạy lại. Chuẩn bị sẵn `demo.mod` để đăng nhập tiếp mà không phải chờ.

---

## 8. Kịch bản demo (~10 phút)

1. **Đăng nhập** `demo.user` — thử sai mật khẩu, rồi thử tài khoản không tồn tại:
   cả hai cho **cùng một thông báo lỗi**, không tiết lộ tài khoản có tồn tại hay
   không (chống user enumeration). Mật khẩu băm bằng Argon2id.
2. **Gửi tin nhắn**, rồi mở tab **Dữ liệu mã hóa** xem bản mã trong DB — chứng
   minh AES-256-GCM at-rest: ciphertext base64, nonce riêng từng bản ghi, khóa
   không nằm trong database.
3. **Thử DLP**: gửi một câu có email hoặc số thẻ, ví dụ
   `Email của tôi là nguyenvana@gmail.com, số thẻ 4111 1111 1111 1111`. Băng DLP
   hiện ra liệt kê **loại** dữ liệu đã che, **không** hiện lại giá trị gốc.
4. **Bật 2FA**: quét QR bằng Google Authenticator → kích hoạt → lưu mã khôi phục
   (chỉ hiện một lần) → đăng xuất → đăng nhập lại 2 bước.
5. **Tấn công IDOR**: lấy `session_id` của user khác, gọi
   `GET /api/sessions/{id}/messages` qua Swagger → **403/404**, audit ghi lại
   `authorization.denied`. Nhấn mạnh: **admin cũng không đọc được** chat người khác.
6. **Brute-force**: nhập sai mật khẩu 6 lần → tài khoản bị khóa, IDS ghi cảnh báo.
7. **Đăng nhập `demo.boss`** → trang quản trị: thống kê, cảnh báo an ninh, nhật ký
   kiểm toán.
8. **Xác minh audit chain**: `GET /api/admin/audit/verify` → chuỗi HMAC-SHA256
   nguyên vẹn. Sửa trộm một dòng bằng `sqlite3` rồi xác minh lại → chuỗi **gãy**,
   chỉ đúng vị trí bản ghi bị sửa.

**Bước 9 (tùy chọn, ghi điểm thêm) — xử lý lỗi an toàn, CWE-209.** Dừng server →
làm hỏng key trong `.env` (`GOOGLE_GENAI_API_KEY=AIzaSyHONG`) → chạy lại → gửi một
tin nhắn. Hệ thống trả **503** với thông báo chung chung *"Dịch vụ AI tạm thời
không khả dụng…"*: không traceback, không tên model, không mảnh API key nào.
Nguyên nhân thật (401 UNAUTHENTICATED) nằm đầy đủ trong log máy chủ — chỉ vào
terminal cho giảng viên thấy. Hành vi này có test tự động khóa lại:
`tests/test_ai_provider_errors.py`. **Nhớ khôi phục key đúng sau khi demo xong.**

---

## 9. Tài liệu liên quan

| File | Nội dung |
|---|---|
| `docs/DEMO_SCRIPT.md` | Kịch bản demo chi tiết: từng thao tác, kết quả mong đợi, câu nên nói, và phần trả lời câu hỏi phản biện |
| `SECURITY_REVIEW.md` | Kết quả rà soát bảo mật |
| `SECURITY.md` | Chính sách bảo mật, quy trình báo lỗi |
| `HUONG_DAN_DOCKER.md` | Chi tiết bản triển khai Docker/PostgreSQL |
