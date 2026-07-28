# Hướng dẫn chạy dự án bằng Docker (thủ công, từng bước)

`docker-compose.yml` của dự án là **cấu hình production thật**: 5 service, phân đoạn
mạng, PostgreSQL 3 vai trò quyền tối thiểu, Caddy tự xin chứng chỉ Let's Encrypt.
Vì vậy không thể `docker compose up` rồi vào `localhost` là xong — tài liệu này đi
qua đúng từng bước, kèm 3 điểm dễ vỡ nhất.

---

## Phần 0. Hiểu stack trước khi chạy

| Service | Image / build | Mạng | Vai trò |
|---|---|---|---|
| `db` | postgres:17-alpine | `backend` | PostgreSQL, xác thực scram-sha-256, log DDL + connection |
| `redis` | redis:7.4-alpine | `backend` | Rate limiter dùng chung, chạy read-only + tmpfs |
| `migrate` | build `.` | `backend` | **Chạy 1 lần rồi thoát.** Tạo schema bằng tài khoản chủ, rồi cấp quyền tối thiểu |
| `app` | build `.` | `backend` + `edge` | FastAPI + Gradio, chạy bằng vai trò `scap_app` (không có DDL) |
| `caddy` | caddy:2.10-alpine | `edge` | Reverse proxy HTTPS, service **duy nhất** publish 80/443 |

Ba vai trò database (`scripts/db_least_privilege.sql`):

- `secure_chat` — chủ schema, **chỉ** dùng bởi container `migrate`
- `scap_app` — runtime: SELECT/INSERT/UPDATE/DELETE, **không** DDL, và bị
  `REVOKE UPDATE, DELETE, TRUNCATE` trên `audit_events` (audit chỉ ghi thêm)
- `scap_auditor` — chỉ đọc `audit_events`, dành cho SOC/giảng viên

Thứ tự khởi động do Compose đảm bảo: `db` healthy → `migrate` chạy xong →
`redis` healthy → `app` healthy → `caddy`.

---

## Phần 1. Ba điểm dễ vỡ — xử lý TRƯỚC khi chạy

### 1.1. `BOOTSTRAP_ADMIN_PASSWORD` phải để trống

Service `app` dùng `env_file: .env`, và nó chạy với `APP_ENV=production`.
`config.py` có guard:

```
RuntimeError: Không đặt BOOTSTRAP_ADMIN_PASSWORD ở production;
tạo admin qua quy trình one-off.
```

Nếu `.env` còn giá trị ở 2 dòng `BOOTSTRAP_ADMIN_*`, container `app` sẽ crash ngay
lúc khởi động. Trong `.env` kèm theo, hai dòng này đã được để trống.

### 1.2. Caddy cần tên miền — chọn 1 trong 3 cách

Caddyfile dùng `{$PUBLIC_DOMAIN}` và global `email`. Với tên miền công khai,
Caddy đi xin cert Let's Encrypt qua HTTP-01 → cần DNS trỏ về máy bạn và cổng
80/443 mở từ Internet. Trên laptop điều đó không có.

| Cách | `PUBLIC_DOMAIN` | Truy cập | Dùng khi |
|---|---|---|---|
| **A. Không Caddy** (dễ nhất) | `localhost` | `http://localhost:8000` | Demo nhanh trên máy |
| **B. Caddy + HTTPS nội bộ** | `scap.localhost` | `https://scap.localhost` | Muốn demo cả TLS, HSTS, security.txt |
| **C. Tên miền thật** | `chat.tenban.com` | `https://chat.tenban.com` | Deploy VPS thật |

Cách B khai thác đặc điểm: với host nội bộ (`localhost`, `*.localhost`, IP),
Caddy **không** gọi ACME mà tự sinh CA nội bộ, cert lưu ở
`/data/caddy/pki/authorities/local`. Trình duyệt sẽ cảnh báo cert lạ — bình thường,
xem mục 4.3 để cài root CA cho hết cảnh báo.

### 1.3. Đổi `MASTER_ENCRYPTION_KEY` = mất dữ liệu cũ

Tin nhắn mã hóa AES-256-GCM bằng khóa trong `.env`. Đổi khóa → hội thoại cũ không
giải mã được (đúng thiết kế). Nếu muốn đổi mà giữ dữ liệu, dùng
`MASTER_ENCRYPTION_KEYS` + `scripts/rotate_encryption_key.py`.

---

## Phần 2. Kiểm tra `.env`

`docker compose` tự đọc `./.env` để nội suy `${...}`, và service `app` nạp cùng file
đó làm biến môi trường. Các biến **bắt buộc** (Compose dùng cú pháp `:?` nên thiếu
là dừng ngay, không chạy nửa vời):

```env
POSTGRES_PASSWORD=...        # mật khẩu tài khoản chủ secure_chat
APP_DB_PASSWORD=...          # mật khẩu vai trò runtime scap_app
AUDITOR_DB_PASSWORD=...      # mật khẩu vai trò read-only scap_auditor
PUBLIC_DOMAIN=localhost      # xem mục 1.2
CADDY_EMAIL=admin@example.com
SECURITY_TXT_EXPIRES=2027-07-01T00:00:00Z
APP_SECRET_KEY=...           # >= 32 ký tự, ký JWT + dẫn xuất khóa audit chain
MASTER_ENCRYPTION_KEY=...    # 32 byte base64
BOOTSTRAP_ADMIN_USERNAME=    # PHẢI trống
BOOTSTRAP_ADMIN_PASSWORD=    # PHẢI trống
```

Những biến sau trong `.env` **bị Compose ghi đè**, không cần sửa:
`APP_ENV`, `DATABASE_URL`, `REDIS_URL`, `ALLOWED_ORIGINS`, `ALLOWED_HOSTS`,
`DOCS_ENABLED`, `PASSWORD_BREACH_CHECK`, `SEED_DEMO_DATA`.

Kiểm tra cấu hình đã nội suy đúng chưa (chưa build gì cả):

```bash
docker compose config
```

Lệnh này in ra compose file sau khi thay biến. Nếu thiếu biến bắt buộc, nó báo
`set POSTGRES_PASSWORD in .env` và dừng — sửa `.env` rồi chạy lại.

---

## Phần 3. Cách A — Chạy local, không Caddy (khuyến nghị để demo)

Cần `PUBLIC_DOMAIN=localhost` trong `.env` và file `docker-compose.local.yml`
(đã kèm theo).

```bash
# 1. Build image (lần đầu ~3-6 phút: uv sync --frozen theo uv.lock)
docker compose -f docker-compose.yml -f docker-compose.local.yml build

# 2. Khởi động db + redis + migrate + app  (caddy bị tắt qua profile)
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d

# 3. Xem trạng thái — app phải là "healthy"
docker compose -f docker-compose.yml -f docker-compose.local.yml ps

# 4. Kiểm tra migrate đã chạy xong
docker compose -f docker-compose.yml -f docker-compose.local.yml logs migrate
#   -> "Database migration and least-privilege grants completed."

# 5. Xem log app
docker compose -f docker-compose.yml -f docker-compose.local.yml logs -f app
```

Mẹo: gõ dài quá thì đặt biến tắt cho cả phiên terminal:

```bash
export COMPOSE_FILE=docker-compose.yml:docker-compose.local.yml   # macOS/Linux
$env:COMPOSE_FILE="docker-compose.yml;docker-compose.local.yml"   # PowerShell
# từ đây chỉ cần: docker compose up -d / logs -f app / down
```

Kiểm tra sống:

```bash
curl http://localhost:8000/api/health
```

Truy cập: <http://localhost:8000> (Gradio UI) và <http://localhost:8000/spa>.
Lưu ý `/docs` **404** vì Compose đặt `DOCS_ENABLED=false` — đúng theo yêu cầu
production (không lộ schema API). Muốn có Swagger để demo, thêm
`DOCS_ENABLED: "true"` vào `docker-compose.local.yml`, nhưng nên nói rõ với giảng
viên rằng bản production tắt nó.

---

## Phần 4. Cách B — Chạy đủ 5 service với Caddy + HTTPS nội bộ

Đặt trong `.env`: `PUBLIC_DOMAIN=scap.localhost`

### 4.1. Trỏ tên miền về máy

Chrome/Edge/Firefox tự phân giải `*.localhost` về loopback. Windows hoặc curl thì
thêm dòng vào hosts file:

- Windows: `C:\Windows\System32\drivers\etc\hosts` (mở bằng Notepad chạy as admin)
- macOS/Linux: `/etc/hosts` (`sudo nano /etc/hosts`)

```text
127.0.0.1   scap.localhost
```

### 4.2. Chạy

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f caddy
```

Cổng 80 và 443 trên máy phải trống (tắt IIS/Apache/nginx/Skype nếu đang chiếm).

Truy cập <https://scap.localhost> → trình duyệt cảnh báo cert không tin cậy →
Advanced → Proceed. Thử luôn:

```bash
curl -k https://scap.localhost/.well-known/security.txt   # RFC 9116
curl -k -X PUT https://scap.localhost/                    # -> 405, Caddy chặn method
curl -k https://scap.localhost/wp-login.php               # -> 404, chặn recon ở biên
curl -kI http://scap.localhost/                           # -> 301 sang HTTPS
```

### 4.3. (Tùy chọn) Hết cảnh báo cert — cài root CA của Caddy

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
```

- **Windows:** double-click `caddy-root.crt` → Install Certificate → Local Machine
  → Place in *Trusted Root Certification Authorities*
- **macOS:** `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain caddy-root.crt`
- **Linux:** `sudo cp caddy-root.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`
- **Firefox** dùng store riêng: Settings → Certificates → View Certificates →
  Authorities → Import

Khởi động lại trình duyệt. Sau khi CA được tin cậy, HSTS trong Caddyfile mới thực
sự có hiệu lực (HSTS bị bỏ qua trên kết nối có lỗi certificate).

---

## Phần 5. Tạo tài khoản đăng nhập

Vì production chặn `BOOTSTRAP_ADMIN_*` và `SEED_DEMO_DATA`, phải tạo admin bằng
quy trình one-off. Chọn 1 trong 2 cách.

### Cách 1 — Nạp dữ liệu mẫu (nhanh, có sẵn 3 vai trò + dữ liệu cho trang quản trị)

`scripts/seed_demo_data.py` không được COPY vào image (xem `Dockerfile`), nhưng
module `src/app/demo_seed.py` thì có. Gọi trực tiếp trong container đang chạy:

```bash
docker compose exec app /app/.venv/bin/python -c "from src.app.config import Settings; from src.app.db import Database; from src.app.demo_seed import seed_demo_data; from src.app.security import CryptoService, PasswordService; s=Settings.from_env(); seed_demo_data(Database(s.database_url), PasswordService(), CryptoService(s.master_encryption_key))"
```

Chạy được vì `scap_app` có quyền INSERT trên mọi bảng, và schema đã do `migrate`
tạo nên không cần DDL.

Kết quả — mật khẩu chung `Phenikaa-Vault#2026-Lab`:

| Tài khoản | Vai trò | Thấy gì |
|---|---|---|
| `demo.user` | user | 4 hội thoại mẫu, bản mã trong DB, tìm kiếm |
| `demo.mod` | moderator | như user + nhật ký kiểm toán |
| `demo.boss` | admin | toàn bộ trang quản trị |

Muốn xóa sạch rồi nạp lại (`--reset` xóa cả audit `seed-%`, mà `scap_app` bị
REVOKE DELETE trên `audit_events` → phải dùng tài khoản chủ):

```bash
docker compose run --rm --no-deps \
  -e APP_ENV=development \
  -e DATABASE_URL="postgresql+psycopg://secure_chat:$POSTGRES_PASSWORD@db:5432/secure_chat" \
  app /app/.venv/bin/python -c "from src.app.config import Settings; from src.app.db import Database; from src.app.demo_seed import seed_demo_data; from src.app.security import CryptoService, PasswordService; s=Settings.from_env(); seed_demo_data(Database(s.database_url), PasswordService(), CryptoService(s.master_encryption_key), reset=True)"
```

(Cần `export POSTGRES_PASSWORD=...` trước, hoặc thay trực tiếp mật khẩu vào chuỗi.
`APP_ENV=development` là bắt buộc: guard production từ chối `DATABASE_URL` dùng
tài khoản chủ.)

### Cách 2 — Tự đăng ký rồi nâng quyền bằng SQL (giống quy trình thật hơn)

1. Vào UI, đăng ký một tài khoản. Mật khẩu phải ≥ 15 ký tự (`PASSWORD_MIN_LENGTH`).
2. Nâng lên admin:

```bash
docker compose exec db sh -c 'PGPASSWORD=$POSTGRES_PASSWORD psql -U secure_chat -d secure_chat'
```

Tại dấu nhắc `psql`:

```sql
UPDATE users SET role = 'admin' WHERE username = 'tendangnhap';
SELECT id, username, role, mfa_enabled FROM users;
\q
```

Đăng xuất rồi đăng nhập lại để token mang role mới.

---

## Phần 6. Kiểm chứng các lớp bảo mật (phần ăn điểm khi bảo vệ)

### 6.1. Phân đoạn mạng — `db`/`redis` không thể chạm từ ngoài

```bash
docker compose port db 5432          # -> lỗi: không có port mapping
docker network inspect $(docker compose ls -q 2>/dev/null | head -1)_backend \
  | grep -i internal                 # -> "Internal": true
```

Chứng minh app vẫn nối được, còn caddy thì không:

```bash
docker compose exec app /app/.venv/bin/python -c "import socket;print(socket.create_connection(('db',5432),3))"
docker compose exec caddy sh -c "nc -z -w2 db 5432 || echo 'caddy KHONG thay db'"
```

### 6.2. Quyền tối thiểu của database — runtime không được DDL

```bash
docker compose exec db sh -c 'PGPASSWORD=$APP_DB_PASSWORD psql -U scap_app -d secure_chat'
```

```sql
DROP TABLE users;                     -- ERROR: must be owner of table users
DELETE FROM audit_events;             -- ERROR: permission denied for table audit_events
INSERT INTO audit_events (event, outcome) VALUES ('test','success');  -- OK: chỉ được ghi thêm
\q
```

Đây chính là minh chứng "một lỗ hổng SQLi cũng không DROP được bảng, không xóa
được audit log".

Vai trò auditor cho giảng viên:

```bash
docker compose exec db sh -c 'PGPASSWORD=$AUDITOR_DB_PASSWORD psql -U scap_auditor -d secure_chat -c "SELECT event, outcome, created_at FROM audit_events ORDER BY id DESC LIMIT 10;"'
docker compose exec db sh -c 'PGPASSWORD=$AUDITOR_DB_PASSWORD psql -U scap_auditor -d secure_chat -c "SELECT * FROM users LIMIT 1;"'
# -> permission denied for table users
```

### 6.3. Dữ liệu thật trong DB là bản mã

```bash
docker compose exec db sh -c 'PGPASSWORD=$POSTGRES_PASSWORD psql -U secure_chat -d secure_chat -c "SELECT id, session_id, nonce, left(ciphertext, 60) FROM secure_messages LIMIT 3;"'
```

Không có chữ tiếng Việt nào đọc được — AES-256-GCM at-rest, nonce riêng từng tin.

### 6.4. Container hardening

```bash
docker inspect $(docker compose ps -q app) \
  --format '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} {{.HostConfig.PidsLimit}}'
docker compose exec app id            # -> uid=app, không phải root
docker compose exec app touch /app/x  # -> Read-only file system
```

### 6.5. Log SIEM dạng JSON theo ECS

```bash
docker compose logs app | grep '"event.category"' | tail -5
```

Đây là stdout JSON một dòng, cắm thẳng vào Loki/ELK/Wazuh được.

### 6.6. Audit chain chống giả mạo

Đăng nhập `demo.boss`, vào tab Quản trị, hoặc gọi API:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo.boss","password":"Phenikaa-Vault#2026-Lab"}' \
  | python -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
curl -s http://localhost:8000/api/admin/audit/verify -H "Authorization: Bearer $TOKEN"
```

Rồi sửa tay một dòng audit bằng tài khoản chủ và verify lại → chuỗi HMAC-SHA256 báo
đứt tại đúng vị trí đó. Đây là demo rất mạnh:

```bash
docker compose exec db sh -c 'PGPASSWORD=$POSTGRES_PASSWORD psql -U secure_chat -d secure_chat -c "UPDATE audit_events SET outcome=\047success\047 WHERE id=(SELECT min(id) FROM audit_events);"'
```

### 6.7. IDS/IPS tầng ứng dụng

```bash
for i in $(seq 1 8); do curl -s -o /dev/null -w "%{http_code} " \
  "http://localhost:8000/api/health?q=' OR 1=1--"; done; echo
```

Điểm rủi ro tích lũy vượt `IDS_BLOCK_THRESHOLD=5` → nguồn bị chặn 15 phút, cảnh báo
hiện trong trang quản trị. Muốn bỏ chặn: `IDS_BLOCK_SECONDS` hết hạn, hoặc dùng
endpoint xóa chặn trong tab quản trị.

---

## Phần 7. Vận hành hằng ngày

```bash
docker compose up -d                  # khởi động
docker compose stop                   # dừng, giữ dữ liệu
docker compose start                  # chạy lại
docker compose restart app            # restart 1 service
docker compose logs -f app            # theo dõi log
docker compose down                   # xóa container, GIỮ volume (dữ liệu còn)
docker compose down -v                # XÓA LUÔN DỮ LIỆU (postgres_data, caddy_data)
docker compose up -d --build app      # rebuild sau khi sửa code
docker compose exec app sh            # vào shell container app
```

Sau khi sửa code trong `src/`, phải `--build` lại vì Dockerfile `COPY src ./src`
(không bind-mount, cố ý — image bất biến).

Backup / restore database:

```bash
docker compose exec db sh -c 'PGPASSWORD=$POSTGRES_PASSWORD pg_dump -U secure_chat secure_chat' > backup.sql
cat backup.sql | docker compose exec -T db sh -c 'PGPASSWORD=$POSTGRES_PASSWORD psql -U secure_chat -d secure_chat'
```

Xem thêm `docs/BACKUP_AND_RECOVERY.md`.

---

## Phần 8. Xử lý sự cố

| Triệu chứng | Nguyên nhân → cách xử lý |
|---|---|
| `set POSTGRES_PASSWORD in .env` | Thiếu biến bắt buộc. Chạy `docker compose config` để biết thiếu biến nào |
| `app` khởi động rồi tắt ngay, log có `Không đặt BOOTSTRAP_ADMIN_PASSWORD ở production` | Xóa giá trị 2 dòng `BOOTSTRAP_ADMIN_*` trong `.env`, rồi `docker compose up -d app` |
| Log app: `REDIS_URL bắt buộc ở production` | Đang chạy service `app` lẻ mà không qua Compose. Luôn dùng `docker compose up`, đừng `docker run` tay |
| Log app: `Database schema chưa được migrate; thiếu bảng: ...` | `migrate` chưa chạy xong hoặc lỗi. `docker compose logs migrate`, sửa rồi `docker compose up migrate` |
| `migrate` báo `role "scap_app" does not exist` | Volume `postgres_data` được tạo từ lần trước khi chưa có `init_db_roles.sh`. Init script chỉ chạy trên volume rỗng → `docker compose down -v` rồi `up` lại |
| `password authentication failed for user "scap_app"` | Đã đổi `APP_DB_PASSWORD` sau khi volume được khởi tạo. Đổi lại mật khẩu cũ, hoặc `ALTER ROLE scap_app WITH PASSWORD '...'` bằng tài khoản chủ, hoặc `down -v` |
| Truy cập trả về `400 Invalid host header` | `ALLOWED_HOSTS` không khớp Host bạn dùng. Cách A phải vào bằng `localhost`; cách B bằng đúng `PUBLIC_DOMAIN` |
| `/docs` trả 404 | Đúng thiết kế: `DOCS_ENABLED=false` ở production |
| `caddy` restart liên tục, log ACME lỗi | `PUBLIC_DOMAIN` là tên miền công khai nhưng DNS chưa trỏ về máy / cổng 80 bị chặn. Đổi sang `scap.localhost`, hoặc dùng cách A |
| `bind: address already in use` cổng 80/443 | IIS/Apache/nginx đang chiếm. Tắt chúng, hoặc dùng cách A |
| Build lỗi ở `uv sync --no-dev --frozen` | `uv.lock` không khớp `pyproject.toml`, hoặc mạng chậm. Chạy `uv lock` trên host rồi build lại |
| Đăng nhập báo sai dù mật khẩu đúng | Đã bị lockout sau 5 lần sai. Chờ `LOGIN_LOCKOUT_SECONDS=900`, hoặc `UPDATE users SET failed_login_attempts=0, locked_until=NULL WHERE username='...';` |
| Hội thoại cũ lỗi giải mã | `MASTER_ENCRYPTION_KEY` đã bị đổi. Khôi phục khóa cũ hoặc dùng keyring rotation |
| Bot trả lời chung chung | Chưa có `GOOGLE_GENAI_API_KEY` → chế độ DEMO AI, vẫn đủ để demo bảo mật |
| Muốn reset sạch từ đầu | `docker compose down -v` → `docker compose up -d --build` → nạp lại dữ liệu mẫu (Phần 5) |

---

## Phần 9. Nếu deploy VPS thật (cách C)

1. Trỏ DNS A/AAAA của `PUBLIC_DOMAIN` về IP VPS, mở firewall 80 + 443.
2. `CADDY_EMAIL` là email thật (Let's Encrypt gửi cảnh báo hết hạn).
3. `SECURITY_TXT_EXPIRES` đặt dưới 1 năm, nhớ cập nhật trước khi hết hạn (RFC 9116).
4. Sinh lại toàn bộ secrets trên máy chủ, không tái dùng secret đã từng nằm trong
   file bài tập: `python scripts/generate_secrets.py`.
5. Pin base image theo digest cho chuỗi cung ứng:

   ```bash
   docker buildx imagetools inspect python:3.12-slim --format '{{println .Manifest.Digest}}'
   docker compose build --build-arg BASE_IMAGE=python:3.12-slim@sha256:<digest>
   ```

6. Sau khi có admin, cân nhắc `IDS_ENABLED=true` + gom log JSON về SIEM
   (`docs/LOGGING_AND_SIEM.md`), và chuyển khóa AES sang KMS/Vault thay vì biến
   môi trường — đây là giới hạn đã ghi nhận trong `README.md` mục 9.
