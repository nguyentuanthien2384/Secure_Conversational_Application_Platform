# Bản nâng cấp bảo mật v2 — Hướng dẫn tích hợp và trình diễn

Tài liệu này mô tả **những gì đã thay đổi**, **cách bật**, và **cách demo** trước
hội đồng. Xem `docs/GAP_ANALYSIS.md` để biết lý do từng thay đổi gắn với bài học nào.

---

## 1. Danh sách thay đổi

### File mới

| File | Vai trò | Bài |
|---|---|---|
| `src/app/audit_chain.py` | Chuỗi băm HMAC chống giả mạo audit log | 1, 4 |
| `src/app/ids.py` | IDS/IPS tầng ứng dụng (chữ ký + bất thường) | 7, 2, 3.2 |
| `src/app/siem.py` | Log bảo mật JSON một dòng cho SIEM | 7, 1 |
| `scripts/rotate_encryption_key.py` | Xoay vòng khóa AES-256-GCM | 4 |
| `scripts/db_least_privilege.sql` | Ba vai trò CSDL với quyền tối thiểu | 4, 1 |
| `tests/test_security_v2.py` | 38 test hồi quy cho các lớp trên | 8 |
| `docs/GAP_ANALYSIS.md` | Đối chiếu dự án với 9 slide | — |

### File đã sửa

| File | Thay đổi |
|---|---|
| `src/app/services.py` | **Sửa lỗi P0**: regex DLP bị escape hai lần; mở rộng thêm JWT/PEM/email |
| `src/app/security.py` | `CryptoService` hỗ trợ keyring nhiều phiên bản khóa |
| `src/app/audit.py` | Mỗi sự kiện được niêm phong vào chuỗi băm và đẩy sang SIEM |
| `src/app/models.py` | `AuditEvent` thêm `prev_hash`, `entry_hash` |
| `src/app/db.py` | Tự thêm hai cột trên cho database cũ (idempotent) |
| `src/app/config.py` | Thêm keyring, các công tắc IDS/SIEM/audit-chain |
| `src/app/main.py` | Middleware IDS/IPS; 4 endpoint quản trị mới; rate limit đổi mật khẩu; bỏ rò rỉ ở `/api/health` |
| `docker-compose.yml` | Hardening Postgres; phân đoạn mạng; giới hạn tài nguyên |
| `Dockerfile` | `HEALTHCHECK`; cài đặt theo `uv.lock` |
| `Caddyfile` | `security.txt`; chặn đường dẫn trinh sát; giới hạn method; COOP/CORP |
| `.env.example` | Tài liệu hóa toàn bộ biến mới |

### Giao diện mới (v2.1 – v2.2)

| Vị trí | Chức năng |
|---|---|
| Tab **Trò chuyện** | Băng thông báo DLP hiện lên khi hệ thống che dữ liệu nhạy cảm trước khi gửi sang AI, nói rõ đã che **nhóm** nào (không hiện lại giá trị) |
| Tab **Trò chuyện** | Danh sách phiên hội thoại **bấm chọn trực tiếp** (trước đây là Dropdown), mỗi hàng có ổ khoá nhắc trạng thái mã hoá; các nút quản lý gom vào Accordion cho gọn |
| Tab **Trò chuyện** | Dòng nhắc "Đã mã hoá — AES-256-GCM" trên khung chat; avatar khiên cho trợ lý |
| Tab **Bảo mật** (moderator/admin) | 4 khối: xác minh chuỗi băm audit · mẫu tấn công IDS phát hiện · phân tích hành vi bất thường theo cửa sổ thời gian · danh sách IPS đang chặn kèm nút gỡ chặn |

Ghi chú kỹ thuật: `dd_session` đổi từ `gr.Dropdown` sang `gr.Radio`. Hai component
này dùng chung API `choices`/`value` và đều có sự kiện `.input`, nên toàn bộ
handler cũ giữ nguyên. CSS `#session-list` biến mỗi lựa chọn thành một hàng
cuộn được.

### Endpoint mới

```
GET    /api/admin/audit/verify           # xác minh chuỗi băm audit (admin)
GET    /api/admin/ids/detections         # các lần khớp chữ ký (moderator+)
GET    /api/admin/ids/anomalies          # phát hiện bất thường (moderator+)
GET    /api/admin/ids/blocklist          # danh sách IP đang bị chặn (admin)
DELETE /api/admin/ids/blocklist/{ip}     # gỡ chặn (admin)
```

---

## 2. Bật các tính năng mới

Không cần thay đổi gì để chạy thử: mọi tính năng đều **bật mặc định** và tương
thích ngược. Database cũ được tự nâng cấp khi khởi động.

```bash
uv sync --group dev
uv run pytest -q                 # 5 file test
uv run python run_app.py
```

Các biến trong `.env` (tùy chọn):

```env
IDS_ENABLED=true
IDS_BLOCK_THRESHOLD=5          # điểm tích lũy: high=3, medium=2, low=1
IDS_BLOCK_SECONDS=900
AUDIT_CHAIN_ENABLED=true
SIEM_JSON_LOGS=true
PASSWORD_CHANGE_MAX_ATTEMPTS=5
PASSWORD_CHANGE_WINDOW_SECONDS=900
```

> **Lưu ý về khóa audit:** chuỗi băm dẫn xuất từ `APP_SECRET_KEY`. Nếu đổi
> `APP_SECRET_KEY`, chuỗi cũ sẽ không xác minh được nữa — đúng theo thiết kế,
> nhưng hãy xác minh và lưu trữ kết quả trước khi đổi.

---

## 3. Kịch bản demo (mỗi phần ~2 phút)

### Demo A — Lỗ hổng DLP đã được sửa (mạnh nhất về mặt kể chuyện)

```bash
uv run python -c "
from src.app.services import AIService
s = 'mật khẩu của tôi là password: SuperSecret123, thẻ 4111 1111 1111 1111'
print('Gửi đi:', AIService._redact_for_external_ai(s))
"
```

Kể chuyện: *"Lớp DLP này đã tồn tại trong mã nguồn từ đầu, có comment, có trong
tài liệu — nhưng suốt nhiều commit nó không che gì cả, vì regex bị escape sai
một dấu gạch chéo. Không có test nào chạm tới nên không ai biết. Đây là ví dụ
thực tế cho nguyên tắc Bài 8: biện pháp bảo mật không được kiểm thử thì không
tồn tại."*

Chạy `git log -p src/app/services.py` để chiếu đoạn diff nếu có repo.

### Demo B — Audit log chống giả mạo

```bash
# 1. Đăng nhập vài lần để sinh sự kiện, rồi xác minh
curl -s -H "Authorization: Bearer $ADMIN" localhost:8000/api/admin/audit/verify
# {"total_events":12,"verified_events":12,"chain_intact":true,"first_broken_id":null}

# 2. Đóng vai insider threat: sửa trực tiếp trong database
sqlite3 secure_chat.db "UPDATE audit_events SET outcome='success' WHERE id=3;"

# 3. Xác minh lại
curl -s -H "Authorization: Bearer $ADMIN" localhost:8000/api/admin/audit/verify
# {"chain_intact":false,"first_broken_id":3,"reason":"entry_hash_mismatch"}
```

Kể chuyện: kẻ tấn công có quyền ghi vào CSDL vẫn không sửa được log mà không bị
phát hiện, vì khóa HMAC không nằm trong CSDL. Và bản thân việc phát hiện cũng
được ghi lại thành sự kiện `audit.chain.broken`.

### Demo C — IDS/IPS chặn tấn công

```bash
curl -i "localhost:8000/api/health?id=1' OR '1'='1"
curl -i "localhost:8000/api/health?q=1 UNION SELECT username,password FROM users"
curl -i "localhost:8000/api/health?file=../../../../etc/passwd"
# lần thứ 2 trở đi: HTTP 403 + Retry-After

curl -s -H "Authorization: Bearer $ADMIN" localhost:8000/api/admin/ids/detections | jq
curl -s -H "Authorization: Bearer $ADMIN" localhost:8000/api/admin/ids/blocklist  | jq
```

Thử với `User-Agent: sqlmap/1.7` để minh họa phát hiện công cụ quét.

**Nói rõ trước hội đồng:** ứng dụng an toàn trước SQLi là nhờ **ORM tham số
hóa**, không nhờ WAF. WAF ở đây là lớp *phát hiện* bổ sung và có thể bị né.

### Demo D — Phân biệt brute force và password spraying

```bash
# spraying: mỗi tài khoản chỉ sai 2 lần -> KHÔNG kích hoạt khóa tài khoản
for u in demo.user demo.mod demo.boss; do
  for i in 1 2; do
    curl -s -X POST localhost:8000/api/auth/login \
      -H 'Content-Type: application/json' \
      -d "{\"username\":\"$u\",\"password\":\"sai-mat-khau-hoan-toan\"}" > /dev/null
  done
done

curl -s -H "Authorization: Bearer $ADMIN" localhost:8000/api/admin/ids/anomalies | jq
# IDS-CREDENTIAL-SPRAY: "... thất bại đăng nhập trên 3 tài khoản khác nhau"
```

Điểm nhấn: khóa tài khoản **không** phát hiện được kịch bản này vì mỗi tài
khoản đều dưới ngưỡng. Chỉ tương quan theo nguồn mới thấy.

### Demo E — Xoay vòng khóa mã hóa

```bash
python scripts/generate_secrets.py     # sinh khóa mới
# .env:
#   MASTER_ENCRYPTION_KEYS=1:<khóa_cũ>,2:<khóa_mới>
#   ACTIVE_KEY_VERSION=2

uv run python scripts/rotate_encryption_key.py --dry-run
uv run python scripts/rotate_encryption_key.py --to-version 2
```

Trước khi chạy, mở trang "Xem bản mã trong DB" để chỉ ra `key_version=1`; sau
khi chạy, tải lại để thấy `key_version=2` **mà nội dung hội thoại vẫn đọc được
bình thường** — chứng minh xoay khóa không mất dữ liệu, không downtime.

### Demo F — Log SIEM

```bash
uv run python run_app.py | grep '"event.dataset":"scap.audit"'
```

Mỗi dòng là một JSON theo chuẩn ECS:

```json
{"@timestamp":"2026-07-23T09:14:02.118+00:00","log.level":"warning",
 "event.action":"auth.login","event.outcome":"failure","event.severity":"warning",
 "source.ip":"127.0.0.1","http.request.id":"a3f...","audit.id":42,
 "audit.entry_hash":"9c1b...","scap.reason":"invalid_credentials"}
```

Chỉ ra: có `audit.entry_hash` trong log ngoài, nên ngay cả khi kẻ tấn công xóa
sạch bảng audit trong CSDL, bản sao ở SIEM vẫn cho phép đối chiếu.

---

## 4. Triển khai production

```bash
# 1. Khóa phụ thuộc (bắt buộc)
uv lock && git add uv.lock

# 2. Vai trò CSDL tối thiểu
psql -U secure_chat -d secure_chat \
     -v app_password="'$(openssl rand -base64 24)'" \
     -v auditor_password="'$(openssl rand -base64 24)'" \
     -f scripts/db_least_privilege.sql

# 3. Đổi DATABASE_URL sang vai trò scap_app + sslmode=require

# 4. Khởi chạy
docker compose up --build -d
docker compose ps        # cột STATUS phải hiện (healthy)
```

Kiểm tra hardening đã ăn:

```bash
docker compose exec app whoami                    # app, không phải root
docker compose exec app touch /test 2>&1          # Read-only file system
docker compose exec db psql -U scap_app -c \
  "DELETE FROM audit_events;"                     # ERROR: permission denied
curl -I https://$PUBLIC_DOMAIN/.well-known/security.txt
curl -I https://$PUBLIC_DOMAIN/wp-admin           # 404 từ Caddy
```

---

## 5. Cần lưu ý khi vận hành

- **Chuỗi băm cần ghi tuần tự.** Với một tiến trình, mutex là đủ. Với Postgres
  nhiều worker, `append_lock` tự dùng `pg_advisory_xact_lock`. Nếu chạy nhiều
  container ứng dụng, hãy kiểm chứng lại thứ tự ghi trước khi tin vào kết quả
  xác minh.
- **Blocklist của IPS nằm trong bộ nhớ**, mất khi khởi động lại. Đây là lựa
  chọn có ý thức cho một instance; đừng trình bày nó như giải pháp production.
- **`verify_chain` quét toàn bộ bảng.** Với log lớn, hãy dùng tham số `limit`
  hoặc chạy theo lịch (cron) thay vì gọi đồng bộ trong request.
- **IDS chỉ soi URL và header, không soi body.** Đây là chủ ý: đọc body trong
  middleware sẽ phá streaming và tạo ra điểm khuếch đại bộ nhớ cho kẻ tấn công.
  Nội dung body đã được Pydantic và ORM xử lý an toàn về mặt cấu trúc.
