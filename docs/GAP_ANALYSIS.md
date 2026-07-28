# Đối chiếu dự án với chương trình môn học (Bài 1 → Bài 8)

Tài liệu này rà soát mã nguồn thực tế của `btl-atbmtt` so với từng nội dung trong
chín slide của môn *Bảo mật Ứng dụng và Hệ thống* (CSE702005-1-1-25). Mỗi dòng
chỉ được đánh **Đạt** khi có **mã nguồn chạy được**, không tính tài liệu mô tả.

Ký hiệu: ✅ Đạt · 🟡 Đạt một phần · ❌ Chưa có · 🆕 Bổ sung ở lần rà soát v2

---

## 0. Tóm tắt điều hành

| Hạng mục | Trước rà soát | Sau rà soát v2 |
|---|---|---|
| Số biện pháp có mã nguồn | 41 | 58 |
| Lỗ hổng nghiêm trọng (P0) | **1 (đang mở)** | 0 |
| Bài học có mảng thiếu hoàn toàn | Bài 6, Bài 7 | không |
| Kiểm thử bảo mật tự động | 4 file | 5 file (+38 test) |

**Phát hiện quan trọng nhất:** lớp DLP che dữ liệu nhạy cảm trước khi gửi ra
nhà cung cấp AI bên ngoài **không hoạt động** trong suốt thời gian qua. Chi tiết
ở mục "Phát hiện P0" bên dưới.

---

## 1. Phát hiện P0 — Lớp DLP chết âm thầm

**Vị trí:** `src/app/services.py` → `AIService._redact_for_external_ai`
**Mức độ:** Nghiêm trọng (rò rỉ dữ liệu qua biên tin cậy)
**Liên quan:** Bài 1 §Confidentiality · Bài 4 §4.4 · Bài 5 §5.2

### Mã lỗi

```python
patterns = (
    (r"(?i)\\b(password|passphrase|secret)\\s*[:=]\\s*\\S+", r"\\1=[REDACTED]"),
    ...
)
```

Trong chuỗi **raw** (`r"..."`), `\\b` là *dấu gạch chéo ngược + chữ b*, chứ không
phải ký tự biên từ `\b`. Toàn bộ 6 quy tắc vì thế không bao giờ khớp.

### Bằng chứng

```
Đầu vào : my password: hunter2xyz, api_key=AIzaSy..., card 4111 1111 1111 1111
Đầu ra  : my password: hunter2xyz, api_key=AIzaSy..., card 4111 1111 1111 1111
          ^ không có gì bị che
```

Hệ quả: mật khẩu, API key, số thẻ, CCCD, số điện thoại người dùng gõ trong hội
thoại được gửi **nguyên văn** tới Google Gemini. Việc tin nhắn được mã hóa
AES-256-GCM trong database **không cứu được** tình huống này, vì rò rỉ xảy ra ở
đường ra (egress), không phải ở nơi lưu trữ.

### Đã sửa

Regex được biên dịch sẵn với escape đúng, mở rộng thêm JWT, private key PEM,
Google API key, email; và được khóa lại bằng 8 test tham số hóa trong
`tests/test_security_v2.py::test_dlp_redacts_sensitive_values_before_external_ai`.

### Bài học cho báo cáo

Đây là minh chứng sống cho luận điểm **Bài 8 §8.3**: *một biện pháp bảo mật
không có kiểm thử tự động thì không phải là biện pháp bảo mật, mà chỉ là ý
định*. Lớp DLP tồn tại đầy đủ trong mã nguồn, có comment giải thích, có trong
tài liệu — nhưng không có test nào chạm tới nên nó chết mà không ai biết.

---

## 2. Bài 1 — Tổng quan Bảo mật Ứng dụng và Hệ thống

### 2.1. C.I.A

| Thuộc tính | Hiện thực | Trạng thái |
|---|---|---|
| Confidentiality | AES-256-GCM cho nội dung chat; TOTP seed mã hóa riêng; Argon2id cho mật khẩu; TLS ở Caddy | ✅ |
| Confidentiality (egress) | DLP che dữ liệu nhạy cảm trước khi gửi AI ngoài | 🆕 (đã sửa lỗi P0) |
| Integrity | AEAD với AAD ràng buộc `session_id\|role\|key_version`; JWT ký HS256 | ✅ |
| Integrity (log) | Chuỗi băm HMAC-SHA256 cho audit log | 🆕 |
| Availability | Rate limit nhiều tầng; giới hạn body 1 MiB; `MAX_SESSIONS_PER_USER`; healthcheck + `pids_limit`/`mem_limit` | 🆕 bổ sung |

### 2.2. A.A.A

| Thành phần | Hiện thực | Trạng thái |
|---|---|---|
| Authentication | Argon2id + TOTP RFC 6238 tự cài đặt + mã khôi phục dùng một lần | ✅ |
| Authorization | RBAC ba vai trò; kiểm tra quyền sở hữu theo từng phiên | ✅ |
| Accounting | `audit_events` ghi mọi hành động nhạy cảm | ✅ |
| Accounting — **chống giả mạo** | Trước đây: bất kỳ ai có quyền SQL đều sửa/xóa log được mà không để lại dấu vết | ❌ → 🆕 |

**Vì sao chuỗi băm quan trọng:** một audit log có thể bị sửa im lặng thì không
phải là bằng chứng. Đây đúng là kịch bản **Insider Threat** ở Bài 1 §f — quản
trị viên có quyền hợp pháp, xóa dòng log của chính mình sau khi hành động.

```
entry_hash = HMAC-SHA256(khóa_audit, prev_hash ‖ canonical(bản_ghi))
```

Khóa audit dẫn xuất từ `APP_SECRET_KEY` với nhãn riêng (tách khóa — không dùng
chung với khóa ký JWT) và **không nằm trong database**, nên kẻ chỉ có quyền SQL
có thể xóa nhưng không thể giả mạo chuỗi hợp lệ.

Đã kiểm chứng bằng mô phỏng:

| Hành vi tấn công | Kết quả phát hiện |
|---|---|
| Sửa nội dung một dòng | `entry_hash_mismatch` tại đúng dòng đó |
| Xóa một dòng ở giữa | `prev_hash_mismatch` |
| Đảo thứ tự hai dòng | `prev_hash_mismatch` |
| Tự tính lại chuỗi bằng khóa đoán | `entry_hash_mismatch` ngay dòng đầu |

Kiểm tra qua `GET /api/admin/audit/verify`.

### 2.3. Least Privilege & Defense in Depth

| Biện pháp | Trạng thái |
|---|---|
| Container chạy user không phải root, `read_only`, `cap_drop: ALL` | ✅ |
| Admin **không** đọc được hội thoại người dùng | ✅ (thiết kế rất tốt) |
| Container Postgres được hardening | ❌ → 🆕 |
| **Vai trò DB tối thiểu** — ứng dụng chạy bằng vai trò sở hữu schema | ❌ → 🆕 `scripts/db_least_privilege.sql` |
| Phân đoạn mạng (DB/Redis không ra Internet) | 🟡 → 🆕 mạng `backend` `internal: true` |

Điểm đáng chú ý: ứng dụng đang kết nối DB bằng chính vai trò **sở hữu schema**.
Một lỗi SQL injection duy nhất là đủ để `DROP TABLE`. Script mới tách ba vai
trò và — quan trọng nhất — **thu hồi `UPDATE`/`DELETE` trên `audit_events`**,
biến bảng này thành gần như append-only ở tầng CSDL. Kết hợp với chuỗi băm:
tầng CSDL **ngăn chặn**, chuỗi băm **phát hiện** nếu ngăn chặn thất bại. Đúng
mô hình Defense in Depth ở §e3.

---

## 3. Bài 2 — Tấn công và Phòng thủ trên không gian mạng

| Nội dung slide | Hiện thực | Trạng thái |
|---|---|---|
| §2.3 Brute force | Khóa tài khoản + rate limit theo cả tài khoản và IP | ✅ |
| §2.3 Credential stuffing / spraying | Không phân biệt được với brute force | ❌ → 🆕 |
| §2.3 DoS | Rate limit, giới hạn body, giới hạn tài nguyên container | ✅ |
| §2.5 Phòng thủ chủ động | Chỉ có phòng thủ thụ động | ❌ → 🆕 IPS tự chặn nguồn |
| §2.6 Giám sát tập trung | Có tài liệu, **không có mã** | ❌ → 🆕 `siem.py` |

**Phân biệt brute force và password spraying** (mới): nhiều lần thất bại trên
*một* tài khoản là brute force; nhiều lần thất bại trên *nhiều* tài khoản từ
cùng một nguồn là spraying. Hai kịch bản cần phản ứng khác nhau — khóa tài
khoản không cứu được spraying vì mỗi tài khoản chỉ bị thử 1–2 lần, dưới ngưỡng
khóa. Luật `IDS-CREDENTIAL-SPRAY` đếm số tài khoản *khác nhau* bị tấn công từ
một IP.

---

## 4. Bài 3.1 + 3.2 — Bảo mật ứng dụng Web

| Lỗ hổng | Biện pháp trong dự án | Trạng thái |
|---|---|---|
| SQL Injection | SQLAlchemy ORM tham số hóa 100%, không có chuỗi SQL ghép tay | ✅ |
| XSS | Gradio render qua component, không chèn HTML thô; CSP | ✅ |
| CSRF | API dùng Bearer token, không dùng cookie phiên → không có bề mặt CSRF cổ điển | ✅ |
| IDOR / BOLA | `require_owned_session` lọc theo `owner_id`, trả 404 chống liệt kê | ✅ |
| Security headers | CSP phân biệt theo route, HSTS, `X-Frame-Options`, `nosniff`, `Referrer-Policy` | ✅ |
| Host header injection | `TrustedHostMiddleware` | ✅ |
| §3.2 **WAF** | Không có | ❌ → 🆕 |
| §3.2.4 Công cụ kiểm thử | ZAP baseline, Semgrep, Bandit, Trivy trong CI | ✅ |

**Về WAF (`ids.py`) — cần nói thẳng trong báo cáo:** dự án an toàn trước SQLi
là **nhờ ORM tham số hóa**, không nhờ WAF. Bộ chữ ký chỉ để **phát hiện và ghi
nhận** nỗ lực tấn công, và có thể bị vượt qua dễ dàng. Trình bày WAF như lý do
ứng dụng an toàn là sai về mặt học thuật; trình bày nó như lớp *phát hiện* bổ
sung mới đúng.

10 nhóm chữ ký: SQLi (3), XSS (2), path traversal, command injection, SSTI,
Log4Shell/JNDI, NoSQL injection — cộng nhận diện công cụ quét (sqlmap, nikto,
ZAP, Burp…) và đường dẫn trinh sát (`/wp-admin`, `/.env`, `/.git/`).

Đã kiểm chứng: **7/7 payload tấn công bị phát hiện** (kể cả double-encoding
`%252e%252e%252f`), **0 cảnh báo giả** trên lưu lượng bình thường.

CSP còn `'unsafe-inline'` cho giao diện Gradio — hạn chế của framework, đã ghi
nhận trong mã nguồn, cần nonce/hash ở giai đoạn 2.

---

## 5. Bài 4 — Bảo mật Cơ sở dữ liệu

| Nội dung | Hiện thực | Trạng thái |
|---|---|---|
| §4.3 Mã hóa dữ liệu nhạy cảm | AES-256-GCM, khóa ngoài DB | ✅ |
| §4.3 **Vòng đời khóa (rotation)** | `key_version` có sẵn nhưng `decrypt` **từ chối** mọi version ≠ 1 → xoay khóa là bất khả thi | ❌ → 🆕 |
| §4.3 Least privilege | Chạy bằng vai trò owner | ❌ → 🆕 |
| §4.3 Mã hóa đường truyền tới DB | Chỉ dựa vào mạng Docker | 🟡 → 🆕 hướng dẫn `sslmode=require` + `hostssl` |
| §4.4 Audit truy cập dữ liệu | `audit_events` + log DDL/kết nối của Postgres | 🆕 bổ sung |
| §4.7 Chống SQLi ở tầng lập trình | ORM tham số hóa | ✅ |

**Về xoay vòng khóa:** một khóa dùng vĩnh viễn nghĩa là toàn bộ dữ liệu lịch sử
mất an toàn cùng lúc nếu khóa lộ. `CryptoService` nay giữ **một keyring**: khóa
đang hoạt động dùng để mã hóa, mọi khóa cũ vẫn dùng để giải mã. Nhờ vậy xoay
khóa **không cần downtime** và không cần re-encrypt tất cả ngay lập tức.

```
MASTER_ENCRYPTION_KEYS=1:<khóa_cũ>,2:<khóa_mới>
ACTIVE_KEY_VERSION=2
uv run python scripts/rotate_encryption_key.py --dry-run
```

Đã kiểm chứng: dữ liệu mã hóa bằng khóa v1 vẫn đọc được sau khi chuyển sang v2;
khóa cũ **không** đọc được dữ liệu mới; ràng buộc AAD chống hoán đổi bản mã
giữa các phiên/vai trò vẫn nguyên vẹn sau khi xoay khóa.

---

## 6. Bài 5 — Bảo mật API và Hệ điều hành

| Nội dung | Hiện thực | Trạng thái |
|---|---|---|
| §5.2 Broken Object Level Authorization | Kiểm tra quyền sở hữu từng request | ✅ |
| §5.2 Broken Authentication | JWT đủ `iss/aud/nbf/exp/jti/ver`, ba lớp thu hồi | ✅ |
| §5.2 Excessive Data Exposure | Response model Pydantic, không trả `password_hash` | ✅ |
| §5.2 Rate limiting | Login, đăng ký, gửi tin, MFA | ✅ |
| §5.2 Rate limiting — đổi mật khẩu | Không có → có thể dò mật khẩu hiện tại không giới hạn | ❌ → 🆕 |
| §5.2 Improper Assets Management | `DOCS_ENABLED=false` bắt buộc ở production | ✅ |
| §5.2 Rò rỉ thông tin qua health check | `/api/health` trả về tên môi trường | 🟡 → 🆕 đã bỏ ở production |
| §5.5 Hardening OS/container | User thường, `read_only`, `cap_drop`, `no-new-privileges` | ✅ |
| §5.5 Healthcheck / tự phục hồi | Không có | ❌ → 🆕 `HEALTHCHECK` trong Dockerfile |

---

## 7. Bài 6 — Mã độc và Mã khai thác

| Nội dung | Đánh giá |
|---|---|
| §6.3 Quy trình khai thác lỗ hổng | 🆕 Chữ ký IDS phát hiện các giai đoạn trinh sát và khai thác (traversal, command injection, JNDI) |
| §6.4 Kỹ thuật che giấu | 🆕 Giải mã URL hai lớp để chống né bộ lọc bằng encoding |
| §6.7 Phòng chống | ✅ Trivy quét image và filesystem; Dependabot; `pip-audit`; không có chức năng upload file nên **không có bề mặt tấn công qua tệp** |

**Ghi chú trung thực cho báo cáo:** dự án không có chức năng tải tệp lên, nên
việc tích hợp antivirus (ClamAV) là **không cần thiết** và sẽ là "bảo mật hình
thức". Nếu sau này bổ sung upload, đó là lúc cần ClamAV + kiểm tra magic bytes
+ lưu ngoài web root. Nên nêu điều này như một quyết định thiết kế có ý thức,
không phải một thiếu sót.

---

## 8. Bài 7 — Hạ tầng mạng E-Commerce: VPN – Firewall – IDS

| Thành phần | Trước | Sau |
|---|---|---|
| §7.2 Firewall | 🟡 Chỉ có mạng Docker phẳng | 🆕 Phân đoạn `backend` (internal) / `edge`; lọc method và đường dẫn trinh sát tại Caddy |
| §7.3 **IDS** | ❌ Không có | 🆕 `ids.py` — hai engine: chữ ký + bất thường |
| §7.3 **IPS** | ❌ Không có | 🆕 Tự chặn nguồn theo điểm rủi ro tích lũy, có thời hạn, admin gỡ chặn được |
| §7.5 SIEM / log tập trung | ❌ Chỉ có tài liệu | 🆕 `siem.py` — JSON một dòng theo chuẩn ECS ra stdout |
| §7.1 VPN | ❌ Không áp dụng | Ghi nhận là ngoài phạm vi: đây là ứng dụng web công khai, không phải mạng nội bộ. Nếu triển khai thật, trang quản trị nên đặt sau VPN/mTLS |

**Kiến trúc IDS hai engine:**

| Engine | Nguồn dữ liệu | Phát hiện được | Điểm mù |
|---|---|---|---|
| Chữ ký | URL + header của request | Tấn công đã biết, công cụ quét | Tấn công mới; dễ bị né |
| Bất thường | Chuỗi sự kiện audit | Brute force, spraying, dò IDOR, hammering MFA | Tấn công chậm dưới ngưỡng |

Điểm mạnh của engine bất thường: nó nhìn thấy thứ IDS mạng **không bao giờ**
thấy — một request IDOR đã xác thực là lưu lượng TLS hợp lệ tới endpoint hợp
lệ; chỉ khi tương quan với audit log mới thấy "tài khoản này bị từ chối truy
cập 12 lần trong 5 phút".

**Về SIEM:** audit log trong database đúng cho *điều tra sau sự cố*, nhưng sai
cho *phát hiện* — không hệ thống SIEM nào đi poll một bảng SQL. Nay mỗi sự kiện
đồng thời được ghi ra stdout dạng JSON một dòng, sẵn sàng cho Loki/ELK/Wazuh
mà không cần parser riêng. Bảo đảm: **không bao giờ ghi mật khẩu, token, nội
dung tin nhắn hay TOTP seed** — chỉ ghi độ dài và định danh.

---

## 9. Bài 8 — Quy trình phát triển phần mềm an toàn (SSDLC)

| Giai đoạn | Hiện thực | Trạng thái |
|---|---|---|
| Requirements | `docs/SECURITY_REQUIREMENTS.md` | ✅ |
| Design | Threat model STRIDE | ✅ |
| Implementation | Ruff, code review, secure defaults | ✅ |
| **Testing** | Bandit, Semgrep, pytest — nhưng **lớp DLP không có test** | 🟡 → 🆕 +38 test |
| Deployment | Docker, CI, Trivy, SBOM CycloneDX | ✅ |
| **Chuỗi cung ứng** | Thiếu `uv.lock` → `uv sync` giải phụ thuộc lại mỗi lần build | ❌ → 🆕 |
| Operations | IR playbook, backup, logging docs | ✅ |
| Báo cáo lỗ hổng | Không có `security.txt` | ❌ → 🆕 RFC 9116 tại Caddy |

**Về `uv.lock`:** không có lockfile nghĩa là hai lần build cùng một commit có
thể ra hai bộ phụ thuộc khác nhau. SBOM sinh ra khi đó mô tả *một* bản build,
không phải bản đang chạy — và đó chính là kịch bản tấn công chuỗi cung ứng
(§8.4). Hãy chạy `uv lock` và **commit file này**; Dockerfile đã sẵn sàng dùng
`--frozen`.

---

## 10. Việc cần làm trước khi nộp

| # | Việc | Lý do |
|---|---|---|
| 1 | `uv lock` rồi commit `uv.lock` | Build tái lập được — bắt buộc cho Bài 8 |
| 2 | Xóa `secure_chat.db`, `.coverage`, `__pycache__/`, `.pytest_cache/` khỏi gói nộp | File `.db` chứa dữ liệu thật; `.gitignore` đã loại nhưng bản zip vẫn kèm |
| 3 | `uv run pytest` cho toàn bộ 5 file test | Xác nhận không hồi quy |
| 4 | Chụp màn hình `GET /api/admin/audit/verify` trước và sau khi cố ý sửa một dòng log | Bằng chứng trực quan mạnh nhất cho phần Bài 1 §AAA |
| 5 | Chụp màn hình IDS chặn `sqlmap` hoặc payload `' OR 1=1` | Bằng chứng cho Bài 7 §7.3 |
| 6 | Chạy `scripts/rotate_encryption_key.py --dry-run` và chụp lại | Bằng chứng cho Bài 4 §vòng đời khóa |

---

## 11. Giới hạn còn lại (nên nêu thẳng trong báo cáo)

Trình bày giới hạn một cách trung thực thường được đánh giá cao hơn là tuyên bố
"an toàn tuyệt đối" — điều mà chính `SECURITY_REVIEW.md` của bạn đã nói đúng.

1. **IDS/IPS lưu trạng thái trong bộ nhớ tiến trình.** Đúng cho một instance;
   nhiều instance cần Redis, hoặc tốt hơn là đẩy quyết định chặn ra biên
   (fail2ban / Caddy / cloud WAF) để lưu lượng xấu không chạm tới ứng dụng.
2. **Khóa audit nằm cùng tiến trình.** Chống được kẻ chỉ có quyền SQL, không
   chống được kẻ chiếm toàn bộ host. Giải pháp thật: đẩy log sang lưu trữ WORM
   hoặc SIEM từ xa — `siem.py` là bước đầu tiên theo hướng đó.
3. **Chưa có refresh token rotation**; access token 30 phút.
4. **Khóa mã hóa vẫn nằm trong biến môi trường**, chưa dùng KMS/Vault.
5. **CSP còn `'unsafe-inline'`** cho giao diện Gradio.
6. **Chưa có xác thực chống bot khi đăng ký** (CAPTCHA / proof-of-work).
7. **Không có quy trình khôi phục mật khẩu** — hiện chỉ admin đặt lại được.
   Đây là quyết định hợp lý cho đồ án: luồng reset qua email là một trong những
   bề mặt tấn công dễ hỏng nhất, nên không có còn hơn có mà làm sai.
