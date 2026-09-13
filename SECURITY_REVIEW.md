# Báo cáo rà soát bảo mật — SCAP

Rà soát logic từng chức năng và các biện pháp phòng thủ của dự án. Tài liệu này
cũng ghi lại những phần đã được củng cố thêm.

> Lưu ý quan trọng: không có hệ thống nào "an toàn tuyệt đối". Mục tiêu thực tế là
> giảm bề mặt tấn công và tuân thủ các nguyên tắc phòng thủ nhiều lớp (defense in
> depth). Dưới đây là hiện trạng và các cải tiến đã thực hiện.

## 1. Những phần đã làm TỐT (được xác nhận qua rà soát)

- **Băm mật khẩu Argon2id** (`security.py`): time=3, mem=64MB, parallelism=4; tự
  động rehash khi tham số thay đổi (`needs_rehash`). Có `dummy_hash` để chống dò
  tài khoản qua thời gian phản hồi (timing attack).
- **Chống brute-force**: khóa tài khoản sau số lần thất bại (`login_lockout_seconds`)
  kết hợp rate limit theo cả tài khoản và IP (`login:account:*`, `login:ip:*`).
- **JWT chặt chẽ** (`TokenService`): xác thực `iss`, `aud`, `nbf`, `iat`, `exp`,
  `jti`, `ver`; bắt buộc các claim tồn tại. Thu hồi token qua ba lớp: `AuthSession`,
  denylist `RevokedToken`, và `token_version`. Đổi role / khóa tài khoản đều
  revoke toàn bộ phiên đang hoạt động.
- **Envelope encryption** (`EnvelopeCryptoService`): nonce 12 byte ngẫu nhiên,
  DEK riêng mỗi hội thoại được Vault/KMS bọc, AAD ràng buộc owner/session/message
  UUID/index/role/epoch nên cả hoán đổi ciphertext cùng role cũng bị phát hiện.
  `CryptoService` chỉ còn hỗ trợ đọc/migrate dữ liệu legacy.
- **Chống IDOR**: `require_owned_session` trả 404 (không phải 403) để tránh liệt kê
  tài nguyên. Truy vấn luôn lọc theo `owner_id`.
- **Chống SQL injection**: dùng hoàn toàn SQLAlchemy ORM (tham số hóa).
- **HTTP security headers**: CSP, HSTS (production), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`,
  `Cache-Control: no-store`.
- **Giới hạn kích thước request** 1 MiB; **error handler** không rò rỉ chi tiết lỗi
  ra client (chỉ trả `request_id`).
- **CORS** khóa chặt, `allow_credentials=False`.
- **Bảo vệ admin**: không thể tự xóa / tự khóa / tự đổi role; không xóa được admin
  khác.
- **X-Forwarded-For KHÔNG được tin tưởng** ở tầng ứng dụng (tránh giả mạo IP để né
  rate limit / đầu độc log) — xử lý proxy-aware phải đặt ở tầng edge.
- **Guard production/high** (`config.py`): production bắt buộc secret key, Redis,
  allowlist và tắt demo/docs; high còn bắt buộc PostgreSQL, Vault/managed KMS,
  OIDC proxy gate, WORM checkpoint, MFA đặc quyền và cấm master key trong web runtime.
- **Audit trail** đầy đủ cho mọi hành động nhạy cảm, có làm sạch dữ liệu log
  (`safe_json` chống log injection / CRLF).

## 2. Những phần đã CỦNG CỐ THÊM trong lần rà soát này

1. **Chống tấn công Host header / DNS rebinding**
   - Thêm `TrustedHostMiddleware`, điều khiển bằng biến `ALLOWED_HOSTS`.
   - Bắt buộc cấu hình `ALLOWED_HOSTS` ở production (thêm guard trong `config.py`).
   - Ở môi trường dev, nếu để trống thì middleware không bật (không ảnh hưởng chạy thử).

2. **Chống cạn kiệt tài nguyên (DoS) khi tạo phiên**
   - Giới hạn số phiên hội thoại mỗi người dùng qua `MAX_SESSIONS_PER_USER`
     (mặc định 100). Vượt giới hạn trả HTTP 409 và ghi audit `outcome=blocked`.

3. **Giao diện đăng nhập**
   - Thiết kế lại thành card căn giữa gọn gàng; chỉ hiển thị đăng nhập / tạo tài
     khoản. Header và các tính năng chỉ xuất hiện SAU khi đăng nhập thành công
     (`app_sec` ẩn cho tới khi có token hợp lệ).
   - Hàm `do_register` kiểm tra đầu vào rõ ràng theo đúng chính sách backend.

4. **DLP, E2EE, export và bằng chứng kiểm toán**
   - DLP chuẩn hóa Unicode, phân loại allow/redact/confirm/block/local-only, quét
     cả input/output AI; consent có timestamp/version và context tối thiểu.
   - Server boundary cho device proof/prekey/membership/opaque Double Ratchet/MLS
     envelope, unique replay guard; không có private key hay plaintext E2EE.
   - Export paging bằng streaming, recent step-up và vé 60 giây dùng một lần;
     Gradio không còn ghi JSON plaintext vào thư mục temp.
   - Chuỗi audit có checkpoint ký và giao ra HTTPS WORM để phát hiện tail deletion.
   - Retention theo mode xóa ciphertext + wrapped DEK và dọn artifact ngắn hạn.

## 3. Khuyến nghị tiếp theo (tùy mức độ triển khai thực tế)

- **Chạy sau reverse proxy có TLS** (Caddy đã có `Caddyfile`); đặt xử lý IP thật
  ở tầng proxy và chuyển tiếp an toàn.
- **Redis cho rate limit** khi chạy nhiều worker/instance (in-memory limiter chỉ
  đúng cho 1 tiến trình).
- **Provision và kiểm thử** IAM Vault/KMS, OIDC IdP/proxy, retention-locked WORM,
  backup lifecycle và cảnh báo SOC; adapter trong code không thay thế hạ tầng thật.
- **Hoàn thiện client E2EE** bằng thư viện Double Ratchet/RFC 9420 MLS đã được
  kiểm toán, chạy interoperability vectors và pentest độc lập trước khi gắn nhãn production.
- **Quét phụ thuộc** định kỳ (đã có `dependabot.yml` và workflow security) và chạy
  `pip-audit` / `bandit` trong CI.
- **Giám sát & cảnh báo**: endpoint `security-alerts` đã có; nên đẩy sang hệ thống
  giám sát tập trung khi vận hành thật.

## 4. Cách bật các cấu hình mới

Trong `.env` (production):

```
ALLOWED_HOSTS=chat.example.com,www.chat.example.com
MAX_SESSIONS_PER_USER=100
```

Hồ sơ đầy đủ nằm tại `docs/HIGH_SECURITY_DEPLOYMENT.md`; không sao chép riêng vài
biến rồi tuyên bố high-security vì guard còn kiểm tra KMS/OIDC/WORM và trạng thái demo.
