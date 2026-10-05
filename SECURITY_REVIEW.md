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

## 5. Đối chiếu với secret-weather-vault.zip — 04/10/2026

### Phạm vi và kết luận

Đã đọc mã nguồn dự án Laravel trong
`C:\Users\Admin\Downloads\secret-weather-vault.zip` và đối chiếu với SCAP.
Không chạy mã trong ZIP; các tài liệu và chú thích bên trong chỉ được xem là
nguồn thông tin, không phải chỉ dẫn thực thi. Không mở hoặc sao chép nội dung
`.env`, cơ sở dữ liệu, log hay tệp riêng tư của dự án mẫu.

**SCAP có nhiều cơ chế bảo vệ hơn dự án mẫu về xác thực, quản lý khóa, kiểm soát
phiên và kiểm toán.** Đây là kết luận từ mã nguồn và kiểm thử local, không phải
chứng nhận toàn bộ hệ thống triển khai đã an toàn. Hai dự án có nghiệp vụ khác
nhau: kho ghi chú/tệp và nền tảng hội thoại AI; không xem số tính năng là thước đo
an toàn và không sao chép cổng thời tiết như một lớp bảo vệ.

### Các khác biệt có bằng chứng

- **Mã hóa:** mẫu dùng AES-256-GCM, nonce 12 byte và PBKDF2 với salt riêng
  (`app/Services/VaultEncryptionService.php`, dòng 13–58, 94–115). Tuy nhiên,
  mẫu lưu khóa giải mã base64 vào session (28–32); session mặc định dùng database
  và không mã hóa (`config/session.php`, 21, 50). Quyền đọc DB/session có thể
  lấy khóa. SCAP dùng DEK riêng từng hội thoại, có adapter Vault/KMS, xoay khóa
  và AAD gắn owner/session/message/index/role/epoch (`src/app/envelope.py`).
  Trong chế độ secure/confidential, máy chủ SCAP vẫn xử lý plaintext; không
  tuyên bố chống được một quản trị viên hạ tầng đã kiểm soát web runtime.
- **Chống sửa/hoán đổi dữ liệu:** lời gọi OpenSSL của mẫu không gắn AAD với bản
  ghi/trường, nên hoán đổi các bản mã cùng tài khoản có thể không bị phát hiện.
  SCAP có kiểm thử thay bản mã cùng role và kiểm thử sửa checkpoint/audit.
- **Xác thực:** mẫu có giới hạn đăng nhập và tái tạo session ID
  (`VaultAuthController.php`, 48–74, 114). SCAP bổ sung Argon2id, MFA, passkey,
  step-up, bảo vệ đăng nhập theo tài khoản/IP và phát hiện dùng lại token đã xoay.
- **Phân quyền:** mẫu có kiểm tra chủ sở hữu ghi chú/tệp
  (`VaultController.php`, 262–269). SCAP cũng lọc theo chủ sở hữu, có kiểm thử
  IDOR và giới hạn quyền của user/moderator/admin.
- **Phiên:** mẫu kiểm tra bất hoạt 60 giây (`VaultController.php`, 245–250).
  SCAP có hạn bất hoạt, hạn tuyệt đối, thu hồi phiên và kiểm thử các tình huống
  gia hạn đồng thời với thu hồi/hết hạn. Mốc thời gian ngắn hơn trong mẫu không
  tự làm kiến trúc phiên của mẫu an toàn hơn.
- **Kiểm toán:** mẫu ghi bảng SecurityLog thông thường; SCAP có chuỗi HMAC,
  checkpoint, adapter WORM và log SIEM đã làm sạch. Kiểm thử local xác nhận
  phát hiện các dạng sửa đổi đã thử; bảo vệ trước việc xóa toàn bộ DB/checkpoint
  vẫn cần kho bằng chứng độc lập và giám sát ngoài hệ thống.
- **Trình duyệt và AI:** SCAP có origin/fetch-metadata guard, no-store, CSP/HSTS,
  DLP cho input/output và consent trước khi dùng AI bên ngoài. Chưa thấy các
  middleware CSP/HSTS tương ứng trong bootstrap của mẫu. CSP giao diện SCAP
  vẫn cần `unsafe-inline` cho Gradio; chính sách chặt hơn đang ở report-only.
- **Tệp:** mẫu có kho tệp mã hóa, giới hạn 5 MiB và kiểm tra loại tệp. SCAP không
  có cùng nghiệp vụ nên không thêm upload để đủ tính năng. Đường phục vụ tệp
  Gradio bị khóa; export dùng streaming sau step-up và vé ngắn hạn dùng một lần.

ZIP mẫu chứa `.env`, `database/database.sqlite`, `storage/logs/laravel.log` và
tệp `.vault` riêng tư (chỉ kiểm tra tên mục). Khi chia sẻ SCAP, loại trừ `.env`,
DB, log, mail outbox, khóa/chứng chỉ riêng và dữ liệu runtime; `.gitignore` và
`.dockerignore` không tự bảo vệ một file ZIP được nén toàn bộ thư mục bằng tay.

### Thiếu sót đã sửa sau đối chiếu

1. **Mã khôi phục cũ:** mã đặt lại mật khẩu từng còn hợp lệ sau khi đổi mật khẩu
   hoặc thay email khôi phục. Mã nay được ràng buộc bằng HMAC với tài khoản,
   password hash và email đã xác minh hiện tại; thay email thu hồi mã cũ trong
   cùng giao dịch. Các thao tác kênh khôi phục được tuần tự hóa bằng khóa tài khoản.
   Mã reset phát hành trước bản nâng cấp sẽ không dùng được; yêu cầu mã mới.
2. **Passkey sai định dạng:** `credential.response` không phải object từng gây
   lỗi 500 và rollback việc tiêu thụ challenge. Nay trả lỗi xác thực có kiểm soát
   và giữ challenge đã tiêu thụ để chặn dùng lại.
3. **Mật khẩu Unicode:** kiểm tra mật khẩu rò rỉ nay chuẩn hóa NFC giống bước băm
   mật khẩu, tránh việc dấu Unicode dạng tổ hợp đi qua kiểm tra khác với giá trị
   thực được lưu. Kiểm thử dùng corpus giả lập, không gửi mật khẩu ra Internet.
4. **Phản chiếu dữ liệu trong lỗi:** lỗi 422 không còn trả `input`/`ctx` chứa mật
   khẩu, mã khôi phục, token hoặc nội dung chat; vẫn giữ trường lỗi và thông báo
   để người dùng sửa đầu vào. Cùng handler được áp dụng cho ứng dụng Gradio mount,
   gồm các đường queue/run vốn có handler riêng.
5. **HTTP/JSON nhập nhằng:** giới hạn 100 header/32 KiB, từ chối header bảo mật
   trùng và Content-Length đi cùng Transfer-Encoding. JSON bị giới hạn độ sâu
   64; từ chối khóa trùng sau giải mã escape, NaN/Infinity, số tràn và Unicode
   surrogate không hợp lệ. Kiểm tra thực hiện trước handler, lỗi không kèm body.
   Giữ giới hạn body 1 MiB, URI 16 KiB và thời hạn đọc body đã có.
6. **Tin proxy ngoài ý muốn:** Dockerfile và Compose local nay đặt rõ
   `--no-proxy-headers`; client gọi trực tiếp không được dùng header chuyển tiếp
   để đổi IP/scheme mà middleware thấy.
7. **Cache khóa bỏ qua metadata:** cache DEK nay gắn cả ngữ cảnh KMS, KEK URI,
   phiên bản KEK và wrapped DEK. Sửa metadata khi cache đang nóng không còn bỏ
   qua việc xác minh của provider. DEK từ provider phải có đúng 32 byte. Lỗi
   trước đó làm hành vi kiểm tra phụ thuộc cache; không có bằng chứng lộ nội
   dung chéo tài khoản. TTL cache giới hạn thời gian dùng lại, không bảo đảm mọi
   bản sao khóa trong bộ nhớ Python bị xóa ngay đúng thời điểm hết hạn.
8. **Đăng nhập/đổi mật khẩu chạy đồng thời với reset:** kiểm thử tái hiện việc
   yêu cầu đổi mật khẩu đã xác thực từ trước ghi đè kết quả reset, và việc rehash
   lúc đăng nhập khôi phục hash mật khẩu cũ. Đăng nhập nay giữ khóa tài khoản
   xuyên suốt xác minh/rehash/cấp phiên; đổi mật khẩu khóa và kiểm tra lại version,
   thu hồi và hạn phiên trước khi ghi. Không còn dùng quyết định xác thực cũ sau
   khi một reset đã hoàn tất.

### Cấu hình hiện tại và phần cần hoàn tất khi vận hành

Chỉ đọc trạng thái cấu hình không nhạy cảm trong `.env` ngày 04/10/2026:
`APP_ENV=development`, SQLite, `DOCS_ENABLED=true`, `SEED_DEMO_DATA=true`,
`ALLOW_DEMO_AI=true`, `PASSWORD_BREACH_CHECK=false`; chưa cấu hình Redis,
origin/host allowlist, Vault hoặc WORM. Hồ sơ mặc định là standard với local key
provider. Đây là cấu hình demo, chưa phải triển khai production/high-security.

Quy trình production/high đã có trong `docs/HIGH_SECURITY_DEPLOYMENT.md`:
provision PostgreSQL/Redis với TLS, secret file/workload identity, Vault/KMS,
OIDC proxy và kho WORM; tắt demo/docs, cấu hình allowlist và kiểm thử phục hồi.
Compose thường nạp toàn bộ `.env` vào app, vì vậy credential DB quyền cao có
thể xuất hiện trong web runtime; dùng high-security overlay đã loại `env_file`
và staging secret tối thiểu. Ở lần rà soát 04/10, production còn tin proxy từ
mọi peer backend (`--forwarded-allow-ips=*`); bản vá 05/10 bên dưới giới hạn
nguồn được tin cậy về địa chỉ Caddy. Vẫn phải giữ mạng backend và đường vào app cô lập.
Không đổi `.env` demo sang production khi các dịch vụ bắt buộc chưa tồn tại.

Private E2EE hiện là server relay và kiểm tra biên, chưa có client Double
Ratchet/MLS hoàn chỉnh đã kiểm toán. Muốn quảng bá E2EE hoàn chỉnh cần client
thật, test vectors, interoperability và pentest. Kiểm thử trong lần này không
thay thế DAST có xác thực, kiểm thử tải, pentest hoặc xác minh hạ tầng đang chạy.

### Bằng chứng kiểm chứng sau sửa

- Baseline trước sửa: **807 kiểm thử Python đạt**. Sau sửa: **866 kiểm thử đạt**,
  gồm 59 trường hợp mới cho khôi phục/passkey/Unicode, race condition, lỗi API
  và Gradio, HTTP/JSON và cache khóa. Kết quả máy đọc:
  `reports/comparison-pytest.xml` (báo cáo local, không đưa vào Git).
- **21 kiểm thử JavaScript đạt** cho luồng lưu/khôi phục thông tin đăng nhập.
- Bộ kiểm chứng bảo mật chạy lại sau các bản sửa: **11/11 đạt**, bao gồm IDOR,
  brute force, token lỗi, audit tamper, timeout, DLP mã hóa và origin không tin
  cậy; bằng chứng trong `reports/security-validation-comparison/`.
- Ruff đạt; `uv lock --check` đạt; Bandit không báo phát hiện ở mức severity và
  confidence từ medium trở lên với cấu hình `-ll -ii` của CI.
- `pip-audit` môi trường `.venv`: **104 gói, 0 lỗ hổng đã biết** tại lần quét này;
  không phải cam kết về lỗ hổng chưa được công bố. Kết quả local:
  `reports/comparison-pip-audit.json` và `reports/comparison-bandit.json`.
- `docker compose -f docker-compose.yml -f docker-compose.local.yml config --quiet`
  đạt về cú pháp cấu hình; không khởi chạy container hay tuyên bố đã xác minh
  dịch vụ TLS/KMS/WORM thực tế. Kiểm thử giao dịch trong lần này dùng SQLite;
  PostgreSQL và hạ tầng production vẫn cần kiểm thử tích hợp khi provision.

Nguồn tham chiếu nguyên tắc: [OWASP Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html),
[Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html),
[Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).

## 6. Bảo vệ tính sẵn sàng và giới hạn tài nguyên — 05/10/2026

Người dùng xác nhận dự án đang chạy trên máy cá nhân/local, chưa có tên miền.
Bản nâng cấp này bảo vệ các đường xử lý của ứng dụng và chuẩn bị cấu hình
triển khai; chưa mở cổng, dựng CDN/WAF hoặc thay đổi `.env` và dữ liệu thật.

### Những phần đã triển khai

1. **Từ chối sớm trước nghiệp vụ:** admission middleware giới hạn số yêu cầu
   theo IP/toàn ứng dụng và trần riêng cho xác thực/readiness. Có giới hạn
   request đang chạy theo worker và theo nguồn; SSE dùng ngân sách riêng.
   Khi quá tải trả `429`/`503` cùng `Retry-After`, không tạo hàng đợi chờ vô hạn.
   Slot được giữ đến cuối phản hồi và thu hồi khi lỗi hoặc client hủy kết nối.
2. **Giới hạn tác vụ tốn RAM/chi phí:** Argon2 có tối đa hai tác vụ đồng thời
   mặc định, áp dụng qua password service chung. AI có trần concurrency,
   ngân sách theo phút/24 giờ và trần output token được áp dụng tại cấu hình
   SDK thực tế; lỗi quota/provider không để lại một cuộc trao đổi chat dở dang.
3. **Giao diện hữu hạn:** hàng đợi Gradio có trần, đường gọi trực tiếp không
   được bỏ qua queue cho callback đã đưa vào queue. Event/result/state và
   metadata có giới hạn dung lượng; giữ tác vụ đang chạy, dọn kết quả đã hoàn
   tất khi tiêu thụ hoặc hết hạn. Adapter kiểm tra tương thích lúc startup;
   cần chạy lại các regression này khi nâng phiên bản Gradio.
4. **Phụ thuộc có thời gian chờ hữu hạn:** limiter local không đẩy khóa đang
   sống ra để nhận khóa mới; Redis có timeout ba giây, không retry và pool
   tối đa 16 kết nối cho mỗi limiter. Web runtime PostgreSQL dùng pool 5+5,
   chờ pool/connect năm giây, statement 30 giây, lock năm giây. SQLite giữ
   WAL, foreign key và busy timeout mười giây; tác vụ maintenance không bị
   áp giới hạn SQL mới của web runtime. Lỗi phụ thuộc bảo mật trả lỗi an toàn.
5. **Probe và giám sát ít tốn tài nguyên:** health không truy vấn DB/WORM;
   readiness single-flight, standard cache thành công năm giây, high kiểm tra
   WORM ngay không dùng success cache. Snapshot chỉ dành cho admin và hiển
   thị trong tab Quản trị. Counter/nhãn không chứa credential hay prompt;
   audit từ chối rate limit vô danh được lấy mẫu để giảm khuếch đại ghi DB,
   còn thay đổi tài khoản và lỗi credential vẫn giữ audit đầy đủ.
6. **Cấu hình server/edge:** Uvicorn có trần concurrency/backlog/keep-alive,
   local không tin proxy header. Compose production chỉ tin địa chỉ Caddy
   cố định ngoài dải IP cấp động, thay wildcard; readiness bị chặn ở Caddy,
   healthcheck gọi trực tiếp trong container. Redis có trần RAM/client và `noeviction`, tránh âm thầm
   xóa quota bảo mật khi đầy. Các biến mới được mô tả trong `.env.example`.

### Phạm vi và giới hạn thực tế

Concurrency/counter trong RAM thuộc từng worker; Redis chia sẻ quota theo
thời gian giữa worker. Quota mất lịch sử khi local hoặc Redis không persistence
khởi động lại. SDK AI có retry, nên quota ứng dụng không phải trần số request
billable hay hạn mức tiền. Timeout từng thao tác không phải deadline tuyệt đối
của cả request. TTL Gradio dọn theo lượt yêu cầu tiếp theo, không bảo đảm xóa
mọi bản sao dữ liệu khỏi RAM đúng giây hết hạn.

Các giá trị mặc định là mốc khởi đầu, chưa phải công suất đã đo của laptop.
Chưa thực hiện flood/benchmark tải, pentest độc lập hoặc kiểm chứng hệ thống
PostgreSQL/Redis/TLS/Vault/WORM production đang chạy. Chuỗi xử lý HTTP chậm
trước ASGI và bão lưu lượng làm đầy đường truyền cần kiểm soát ở edge/mạng.
Khi đưa lên Internet phải bổ sung upstream chống DDoS, WAF/bot challenge phù
hợp, khóa truy cập trực tiếp origin, cảnh báo vận hành và diễn tập restore.
Không có cam kết chống mọi tấn công; cấu hình local/demo hiện tại vẫn không
tương đương profile production/high.

Hướng dẫn giới hạn, chạy local và các bước vận hành:
[docs/security/availability.md](docs/security/availability.md).

### Bằng chứng kiểm chứng

- **947 kiểm thử Python đạt**, gồm **81 regression mới** cho admission, limiter,
  provider AI, hàng đợi/lưu giữ Gradio, cấu hình DB và giao diện quản trị.
  Kiểm thử hủy/lỗi xác nhận slot được trả; kiểm thử thread churn bảo vệ state
  đang dùng; driver-boundary test kiểm tra tham số PostgreSQL mà không kết nối
  máy chủ thật. Bằng chứng: `reports/availability-pytest.xml`.
- **21 kiểm thử JavaScript đạt**; bộ kiểm chứng bảo mật **11/11 đạt** sau khi
  tích hợp, trong `reports/security-validation-availability/`.
- Ruff, `uv lock --check` và kiểm tra whitespace đạt. Bandit không có phát hiện
  từ mức medium severity/confidence trở lên với `-ll -ii`; báo cáo local:
  `reports/availability-bandit.json`.
- `pip-audit` môi trường `.venv`: **104 gói, 0 lỗ hổng đã biết** tại lần quét
  này, trong `reports/availability-pip-audit.json`; không bao gồm lỗ hổng chưa
  được công bố.
- Compose local và high-security được parse thành công; cấu hình high xác nhận
  proxy trust khớp IP Caddy, dải IP động tách khỏi địa chỉ đó và biến admission
  còn hiệu lực. High dùng môi trường placeholder, không chạy container hoặc
  đọc secret thật. Đây là kiểm chứng cấu hình, chưa kiểm chứng runtime TLS,
  Caddy, Redis, PostgreSQL, Vault hay WORM.

Nguồn nguyên tắc:
[OWASP Unrestricted Resource Consumption](https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/),
[OWASP Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html),
[Uvicorn settings](https://www.uvicorn.org/settings/),
[Docker static IP ngoài vùng cấp động](https://docs.docker.com/reference/cli/docker/network/connect/#network-implications-of-stopping-pausing-or-restarting-containers).

## 7. Giám sát, HTTP local và diễn tập khôi phục — 05/10/2026

Bước tiếp theo triển khai cho laptop chưa có tên miền. Không thay cấu hình,
khóa hoặc DB đang dùng, không mở cổng LAN/Internet hoặc dùng AI trả phí.

- **Giám sát admin:** vòng đệm cố định 60 ô thống kê status/kind và latency
  tới header trong cửa sổ 60 giây; SSE không phải đợi đóng mới ghi nhận.
  Lỗi/hủy trước header được đếm riêng. Cảnh báo theo ngưỡng cố định cho
  `429`/`503`, lỗi `5xx`, chưa phản hồi, header chậm và ngân sách đang đầy,
  tự hết khi cửa sổ trôi. Giao diện/API chỉ dành cho admin; nhãn không chứa
  định danh, URL, IP, body hoặc header. Không có cảnh báo email/paging bên ngoài.
- **HTTP thật có giới hạn:** `scripts.security_load_check` dựng hai worker
  tạm trên loopback, AI giả lập và SQLite riêng. Kiểm chứng chặn/thu hồi slot
  khi body chưa hoàn tất, deadline body trả `408`, API chat báo bận/phục hồi,
  quota IP không bị đổi bằng header giả và DB/crypto/audit còn hoạt động.
  Guard RSS/CPU/time chạy trước app build/seed; parent quản lý deadline và
  dọn worker. Không có tùy chọn URL để chạy tải vào website khác.
- **Backup/restore:** `scripts.security_recovery_drill` dùng online backup
  khi commit mới còn trong SQLite WAL; xác nhận bản sao giữ commit đó và hai
  epoch wrapped DEK cùng khóa tài khoản. Giải mã với khóa được giữ riêng,
  từ chối khóa sai và các sửa đổi bản mã/AAD/KEK metadata. Token logout và
  account inactive trước backup vẫn bị chặn sau restore; audit chain đạt.
  Snapshot không chứa plaintext mẫu, KEK hoặc khóa JWT; dữ liệu được dọn.

Các giới hạn load được hạ để gây quá tải nhẹ có kiểm soát. SQLite dùng writer
transaction để bảo vệ quyết định xác thực qua thao tác chat, nên reservation
AI được giữ trong core không kèm DB transaction rồi gọi API thật. Các số
latency/RSS local này không thiết lập công suất parallel chat, SLA hoặc sức
chịu DDoS production. Restore còn cần xử lý thu hồi xảy ra sau snapshot;
không coi bằng chứng thu hồi trước backup là bảo đảm cho một snapshot cũ.
Vault/KMS/WORM và phục hồi khi mất máy chưa được kiểm chứng ở bước này.

### Bằng chứng kiểm chứng

- **983 kiểm thử Python đạt**, gồm **36 trường hợp mới** cho giám sát, load
  harness và phục hồi; báo cáo `reports/operations-security-pytest.xml`.
  Load harness được kiểm tra lại 11/11 sau hoàn thiện cleanup; phép chạy fresh
  process với cấu hình host giả chứng minh không mở DB/secret/proxy của host.
- HTTP thật đạt **6/6 giai đoạn** trong khoảng 49,3 giây; body chưa hoàn tất
  trả `408` sau **30,005 giây**, slot được thu hồi và chat/DB/audit phục hồi.
  Báo cáo `reports/security-load-local/security-load.json` giữ latency thành
  công riêng với phản hồi chặn, RSS/CPU worker và phạm vi fault injection.
- Diễn tập khôi phục đạt **33/33 kiểm tra**; bằng chứng tổng hợp an toàn tại
  `reports/security-recovery-drill.json`. Thời gian local không xác lập RTO/RPO.
- Bộ kiểm chứng bảo mật chạy lại đạt **11/11**, trong
  `reports/security-validation-operations/`. Ruff, `uv lock --check` và
  whitespace đạt; Bandit không có phát hiện medium severity/confidence trở
  lên với `-ll -ii`, trong `reports/operations-security-bandit.json`.
- Không đổi dependency, không thực hiện pentest độc lập/Internet flood hoặc
  kiểm chứng hạ tầng production. Báo cáo là dữ liệu local, được loại khỏi Git.

Phạm vi, ngưỡng và lệnh chạy có trong [availability.md](docs/security/availability.md).

## 8. Hoàn thiện các thiếu sót còn xử lý được ở local — 05/10/2026

Đã gia cố thêm các đường có tác động thực tế. Không đổi `.env`, khóa, DB/outbox
đang dùng hoặc mở dịch vụ ra Internet; mọi kiểm chứng thao tác dùng dữ liệu giả.

- **Email hữu hạn:** tối đa 32 thư đang chạy/chờ mỗi worker, hai luồng gửi;
  shutdown chờ hữu hạn rồi hủy thư chưa chạy. Outbox có trần 512 tệp/16 MiB,
  mỗi thư 64 KiB, ghi độc quyền và từ chối link/junction/hardlink. Không xóa
  thư cũ để nhận thư mới. Snapshot quản trị giữ counter, không giữ địa chỉ/body.
  Lỗi gửi đồng bộ có phản hồi chung; reset vô danh vẫn cùng `202` dù tài khoản
  có/không tồn tại khi mail bận. Chỉ mã của request thất bại bị thu hồi, không
  tiêu thụ mã mới hơn đã được một request khác phát hành.
- **CSP thực thi cho script:** nonce ngẫu nhiên 192 bit mỗi phản hồi; chỉ mẫu
  bootstrap Gradio đã kiểm tra trước nội suy được cấp nonce. Không sửa template
  toàn cục, không tự cấp nonce cho script trong HTML đã render. Chặn handler
  inline, bỏ `unsafe-inline` cho script; giữ CSS inline có chủ đích. Adapter
  từ chối bootstrap/custom JS/head không tương thích thay vì nới policy.
  QR 2FA dùng Markdown với PNG data URL nội bộ, không eval hoặc tệp cache.
- **Biên local và thư viện:** Host chỉ nhận danh sách chính xác; local mặc định
  loopback IPv4/IPv6, production bắt buộc cấu hình riêng. Raw header đổi origin
  của Gradio bị bỏ sau kiểm tra kích thước/framing; scheme/client từ ASGI đã
  được server/proxy xác minh vẫn giữ. Chặn deep-link xuất/đọc trạng thái UI ra
  plaintext trước callback thư viện. Compose bổ sung Host loopback cho UI gọi
  REST nội bộ, danh sách Origin trình duyệt vẫn giữ origin public.
- **Backup mã hóa thật:** `scripts.secure_backup` online SQLite tối đa 64 MiB,
  giữ WAL và wrapped key/epoch metadata, AES-256-GCM với header xác thực và
  Argon2id hữu hạn. Mật khẩu nhập ẩn; không xuất `.env`/KEK/JWT. Chỉ xuất tệp
  mới nguyên tử; từ chối ghi đè và đường dẫn liên kết. Restore thu hồi phiên,
  challenge, recovery code và one-time prekey E2EE, đổi token version ngẫu nhiên
  và khóa mọi tài khoản mặc định. Chỉ operator mới kích hoạt rõ ràng tài khoản
  đã đối chiếu; không suy ra các thu hồi/thay đổi sau snapshot từ backup cũ.
- **Kiểm chứng trình duyệt:** cold load với trần IP 8 bị chặn khi các module
  Gradio tải cùng lúc. Đã điều chỉnh mặc định thành 16, giữ trần toàn worker 32,
  không miễn quota/capacity cho static. Bỏ báo cáo vi phạm CSS hợp lệ để tránh
  tự tạo burst request. Giao diện tải, đăng nhập và QR 352×352 hoạt động dưới
  CSP mới trên demo tạm riêng; không có lỗi JavaScript mới ở lần tải thành công.

### Giới hạn còn cần triển khai thực tế

Windows cần ACL riêng cho outbox/thư mục backup và ổ mã hóa; chmod không thay
ACL hoặc bảo đảm xóa an toàn trên SSD. Outbox quota là trong một tiến trình.
Restore phải giữ offline, tắt demo seed/bootstrap và đối chiếu tài khoản,
mật khẩu, MFA/seed, email, passkey, E2EE device/membership/epoch cùng dữ liệu đã
xóa từ nguồn mới hơn; kiểm chứng khóa đúng phiên bản và checkpoint ngoài.
Backup SQLite local không thay backup PostgreSQL/KMS/WORM hoặc lịch/offsite
backup thật. Các thao tác này chưa được vận hành trên dữ liệu của người dùng.

CDN/WAF/chống DDoS upstream, bot challenge và khóa origin cần tên miền/dịch vụ
triển khai. Turnstile chưa tích hợp. Giám sát/paging ngoài, IAM/PKI/retention
lock, client E2EE hoàn chỉnh đã audit và pentest độc lập vẫn là cổng triển khai;
không tuyên bố đã hoàn thành các dịch vụ đó hoặc đạt bảo mật tuyệt đối.

Hướng dẫn vận hành và lệnh backup/restore:
[availability.md](docs/security/availability.md).
Nguyên tắc tham chiếu: [OWASP CSP](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html),
[OWASP DoS](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html),
[cryptography AES-GCM](https://cryptography.io/en/latest/hazmat/primitives/aead/).

### Bằng chứng kiểm chứng cuối

- **1.109 kiểm thử Python đạt**, gồm 126 regression mới đạt; hai kiểm thử quyền
  POSIX được bỏ qua trên Windows. Báo cáo: `reports/final-hardening-pytest.xml`.
  Vòng cuối chạy trên cấu hình mặc định IP 16; 86 kiểm thử biên/config và 20
  kiểm thử wiring giao diện cũng đã đạt riêng sau các điều chỉnh.
- **21 kiểm thử JavaScript đạt** và bộ kiểm chứng bảo mật **11/11 đạt**, trong
  `reports/security-validation-final/`. Demo ngoại tuyến đạt 11 kiểm tra.
- Ruff, `uv lock --check` và whitespace đạt. Bandit không có phát hiện từ
  medium severity/confidence trở lên với `-ll -ii`, gồm cả CLI backup mới;
  báo cáo `reports/final-hardening-bandit.json`.
- `pip-audit` môi trường `.venv`: **104 gói, 0 lỗ hổng đã biết** tại lần quét,
  trong `reports/final-hardening-pip-audit.json`; không xác lập không có lỗ hổng
  chưa công bố. Không thay dependency. Compose base/high/local đã kiểm tra
  cấu hình hợp nhất với placeholder; base/local parse lại sau đổi trần IP 16.
- Trình duyệt kiểm tra trên demo tạm riêng: tải đầu, đăng nhập và QR 2FA có ảnh
  data URL 352×352 đã tải thành công; không có lỗi JavaScript mới. Các server,
  tab và dữ liệu thử đã dọn. Không pentest độc lập, SMTP thật, DDoS Internet
  hoặc vận hành backup trên DB thật.
