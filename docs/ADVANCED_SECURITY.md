# Bảo mật nâng cao: nguồn tham khảo, tích hợp và vận hành

Các cơ chế dưới đây được phát triển trong SCAP dựa trên mẫu thiết kế của các
dự án thực tế. Không cần cài thêm Keycloak, Wazuh hay PyRIT để chạy những phần
này; đây là triển khai trong ứng dụng, không phải kết nối đến các dịch vụ đó.

## 1. Phiên đăng nhập có thời hạn không hoạt động và thời hạn tuyệt đối

[Keycloak Session Idle/Max](https://www.keycloak.org/docs/latest/server_admin/#_timeouts)
phân biệt thời hạn do không hoạt động với tuổi thọ tối đa của phiên. SCAP áp dụng
hai mốc này cho phiên lưu tại server, ngoài hạn JWT:

- `SESSION_IDLE_MINUTES=30`: thời hạn không hoạt động, từ 1 đến 1440 phút.
- `SESSION_ABSOLUTE_HOURS=8`: tuổi thọ tối đa, từ 1 đến 168 giờ.
- `/api/auth/me`, `/api/auth/sessions`, `/api/auth/refresh` và `/api/auth/logout`
  không tính là hoạt động kéo dài phiên. Những API xác thực khác có thể
  cập nhật hoạt động; đây là hoạt động API, không phải đo chuột/bàn phím.
- Gia hạn token giữ nguyên mốc đăng nhập gốc, mốc hoạt động và trạng thái step-up.
- Vé xuất dữ liệu cũng phải có phiên cha còn hiệu lực theo cả hai mốc.
- Danh sách thiết bị trả `last_activity_at`, `idle_expires_at`,
  `absolute_expires_at`; tab tài khoản hiển thị các mốc này.

Hạn JWT vẫn được áp dụng độc lập. Không có hoạt động nào kéo dài phiên qua mốc
tuyệt đối; người dùng cần đăng nhập lại. Hết hạn phiên không xóa hội thoại.
Mỗi yêu cầu có hoạt động ghi lại thời điểm ở database dưới khóa phiên/tài khoản;
cần đánh giá tải ghi khi triển khai nhiều người dùng đồng thời.

Schema thêm cột nullable `auth_sessions.last_activity_at`. Migration lặp lại
an toàn; dữ liệu cũ lấy `issued_at` làm mốc bảo thủ, nên một số phiên cũ có thể
phải đăng nhập lại. Development tự nâng schema lúc khởi động; production dùng
quy trình migration riêng với tài khoản owner hiện có trước khi khởi động bản
app mới. `assert_schema_ready()` từ chối schema thiếu cột. Không cấp quyền DDL
cho tài khoản web để tránh bước migration.

## 2. DLP kiểm tra nội dung mã hóa nhiều lớp

[PyRIT converters](https://microsoft.github.io/PyRIT/0.13.0/api/pyrit-prompt-converter/)
minh họa cách biến đổi nội dung như Base64 trong kiểm thử đối kháng.
[OWASP LLM05](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)
nhấn mạnh xác thực và làm sạch đầu ra model. SCAP mở rộng scanner hiện có để:

- Kiểm tra URL-percent, HTML entity, Base64 và Base64url, cả chuỗi lồng/mixed.
- Ánh xạ nội dung giải mã về đoạn gốc để che cả dạng mã hóa. Việc giải mã chỉ
  phục vụ phát hiện, không chạy code hay gọi dịch vụ ngoài.
- Giữ chính sách hiện có: secret/private key → block egress; email/từ điển
  confidential → redact; nội dung khai báo confidential vẫn cần xác nhận.
- Kiểm tra cả lịch sử đã được phép gửi và phản hồi provider. Quét phản hồi đầy
  đủ trước khi cắt hiển thị 8000 ký tự để không làm mất phần kết thúc private key.
- Báo cáo chỉ chứa danh mục, detector, số lần và mức phân loại; không chứa mẫu
  bí mật hoặc phần nội dung giải mã.

Giới hạn scanner: 65536 ký tự sau chuẩn hóa, 3 lớp giải mã, 262144 ký tự cộng
dồn qua các bản kiểm tra và tối đa 512 bản. Khi không kiểm tra hết được, scanner
trả `inspection_limit` thuộc `highly_confidential`: egress bị chặn, redaction
che vùng không kiểm tra được. Provider response không phải chuỗi hoặc dài hơn
32000 ký tự trả lỗi AI chung, không ghi nội dung vào log.

Đây là phòng thủ dựa trên detector, không đảm bảo phát hiện mọi mã hóa tùy ý,
steganography hoặc prompt injection. Chuỗi mã hóa hợp lệ nhưng quá sâu có thể
bị chặn bảo thủ; cần kiểm thử trên dữ liệu sử dụng thực tế khi chỉnh ngưỡng.

## 3. Tương quan đăng nhập và bằng chứng SIEM

[Wazuh frequency/timeframe, same/different field](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
cung cấp mẫu tương quan nhiều sự kiện. SCAP thêm hai luật trên audit đã có:

- `IDS-DISTRIBUTED-BRUTEFORCE`: mặc định từ 5 thất bại, ít nhất 3 nguồn trên
  cùng tài khoản trong cửa sổ điều tra. Ánh xạ ATT&CK `T1110.001`.
- `IDS-AUTH-SUCCESS-AFTER-FAILURES`: đăng nhập hoàn tất sau chuỗi thất bại đủ
  ngưỡng. MFA challenge không tính là thành công; hoàn tất MFA mới tính.

Truy vấn sử dụng thời gian rồi ID để sắp thứ tự; phân tách tài khoản và các chuỗi
theo lần đăng nhập thành công. Cửa sổ từ 1 đến 1440 phút; mỗi nhóm luật trả tối
đa 100 phát hiện. Bằng chứng gồm ID sự kiện, số nguồn và nhãn ATT&CK. Luật theo
tài khoản chỉ tương quan được sự kiện có actor ID; không suy diễn danh tính
cho tài khoản không tồn tại hoặc sự kiện bị giới hạn trước khi nhận diện actor.

Kết quả xuất hiện trong `GET /api/admin/ids/anomalies` và tab bảo mật. Tác vụ
bảo mật định kỳ hiện có phát `ids.anomaly` ra SIEM khi được bật; chỉ quan sát,
không tự khóa tài khoản hay chặn cả tập IP. Cảnh báo là dấu hiệu cần xác minh,
không phải bằng chứng chắc chắn tài khoản đã bị chiếm.

## 4. Kiểm tra nguồn yêu cầu trình duyệt

[Go CrossOriginProtection](https://go.dev/src/net/http/csrf.go) dùng Fetch
Metadata/Origin để chặn yêu cầu trình duyệt chéo nguồn thay đổi trạng thái.
SCAP kiểm tra trong middleware chung, bao phủ cả REST API và Gradio:

- GET/HEAD/OPTIONS tiếp tục được phép; JWT, ownership và vé xuất dữ liệu vẫn
  kiểm tra quyền riêng. Không dùng guard này để bảo vệ quyền đọc hoặc WebSocket.
- Yêu cầu thay đổi trạng thái chấp nhận Origin cùng scheme/host/port hoặc
  Origin nằm trong `ALLOWED_ORIGINS`. `same-site` không tự tin cậy miền con.
- `Origin: null`, origin sai định dạng, header trùng, metadata không hợp lệ
  hoặc origin không được tin cậy bị chặn 403 trước handler.
- Header-less CLI/client server vẫn được hỗ trợ. Header trình duyệt không phải
  bằng chứng xác thực, nên không thay thế bearer auth/RBAC hoặc TLS.
- Không suy ra origin tin cậy từ `X-Forwarded-Host`/`X-Forwarded-Proto` thô.
  Reverse proxy phải giữ Host và cấu hình trusted proxy để ASGI thấy đúng scheme.
- CORS allowlist cũng cấp quyền gửi yêu cầu thay đổi trạng thái chéo nguồn:
  chỉ cấu hình origin chính xác, ví dụ `https://frontend.example`, không wildcard,
  không đường dẫn hoặc dấu `/` ở cuối.

SIEM ghi `browser.origin.denied` với lý do cố định, `request_id`, địa chỉ nguồn;
không ghi header Origin, body, đường dẫn hay token. Lấy mẫu tối đa 10/nguồn/phút
và 100/phút toàn ứng dụng qua limiter hiện có; Redis chia sẻ khi được cấu hình.

## Kiểm chứng tại máy phát triển

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests scripts
.\.venv\Scripts\python.exe -m bandit -r src/app -ll -ii
```

Các nhóm kiểm thử mới: `test_auth_session_timeouts.py`,
`test_dlp_encoded.py`, `test_ids_correlation.py`, `test_browser_security.py` và
`test_advanced_security_features.py`. Dữ liệu thử nằm trong SQLite tạm; các
provider được thay thế bằng stub, không gửi nội dung sang AI thật. Cần kiểm
chứng thêm trên PostgreSQL/Redis/proxy của môi trường triển khai thực tế.
