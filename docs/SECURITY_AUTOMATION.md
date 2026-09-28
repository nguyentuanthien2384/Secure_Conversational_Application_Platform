# Nâng cấp bảo mật và tự động hoá theo báo cáo tham khảo

## Nội dung PDF được áp dụng

Nguồn: **Vũ Văn Mạnh - ĐATN, “Xây dựng quy trình đánh giá và phát hiện lỗ hổng
ứng dụng Web theo khung MITRE ATT&CK sử dụng ELK Stack và Atomic Red Team”**.
Phần nhận xét của giảng viên ở trang PDF 3 đánh giá tính thực tiễn và khả năng
triển khai, không liệt kê lỗi của SCAP. Các đề xuất kỹ thuật dưới đây được rút ra
từ nội dung báo cáo, rồi kiểm chứng trên mã nguồn SCAP.

- Mục **3.4.4**, trang in **75** / trang PDF **97**: giới hạn của dò mẫu trước
  mã hoá nhiều lớp và chi phí xử lý khi tải cao. SCAP bổ sung chuẩn hoá có giới
  hạn, kiểm tra toàn bộ đường dẫn và kiểm soát kích thước yêu cầu thực nhận.
- Phần **Hướng phát triển**, trang in **78** / trang PDF **100**: mở rộng kịch
  bản, phân tích hành vi và phản ứng tự động. SCAP có bộ kiểm chứng API/audit/IDS
  độc lập, tác vụ định kỳ tìm bất thường, cùng cơ chế IPS tạm chặn nguồn đã có
  được sửa vòng đời và giới hạn bộ nhớ.
- Chu trình diễn tập của báo cáo được chuyển thành **tạo môi trường tạm → chạy
  tình huống → đối chiếu bằng chứng → xuất kết quả → dọn môi trường**, phù hợp
  ứng dụng FastAPI hiện tại. Các thao tác tấn công hệ điều hành trong PDF không
  được chạy trên máy hoặc dữ liệu đang sử dụng.

## Nâng cấp theo các dự án thực tế

Đợt phát triển tiếp theo bổ sung quản lý phiên idle/max, DLP kiểm tra mã hóa nhiều
lớp, tương quan đăng nhập phân tán và kiểm tra nguồn trình duyệt. Nguồn tham khảo,
cấu hình, migration, giới hạn và tình huống kiểm chứng nằm tại
[ADVANCED_SECURITY.md](ADVANCED_SECURITY.md).

## Các thay đổi thực tế

### Giới hạn yêu cầu trước khi phân tích

`src/app/request_limits.py` kiểm tra tổng dung lượng body thực nhận, kể cả khi
không có `Content-Length` hoặc khai báo sai. Quá **1 MiB** trả 413; thời gian đọc
quá **30 giây** trả 408; độ dài URI (path, dấu `?`, query) quá **16 KiB** trả 414.
`Content-Length` trùng hoặc không hợp lệ trả 400. Body được giữ trong bộ nhớ có
giới hạn trước khi chuyển vào bộ phân tích JSON; không tạo tệp tạm. Luồng phản
hồi streaming vẫn hoạt động. Caddy cũng giới hạn body ở 1 MB tại biên.

### IDS nhận diện dữ liệu che giấu

`src/app/ids.py` bổ sung tối đa ba lượt giải mã URL/HTML/escape, xử lý SQL comment
và ký tự điều khiển trong mẫu XSS. Mỗi luật chỉ sinh một kết quả trên mỗi lần
quét. Chuẩn hoá chỉ dùng để phát hiện, không sửa dữ liệu nghiệp vụ.

Middleware quét đường dẫn ASGI đầy đủ, trước khi cắt metadata lưu nhật ký.
Ký tự `#` mã hoá trong path không còn làm mất phần dữ liệu cần kiểm tra.
Trạng thái IPS có giới hạn số nguồn, dọn nguồn hết hạn và đặt lại điểm sau khi
gỡ chặn. Danh sách chặn vẫn thuộc từng tiến trình; triển khai nhiều instance cần
đưa quyết định chặn ra edge hoặc xây dựng kho trạng thái chung. Khi bộ nhớ đã đủ
10.000 nguồn đều đang bị chặn, nguồn mới chỉ được ghi vào lịch sử có giới hạn.

### Bằng chứng xác thực và nhật ký SIEM

Yêu cầu thiếu/sai token và từ chối quyền quản trị được ghi kèm `request_id`,
loại sự kiện và lý do cố định, không ghi token. Mẫu sự kiện mới được giới hạn
10 lần/nguồn/phút và 100 lần/phút toàn hệ thống (Redis chia sẻ khi được cấu hình).
Vì có lấy mẫu, số sự kiện này không đại diện tổng số lần truy cập thất bại.

Nhật ký stdout sử dụng `event.outcome` là `success`, `failure` hoặc `unknown`,
và `event.severity` dạng số theo kiểu dữ liệu [Elastic Common Schema](https://www.elastic.co/docs/reference/ecs/ecs-event).
Giá trị SCAP gốc nằm tại `scap.outcome` và `scap.severity`; rule/dashboard cũ cần
chuyển điều kiện `blocked`/`denied` sang `scap.outcome`. Luật T1190 có thêm
`threat.framework` và `threat.technique.id`. Thay đổi này không sửa nhật ký cũ
trong cơ sở dữ liệu, không tự cài đặt hoặc kết nối Elasticsearch.

## Chạy kiểm chứng tự động

Với đồ án demo trên máy, dùng [launcher ngoại tuyến](../HUONG_DAN_CHAY.md) cho
giao diện và runner dưới đây cho bằng chứng. Hai tiến trình dùng dữ liệu tạm
riêng; chạy runner không chặn IP hay khóa tài khoản của giao diện demo.

Chạy tại thư mục gốc của dự án sau khi cài nhóm phụ thuộc phát triển. Bước cài
đầu tiên cần mạng:

```powershell
uv sync --frozen --group dev
```

Nếu đã có môi trường Python trên Windows:

```powershell
.\.venv\Scripts\python.exe -m scripts.validate_security
```

Các tình huống của runner:

1. Không có xác thực: trả 401 và có `auth.access.denied` tương ứng.
2. Token sai: trả 401 và ghi nhận từ chối mà không lưu token.
3. Truy cập tài nguyên người khác: đọc/xoá đều bị từ chối; chủ sở hữu vẫn đọc được.
4. Dò mật khẩu: giới hạn yêu cầu, khoá tài khoản và phát hiện chuỗi thất bại.
5. SQL injection mã hoá hai lớp: phát hiện `ids.signature`, sau đó có chặn IPS.
6. Mẫu hợp lệ: đăng ký/đăng nhập/truy cập thành công, không phát cảnh báo IDS.
7. Sửa một dòng audit trong SQLite tạm: phát hiện hỏng chuỗi và đúng dòng bị sửa.
8. `session-timeout`: kiểm tra thời hạn không hoạt động/tuyệt đối ở máy chủ;
   dùng thời gian trên dữ liệu thử, không chờ hàng chục phút trên giao diện.
9. `encoded-dlp`: bật đồng thuận, rồi kiểm tra chặn secret mã hóa, che email
   và lọc phản hồi với nhà cung cấp AI **giả lập**, không gọi dịch vụ ngoài.
   Nhánh từ chối do thiếu đồng thuận được kiểm tra trong bộ pytest.
10. `auth-correlation`: đối chiếu sự kiện đăng nhập phân tán và chuỗi thất bại
    rồi thành công với kết quả tương quan; sự kiện đầu vào là dữ liệu mô phỏng.
11. `browser-origin`: kiểm tra yêu cầu thay đổi dữ liệu khác nguồn bị từ chối,
    sự kiện bảo mật có mã yêu cầu tương ứng và ca cùng nguồn hợp lệ.

Mỗi lần chạy tạo khoá và SQLite riêng, không đọc `.env`, không nhận URL mục tiêu
và không dùng cơ sở dữ liệu đã cấu hình. Runner được thiết kế cho tiến trình
CLI/CI riêng; không gọi nó từ một ứng dụng đang phục vụ người dùng.

Bot `[DEMO AI]` trên giao diện chỉ minh họa bản xem trước đã che và không cần
consent gửi dữ liệu ra ngoài. Bằng chứng cho nhánh provider đến từ test giả lập
ở runner: không được diễn giải thành việc đã gọi hoặc kiểm thử Gemini thật.
Chính sách AI ngoài chặn secret, khóa riêng và thẻ thanh toán thay vì chỉ che
rồi gửi. Chi tiết và giới hạn nằm trong [ADVANCED_SECURITY.md](ADVANCED_SECURITY.md).

Đầu ra nằm tại `reports/security-validation/security-validation.json` và
`reports/security-validation/security-validation.junit.xml`. Kết quả gồm mã
yêu cầu, mã audit, trạng thái kiểm tra và thời gian đo tại ứng dụng. Mã thoát 0
là đạt; mã 1 là có kiểm soát hoặc bằng chứng bị thiếu. Báo cáo không chứa mật
khẩu, token, nội dung chat hoặc payload thô. Thư mục kết quả được bỏ qua bởi Git.

Có thể chạy một phần:

```powershell
.\.venv\Scripts\python.exe -m scripts.validate_security --scenario idor --scenario encoded-sqli
```

Kiểm chứng riêng bốn tính năng mới, đồng thời giữ kết quả cho buổi diễn tập:

```powershell
.\.venv\Scripts\python.exe -m scripts.validate_security --scenario session-timeout --scenario encoded-dlp --scenario auth-correlation --scenario browser-origin --output-dir reports/security-validation-advanced
```

Workflow `.github/workflows/security.yml` chạy bộ kiểm chứng trên pull request,
push vào `main` và lần kích hoạt thủ công. JSON/JUnit được tải lên artifact của
CI. Định nghĩa workflow cần được đưa lên GitHub mới chạy trên hệ thống CI đó.

Các nhãn ATT&CK là ánh xạ phạm vi tình huống ứng dụng: dò mật khẩu
[T1110.001](https://attack.mitre.org/techniques/T1110/001/), tín hiệu khai thác Web
[T1190](https://attack.mitre.org/techniques/T1190/) và sửa dữ liệu lưu trữ
[T1565.001](https://attack.mitre.org/techniques/T1565/001/). Chúng không chứng minh
độ bao phủ các kỹ thuật hệ điều hành trong báo cáo. Kết quả toàn bộ tình huống đạt cũng không phải
tỷ lệ phát hiện ngoài thực tế hay phép đo tỷ lệ cảnh báo giả thống kê.

## Bật tác vụ bảo mật định kỳ

Thêm các giá trị sau vào cấu hình triển khai rồi khởi động lại ứng dụng:

```dotenv
SECURITY_MAINTENANCE_ENABLED=true
SECURITY_MAINTENANCE_INTERVAL_SECONDS=300
SECURITY_MAINTENANCE_ANOMALY_WINDOW_MINUTES=60
SECURITY_MAINTENANCE_BATCH_SIZE=500
SECURITY_MAINTENANCE_RETENTION_ENABLED=false
```

Khi bật, tác vụ bắt đầu sau khi khởi động ứng dụng, sau đó chạy theo chu kỳ,
ngoài luồng xử lý yêu cầu. Mỗi chu kỳ:

- Đối chiếu audit trong cửa sổ thời gian để phát hiện dò mật khẩu, dò tài khoản,
  truy cập trái quyền, lỗi MFA và các mẫu tấn công; phát `ids.anomaly` ra SIEM.
- Gộp cảnh báo lặp theo loại, đối tượng và mức độ. Khi mức độ tăng có cảnh báo mới.
- Kiểm tra checkpoint hiện tại, neo phần đuôi audit còn thiếu và thử liên lạc
  với WORM nếu có cấu hình. Một checkpoint hỏng được báo lỗi thay vì thay thế.
- Nếu bật retention, xoá dữ liệu hết thời hạn theo chính sách hiện có và xoá cache
  khoá đã giải bọc sau khi xoá hội thoại.

Tài khoản admin có thể kiểm tra trạng thái bằng
`GET /api/admin/security/maintenance` với bearer token. `last_result` là kết quả
của tiến trình trả lời; có thể còn `null` trước chu kỳ đầu hoặc nếu tiến trình
khác giữ vai trò chạy tác vụ. `degraded` kèm `failed_phases` cho biết pha lỗi;
stdout cũng có sự kiện `security.maintenance.failure` không chứa chi tiết bí mật.

Để tự động thực thi retention, đặt thêm:

```dotenv
SECURITY_MAINTENANCE_RETENTION_ENABLED=true
```

Retention xoá vĩnh viễn dữ liệu hết hạn và wrapped DEK theo
`SECURE_RETENTION_DAYS` / `CONFIDENTIAL_RETENTION_DAYS`. Hai cờ định kỳ mặc định
đều tắt. Cơ chế retention lúc khởi động/truy cập vốn có vẫn do các cấu hình cũ
điều khiển. Có thể xem trước đối tượng đến hạn bằng:

```powershell
uv run python -m scripts.enforce_retention --dry-run
```

Mỗi chu kỳ xoá tối đa số dòng cấu hình trên mỗi nhóm dữ liệu. Bước bổ sung hạn
lưu trữ cho dữ liệu legacy có deadline rỗng vẫn duyệt toàn bộ tập legacy theo
từng lô bộ nhớ; nên xử lý migration trước khi bật ở cơ sở dữ liệu lớn.

PostgreSQL dùng advisory lock giữ suốt chu kỳ; Redis phối hợp nhịp chạy và gộp
cảnh báo giữa các worker. Mất cơ chế phối hợp sẽ bỏ qua công việc và báo lỗi.
SQLite chỉ hỗ trợ một worker cho tác vụ này. Khi tắt ứng dụng, tác vụ đang chạy
được hoàn tất trước khi đóng kết nối cơ sở dữ liệu.

## Phạm vi còn cần kiểm chứng ngoài ứng dụng

Tác vụ định kỳ phát cảnh báo quan sát; nó không tự cô lập container hay thu hồi
tài khoản. IPS ở tầng yêu cầu vẫn tự chặn theo ngưỡng đã cấu hình. Việc phản ứng
trên Docker/cloud cần hạ tầng kiểm thử và chính sách riêng.

Bản nâng cấp chưa cung cấp ML phát hiện zero-day, host telemetry, client E2EE
hoàn chỉnh hoặc SIEM thật. Kiểm tra checkpoint định kỳ cũng không thay thế phép
kiểm tra lại toàn chuỗi ở `/api/admin/audit/verify`. Cần kiểm chứng riêng tải lớn,
Redis/PostgreSQL nhiều worker, giao nhận WORM, pipeline ELK và các tình huống
Atomic Red Team trong phòng lab được cấp phép.
