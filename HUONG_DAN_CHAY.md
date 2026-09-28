# Chạy SCAP để demo đồ án trên máy cá nhân

Bản demo này dùng SQLite, AI ngoại tuyến và dữ liệu mẫu. Không cần máy chủ,
tên miền, Docker, Gemini API key hay sửa `.env`. Sau khi cài đủ thư viện, có thể
chạy phần demo ứng dụng và kiểm chứng bảo mật mà không cần Internet.

## 1. Chuẩn bị một lần

Mở PowerShell tại thư mục gốc dự án, nơi có `pyproject.toml` và `uv.lock`.
Nếu đã có `.venv\Scripts\python.exe`, chuyển sang bước 2.

Nếu chưa có môi trường Python, cài Python 3.10 trở lên và `uv`, rồi cài đúng
các phiên bản trong tệp khóa (bước này cần mạng):

```powershell
uv sync --frozen --group dev
```

Các lệnh dưới đây dùng trực tiếp Python trong `.venv` để không tự cập nhật hoặc
tải thư viện khi đang trình bày. Trên macOS/Linux, thay
`.\.venv\Scripts\python.exe` bằng `./.venv/bin/python`.

## 2. Kiểm tra sẵn sàng rồi mở ứng dụng

Chạy kiểm tra trước buổi demo:

```powershell
.\.venv\Scripts\python.exe -m scripts.demo_local --check
```

Lệnh kiểm tra tạo ứng dụng cùng dữ liệu mẫu trong môi trường tạm, kiểm tra sức
khỏe, đăng nhập, chat ngoại tuyến/DLP, audit và các trang rồi thoát; không mở
cổng phục vụ trình duyệt. Nếu có lỗi, xử lý trước bước tiếp theo.

Mở ứng dụng:

```powershell
.\.venv\Scripts\python.exe -m scripts.demo_local
```

Khi ứng dụng sẵn sàng, vào <http://127.0.0.1:8000>. Tài liệu API nằm tại
<http://127.0.0.1:8000/docs>. Giữ terminal này mở trong suốt buổi trình bày.
Đóng tab demo rồi dừng bằng `Ctrl+C`. Nếu còn tab mở, ứng dụng chờ tối đa
5 giây để kết thúc kết nối trước khi dọn dữ liệu tạm.

Nếu cổng 8000 đang được dùng, chọn một cổng khác:

```powershell
.\.venv\Scripts\python.exe -m scripts.demo_local --port 8080
```

Khi đó mở <http://127.0.0.1:8080>. Luôn dùng cùng địa chỉ `127.0.0.1` và đúng
cổng mà lệnh thông báo, thay vì đổi qua lại giữa nhiều tên máy.

Launcher chỉ lắng nghe trên máy cục bộ. Mỗi lần chạy dùng SQLite tạm và khóa
ngẫu nhiên riêng, bỏ qua `.env`, bật seed và ép AI ngoại tuyến. Dữ liệu đang có
của dự án không được dùng làm dữ liệu demo. Thư mục tạm được dọn khi dừng bình
thường hoặc khi kiểm tra xong. Khởi động lại tạo một lượt demo mới: hội thoại
vừa tạo, thay đổi tài khoản và thiết lập MFA của lượt cũ không được giữ lại.
Đây là cách làm lại bài trình bày; không cần xóa cơ sở dữ liệu hay tắt IDS.

## 3. Đăng nhập và hiểu đúng dữ liệu mẫu

Sau khi đăng nhập thành công, F5 sẽ khôi phục tài khoản nếu phiên vẫn hợp lệ.
Ứng dụng dùng cookie HttpOnly và xác minh lại phiên với máy chủ; không lưu mật
khẩu hay bearer token vào localStorage/sessionStorage. F5 không gia hạn token.
Sau khi đăng xuất, bị thu hồi phiên, hết hạn hoặc khởi động lại tiến trình ứng
dụng, bạn cần đăng nhập lại. Hãy dùng nhất quán `localhost` hoặc `127.0.0.1`
vì cookie của hai địa chỉ này tách biệt. Cơ chế khôi phục này dành cho một tiến
trình phục vụ demo; trạng thái khôi phục nằm trong bộ nhớ máy chủ.

Mật khẩu chung của các tài khoản mẫu: **`Phenikaa-Vault#2026-Lab`**.

- `demo.user`: người dùng, dùng để chat, xem bản mã, thiết bị và MFA.
- `demo.mod`: điều hành, xem thêm nhật ký kiểm toán và phát hiện IDS.
- `demo.boss`: quản trị viên, xem dashboard và xác minh chuỗi audit.

Có thêm tài khoản `lab.*` và hội thoại mẫu cho việc tìm kiếm, phân trang. Các
sự kiện tấn công được seed là **dữ liệu mô phỏng**, không phải dấu vết một cuộc
tấn công thật. Bằng chứng kiểm soát có hoạt động nằm trong bộ kiểm chứng ở
bước 4, nơi các yêu cầu và kết quả được đối chiếu tự động.

Gửi một tin nhắn trong hội thoại mới ở chế độ **Secure**. Câu trả lời bắt đầu
bằng `[DEMO AI]` là kết quả đúng: bot ngoại tuyến nhắc lại bản xem trước sau
DLP, không phải một mô hình AI sinh câu trả lời thông minh.

Ví dụ dùng dữ liệu giả:

```text
Hãy kiểm tra email demo@example.com và email mã hóa demo%40example.com.
```

Kết quả mong đợi: bản xem trước của bot thay các email bằng nhãn che; phần
thông báo chỉ nêu loại dữ liệu. Bản gốc của tin nhắn vẫn được mã hóa để lưu
trong hội thoại của người gửi. Tiêu đề và một số metadata không phải nội dung
tin nhắn mã hóa, vì vậy chỉ nhập dữ liệu giả khi trình diễn.

AI ngoại tuyến không cần đồng ý gửi dữ liệu cho bên ngoài. Đổi ô đồng ý ở tab
**Tài khoản** sẽ không tạo lỗi thiếu đồng thuận trong chế độ này. Runner bật
đồng thuận rồi kiểm chứng chặn secret mã hóa, che email và lọc phản hồi bằng
nhà cung cấp giả lập, không cần khóa API thật. Kiểm thử từ chối khi thiếu đồng
thuận và các quy tắc DLP khác nằm trong bộ pytest.

## 4. Chạy kiểm chứng và lưu bằng chứng

Mở terminal thứ hai tại thư mục dự án:

```powershell
.\.venv\Scripts\python.exe -m scripts.validate_security
```

Đạt khi từng tình huống là `PASS`, dòng tổng kết không có tình huống lỗi và
lệnh kết thúc với mã 0. Runner tự tạo cơ sở dữ liệu và khóa tạm riêng, không
gửi yêu cầu tới ứng dụng đang trình chiếu và không nhận URL máy đích.

Báo cáo được tạo ở:

- `reports/security-validation/security-validation.json`: từng kiểm tra và bằng chứng.
- `reports/security-validation/security-validation.junit.xml`: kết quả định dạng JUnit.

Muốn kiểm chứng riêng bốn tính năng mới:

```powershell
.\.venv\Scripts\python.exe -m scripts.validate_security --scenario session-timeout --scenario encoded-dlp --scenario auth-correlation --scenario browser-origin
```

Mỗi lần chạy mặc định ghi lại báo cáo ở cùng vị trí. Để giữ kết quả riêng của
lần diễn tập:

```powershell
.\.venv\Scripts\python.exe -m scripts.validate_security --output-dir reports/security-validation-rehearsal
```

Chạy kiểm thử tổng thể trước buổi bảo vệ; không cần đợi toàn bộ bộ test trong
thời gian trình bày:

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts='' -q
.\.venv\Scripts\python.exe -m ruff check src tests scripts
.\.venv\Scripts\python.exe -m bandit -q -r src/app -ll -ii
```

Lưu ảnh dòng tổng kết thực tế cùng ngày chạy. Không ghi cố định một số lượng
test hoặc một tỷ lệ bao phủ vào báo cáo nếu chưa có kết quả tương ứng.
Kiểm tra CVE trực tuyến, Docker/ZAP và hạ tầng PostgreSQL/Redis là phần mở rộng,
không phải điều kiện để hoàn thành demo SQLite ngoại tuyến.

## 5. Trình bày và làm lại

Làm theo [kịch bản 6 phút hoặc 12 phút](docs/DEMO_SCRIPT.md). Mở sẵn giao diện
người dùng và một cửa sổ ẩn danh đăng nhập `demo.boss`. Chạy sẵn bộ kiểm chứng
và để kết quả ở terminal thứ hai.

- Nếu bị khóa do nhập sai nhiều lần hoặc tự thử payload: dừng lượt demo, chạy
  lại launcher, rồi đăng nhập lại. Không tắt IDS hoặc xóa `secure_chat.db`.
- Nếu MFA báo mã đã dùng: chờ mã TOTP mới; mã dùng để kích hoạt không được dùng
  lại ngay để đăng nhập. Kiểm tra đồng hồ điện thoại trước buổi trình bày.
- Nếu bot chỉ nhắc lại nội dung đã che: đó là chức năng AI ngoại tuyến dự kiến.
- Nếu trình duyệt báo mất phiên sau khi khởi động lại: tải lại trang và đăng
  nhập lại, vì lượt mới có khóa và cơ sở dữ liệu mới.
- Nếu cần giữ ảnh/video/báo cáo: lưu trước khi dừng lượt demo. Không đưa QR,
  khóa MFA, mã khôi phục hay bearer token vào ảnh báo cáo.

## 6. Cập nhật giao diện khi đang chạy bằng Docker

Nếu ứng dụng tại cổng 8000 đang chạy bằng Docker, mã nguồn nằm trong image.
Sau khi sửa mã nguồn, cần dựng lại image. Khi cập nhật cả phiên bản dự án,
chạy bước nâng cấp schema trước khi thay ứng dụng:

```powershell
docker compose -f docker-compose.yml -f docker-compose.local.yml build app migrate
docker compose -f docker-compose.yml -f docker-compose.local.yml run --rm migrate
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --no-build --no-deps app
```

Chỉ tiếp tục nếu mỗi lệnh trước đã thành công. Đợi ứng dụng sẵn sàng rồi tải
lại trang và đăng nhập. Các lệnh này giữ dữ liệu hội thoại đã lưu, cập nhật
schema nếu phiên bản mới yêu cầu và thay riêng ứng dụng. Chỉ F5 hoặc restart
container cũ sẽ không đưa mã nguồn vừa sửa vào image. Đây là cách chạy khác
với `scripts.demo_local`, vốn tạo dữ liệu tạm cho mỗi lượt demo.

## 7. Tài liệu dùng trong báo cáo

- [DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md): thao tác, kết quả mong đợi và lời giải thích.
- [ADVANCED_SECURITY.md](docs/ADVANCED_SECURITY.md): bốn tính năng mới, nguồn tham khảo và giới hạn.
- [SECURITY_AUTOMATION.md](docs/SECURITY_AUTOMATION.md): phạm vi kiểm chứng và cấu trúc bằng chứng.
- [SECURITY_REQUIREMENTS_TRACEABILITY.md](docs/SECURITY_REQUIREMENTS_TRACEABILITY.md): truy vết yêu cầu tới mã và kiểm thử.

`run_app.py`, cấu hình `.env` và Docker vẫn phục vụ các cách chạy khác. Với đồ
án demo trên máy cá nhân, dùng `scripts.demo_local` để có một điểm bắt đầu
nhất quán và dễ diễn tập lại.
