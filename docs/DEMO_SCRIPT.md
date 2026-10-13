# Kịch bản demo đồ án SCAP trên máy cá nhân

Demo dùng dữ liệu giả, SQLite tạm và AI ngoại tuyến. Mục tiêu là chứng minh
kiểm soát bảo mật của ứng dụng bằng thao tác có thể lặp lại. Không cần Gemini
API key, Docker, máy chủ, tên miền hoặc kết nối Internet trong buổi trình bày
sau khi đã cài đủ thư viện.

## Chuẩn bị trước buổi trình bày

1. Từ thư mục dự án, kiểm tra sẵn sàng:

   ```powershell
   .\.venv\Scripts\python.exe -m scripts.demo_local --check
   ```

2. Chạy bộ kiểm chứng; lưu kết quả để dùng trong báo cáo:

   ```powershell
   .\.venv\Scripts\python.exe -m scripts.validate_security --output-dir reports/security-validation-rehearsal
   ```

3. Mở ứng dụng và giữ terminal này chạy:

   ```powershell
   .\.venv\Scripts\python.exe -m scripts.demo_local
   ```

4. Mở <http://127.0.0.1:8000> trong cửa sổ chính; mở cùng địa chỉ trong cửa sổ
   ẩn danh cho quản trị viên. Nếu đổi cổng bằng `--port`, dùng đúng cổng đó.
5. Đăng nhập thử `demo.user` và `demo.boss`. Mật khẩu chung:
   **`Phenikaa-Vault#2026-Lab`**. Chuẩn bị ứng dụng TOTP trên điện thoại nếu chọn
   bản 12 phút. Không cần mạng để sinh mã TOTP sau khi thiết lập.

Mỗi lần launcher chạy là một lượt demo mới, có khóa và dữ liệu riêng, không
dùng `.env` hoặc dữ liệu đang có. Muốn làm lại, dừng bằng `Ctrl+C`, chạy lại
và đăng nhập lại. Lưu bằng chứng cần giữ trước khi dừng. Không cần tắt IDS,
xóa cơ sở dữ liệu đang sử dụng hoặc sửa chuỗi audit để tiếp tục bài trình bày.

Phân biệt ba loại bằng chứng khi nói với hội đồng:

- **Thao tác trực tiếp:** yêu cầu thật gửi tới ứng dụng đang chạy trên máy.
- **Dữ liệu mẫu:** sự kiện và hội thoại được seed để minh họa màn hình.
- **Kiểm chứng tự động:** runner gửi yêu cầu tới ứng dụng thử nghiệm riêng,
  đối chiếu trạng thái HTTP, audit và tác động lên dữ liệu. Nhánh AI bên ngoài
  dùng nhà cung cấp giả lập, không gọi một dịch vụ AI thật.

## Bản 6 phút

### 1. Đăng nhập và phạm vi quyền — 45 giây

**Thao tác:** đăng nhập `demo.user`. Chỉ vào các tab Trò chuyện, Dữ liệu mã
hóa, Tìm kiếm và Tài khoản. So sánh với cửa sổ ẩn danh đang đăng nhập
`demo.boss`, có thêm chức năng quản trị.

**Kết quả:** hai tài khoản có quyền khác nhau. Việc ẩn tab chỉ là cách hiển
thị; quyền vẫn được kiểm tra tại API.

**Nói:** “Mật khẩu được băm bằng Argon2id. Mỗi phiên đăng nhập được theo dõi
ở máy chủ. Vai trò quyết định thao tác quản trị, còn quyền sở hữu quyết định
ai được đọc từng hội thoại.”

### 2. Chat và kiểm tra dữ liệu mã hóa — 1 phút

**Thao tác:** ở Trò chuyện, nhập tiêu đề `Demo đồ án`, giữ chế độ **Secure**,
bấm **+ Hội thoại mới**. Gửi:

```text
Tôi muốn tìm hiểu bảo mật ứng dụng trong đồ án này.
```

Chuyển sang **Dữ liệu mã hóa**, chọn hội thoại vừa tạo và bấm **Tải bản mã**.

**Kết quả:** bot trả lời với tiền tố `[DEMO AI]`. Bảng bản mã hiển thị
ciphertext, nonce và phiên bản khóa; nội dung câu vừa gửi không xuất hiện
dưới dạng bản rõ trong các trường bản mã.

**Nói:** “Đây là AI ngoại tuyến để trình diễn luồng xử lý. Nội dung tin nhắn
được mã hóa AES-256-GCM, có khóa dữ liệu riêng cho hội thoại và dữ liệu xác
thực bổ sung gắn với bản ghi. Tiêu đề và metadata không phải toàn bộ đều
được mã hóa. Chế độ Secure là mã hóa phía máy chủ, không phải E2EE.”

### 3. DLP nhận diện cả email mã hóa — 1 phút

**Thao tác:** gửi trong cùng hội thoại:

```text
Email giả của tôi là demo@example.com; dạng mã hóa là demo%40example.com.
```

**Kết quả:** phần trả lời `[DEMO AI]` chứa bản xem trước sau DLP, email và
dạng mã hóa được thay bằng nhãn che. Thông báo nêu loại dữ liệu đã xử lý;
bản gốc vẫn được mã hóa để lưu trong hội thoại của người gửi.

**Nói:** “DLP kiểm tra một số dạng mã hóa với giới hạn số lớp và dung lượng,
rồi ánh xạ kết quả về đoạn gốc để che. Chế độ ngoại tuyến chỉ minh họa bản
xem trước. Khi dùng AI bên ngoài, phải có đồng thuận; secret, khóa riêng và
số thẻ bị chính sách chặn gửi ra ngoài, không chỉ che rồi gửi.”

Không bỏ tick consent rồi chờ lỗi 403 trong chế độ này: bot ngoại tuyến
không cần đồng thuận gửi dữ liệu sang bên thứ ba. Bằng chứng chặn secret mã
hóa, che email và lọc phản hồi AI ngoài nằm trong tình huống `encoded-dlp`
với nhà cung cấp giả lập đã bật consent. Kiểm thử từ chối do thiếu consent
nằm trong bộ pytest.

### 4. Thời hạn phiên — 45 giây

**Thao tác:** mở **Tài khoản → Thiết bị đang đăng nhập**. Chỉ vào các cột hoạt
động gần nhất, hết hạn nếu không hoạt động và giới hạn phiên tối đa. Bấm
**Làm mới** để cho thấy bảng có thể được kiểm tra lại.

**Kết quả:** phiên hiện tại có mốc thời gian do máy chủ cung cấp. Làm mới
bảng và refresh token không tự kéo dài mốc không hoạt động. Các yêu cầu
nghiệp vụ hợp lệ khác có thể cập nhật hoạt động.

**Nói:** “Mặc định phiên hết hạn sau 30 phút không hoạt động và tối đa 8 giờ
kể từ lúc đăng nhập. Kiểm tra nằm ở máy chủ. Tình huống tự động điều chỉnh
thời gian trên dữ liệu thử để kiểm tra ngay, không phải chờ 30 phút.”

### 5. Audit và phát hiện bất thường — 1 phút

**Thao tác:** chuyển sang cửa sổ `demo.boss`, vào **Bảo mật**. Bấm **Xác minh
chuỗi**, sau đó **Phân tích** ở mục **IDS — hành vi bất thường**.

**Kết quả:** chuỗi audit hợp lệ. Danh sách bất thường có thể đọc được từ các
sự kiện mẫu trong cửa sổ thời gian. Nêu rõ các sự kiện do seed tạo là mô phỏng.

**Nói:** “Chuỗi HMAC giúp phát hiện sửa dữ liệu audit. Hệ thống còn tương
quan nhiều lần đăng nhập sai từ nhiều IP và trường hợp thất bại rồi đăng
nhập thành công. Đây là tín hiệu để kiểm tra, không tự kết luận tài khoản
đã bị chiếm và không tự khóa tài khoản chỉ vì tương quan này.”

### 6. Bằng chứng kiểm chứng — 1 phút 30 giây

**Thao tác:** trình chiếu kết quả đã chạy ở terminal và mở
`reports/security-validation-rehearsal/security-validation.json`. Chỉ vào các mục
`session-timeout`, `encoded-dlp`, `auth-correlation`, `browser-origin` và một
mục `idor` hoặc `audit-tamper`.

**Kết quả:** từng tình huống đạt các kiểm tra bên trong; có bằng chứng như
trạng thái HTTP, mã audit hoặc kết quả đối chiếu. Nếu kết quả chưa đạt,
trình bày lỗi thực tế, không gọi đó là một tình huống thành công.

**Nói:** “Các tình huống chạy trên SQLite và khóa tạm riêng. Nhà cung cấp AI
được giả lập để kiểm tra chặn gửi và lọc phản hồi mà không cần Internet.
Kết quả chứng minh các kiểm soát trong phạm vi test; không phải một chứng
nhận chống được mọi tấn công hoặc đã kiểm thử hạ tầng thật.”

## Bản 12 phút

Giữ bản 6 phút và thêm ba phần dưới đây. Nếu muốn tự gọi Swagger, diễn tập
riêng trước buổi bảo vệ; không đưa bearer token lên ảnh báo cáo.

### 7. MFA và thu hồi thiết bị — thêm 2 phút 30 giây

**Thao tác:** dùng `demo.user`, vào **Tài khoản → Xác thực hai lớp (TOTP)**:
bấm **Bắt đầu thiết lập 2FA**, quét QR, nhập mã rồi **Kích hoạt**. Giữ riêng
mã khôi phục cho lượt demo, không đưa vào slide. Đăng xuất, đăng nhập lại;
đợi mã TOTP mới nếu mã hiện tại vừa được dùng để kích hoạt.

**Kết quả:** mật khẩu đúng mới qua bước đầu; phải có TOTP hoặc mã khôi phục
hợp lệ mới hoàn tất đăng nhập. Mã TOTP đã dùng không được dùng lại trong
cùng bước thời gian.

**Nói:** “MFA thêm yếu tố sở hữu ngoài mật khẩu. Mã khôi phục chỉ hiện một
lần, được lưu dạng băm và mỗi mã chỉ dùng một lần. Khi khởi động lại lượt
demo, dữ liệu MFA tạm này cũng được tạo lại từ đầu.”

Nếu còn thời gian, đăng nhập cùng tài khoản ở một cửa sổ riêng, làm mới
danh sách thiết bị và thu hồi đúng phiên đó. Ở cửa sổ bị thu hồi, thao tác
API tiếp theo phải yêu cầu đăng nhập lại. Không thu hồi phiên đang dùng để
trình chiếu trước khi hoàn tất phần này.

### 8. IDOR, chặn dò mật khẩu và audit bị sửa — thêm 2 phút

**Thao tác:** tại terminal thứ hai, chạy:

```powershell
.\.venv\Scripts\python.exe -m scripts.validate_security --scenario idor --scenario brute-force --scenario audit-tamper --output-dir reports/security-validation-access
```

**Kết quả:** đọc/xóa tài nguyên của người khác bị từ chối, tài nguyên của
chủ sở hữu vẫn truy cập được; dò mật khẩu bị giới hạn; audit bị sửa trong
SQLite thử nghiệm được phát hiện. Xem kết quả từng kiểm tra trong JSON.

**Nói:** “Phần thử âm tính chạy riêng nên không làm khóa tài khoản hoặc
chặn IP của giao diện đang trình chiếu. Sửa audit chỉ xảy ra trên bản thử
nghiệm tạm. Tôi không sửa cơ sở dữ liệu của ứng dụng để dàn dựng kết quả.”

### 9. Kiểm tra yêu cầu khác nguồn và luật IDS — thêm 1 phút 30 giây

**Thao tác:** chạy kiểm chứng yêu cầu trình duyệt:

```powershell
.\.venv\Scripts\python.exe -m scripts.validate_security --scenario browser-origin --output-dir reports/security-validation-origin
```

Sau đó ở cửa sổ `demo.boss`, mở **Bảo mật → Purple Team — kiểm chứng luật
phát hiện**, bấm **Chạy kiểm chứng Hit/Miss**.

**Kết quả:** kiểm chứng khác nguồn từ chối yêu cầu thay đổi dữ liệu có nguồn
không được tin cậy và cho phép ca hợp lệ; luật IDS được đối chiếu các mẫu
trong ứng dụng, không gửi payload khai thác ra mạng.

**Nói:** “Kiểm tra Origin và Fetch Metadata áp dụng cả API lẫn Gradio.
Header giả lập trong test chứng minh nhánh xử lý phía máy chủ. Nút Hit/Miss
kiểm tra engine IDS nội bộ; nó không phải một lần pentest từ bên ngoài.”

## Bằng chứng nên giữ cho báo cáo

1. Ảnh giao diện chat ngoại tuyến có email được che và ảnh các trường bản mã.
2. Ảnh thời hạn phiên; ảnh audit hợp lệ và bất thường có ghi chú “dữ liệu mẫu”.
3. Dòng tổng kết bộ kiểm chứng, JSON/JUnit cùng ngày chạy và mã phiên bản mã
   nguồn nếu có. Các lần chạy dùng thư mục đầu ra riêng để tránh ghi đè.
4. Dòng tổng kết pytest, Ruff và Bandit thực tế. Lệnh nằm trong
   [HUONG_DAN_CHAY.md](../HUONG_DAN_CHAY.md).
5. Một video 6 phút quay trước để dự phòng. Không quay QR, khóa MFA, mã khôi
   phục, token hoặc dữ liệu cá nhân thật.

## Các câu hỏi nên trả lời rõ

- **“AI này có trả lời thông minh không?”** Bot hiện tại là mô phỏng ngoại
  tuyến cho bài bảo mật. Tích hợp provider có sẵn nhưng không được gọi trong
  lượt demo này.
- **“Mã hóa rồi thì quản trị viên không thể xem gì?”** API chặn đọc hội thoại
  của người khác. Với Secure, tiến trình máy chủ vẫn có khả năng giải mã để
  phục vụ chủ sở hữu; đây không phải cam kết E2EE.
- **“DLP có phát hiện mọi cách che giấu không?”** Không. Bộ dò hỗ trợ các dạng
  và ngân sách kiểm tra được nêu trong tài liệu; có thể có cảnh báo nhầm hoặc
  cách né chưa được hỗ trợ.
- **“Đã chứng minh chạy trên PostgreSQL/Redis chưa?”** Lượt demo và runner
  này dùng SQLite, một tiến trình. Không suy rộng kết quả sang hạ tầng chưa
  được kiểm chứng.
- **“Chuỗi audit có chống được chiếm toàn bộ máy không?”** Không đầy đủ. Nếu
  kẻ tấn công có cả dữ liệu và khóa HMAC, họ có thể tính lại chuỗi. Checkpoint
  ngoài/WORM là phần mở rộng, không được dựng thành dịch vụ thật trong demo.

Nguồn nghiên cứu và giới hạn bốn tính năng nâng cấp nằm tại
[ADVANCED_SECURITY.md](ADVANCED_SECURITY.md); phạm vi runner nằm tại
[SECURITY_AUTOMATION.md](SECURITY_AUTOMATION.md).
