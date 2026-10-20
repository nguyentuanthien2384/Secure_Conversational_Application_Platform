# Kịch bản demo đồ án SCAP trên máy cá nhân

Demo dùng dữ liệu giả, SQLite tạm và AI ngoại tuyến. Mục tiêu là chứng minh
kiểm soát bảo mật của ứng dụng bằng thao tác có thể lặp lại. Không cần Claude
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

## Tùy chọn: mã hóa/giải mã trong trình duyệt — thêm 2 phút

Phần này độc lập với bản 6 phút, mã hóa lưu trữ của tài khoản và chat E2EE.
Dùng HTTPS hoặc localhost. Trước khi trình chiếu, tạo mật khẩu sao lưu tạm
riêng cho dữ liệu giả của lượt demo, dài hơn 16 ký tự, rồi giữ ở nơi riêng để
nhập lại:

```powershell
.\.venv\Scripts\python.exe -c "import secrets; print('Demo-' + secrets.token_urlsafe(18))"
```

1. Mở **Dữ liệu mã hóa → Mã hóa & giải mã trong trình duyệt**. Nhập mật khẩu
   vừa tạo vào hai ô xác nhận, bấm **Tạo cặp khóa**, rồi **Xuất khóa riêng đã
   mã hóa**. Giữ tệp bản sao trước khi đổi tab hoặc tải lại. Chỉ trình bày
   public key và fingerprint, không hiển thị khóa riêng dạng rõ.
2. Giữ khóa của mình làm người nhận ban đầu. Nhập văn bản giả
   `Xin chào nhà tuyển dụng, đây là dữ liệu demo SCAP.` và ngữ cảnh công khai
   `phong-van-demo`. Bấm **Mã hóa văn bản**, giữ lại gói JSON gốc, rồi **Giải
   mã bằng khóa của bạn**. Kết quả phải khớp nguyên văn; ngữ cảnh vẫn nhìn
   thấy trong gói nên không chứa bí mật.
3. Trong gói JSON, chỉ đổi giá trị `context` thành `phong-van-demo-sua`, giữ
   JSON hợp lệ rồi giải mã lại. Thao tác phải bị từ chối và kết quả bản rõ
   cũ được xóa. Không mô tả metadata của hội thoại là bằng chứng kiểm tra này.
4. Tải lại trang hoặc chuyển tab rồi quay lại: khóa và các ô dữ liệu đã được
   xóa khỏi công cụ. Nếu cần, đăng nhập lại; chọn tệp bản sao khóa riêng đã
   mã hóa, nhập mật khẩu sao lưu, bấm **Mở bản sao bằng mật khẩu**. Dán lại
   gói JSON gốc để giải mã thành công.

**Nói:** “Thao tác này chạy trong tab bằng RSA-OAEP và AES-GCM, không gửi
văn bản hay khóa riêng tới API/AI. Khóa demo độc lập với khóa hội thoại và
thiết bị Olm/MLS. Mất bản sao hoặc mật khẩu thì không khôi phục được; đây
không phải cơ chế xác minh danh tính người gửi hay thay thế giao thức chat
E2EE.” Giới hạn và cách giữ bản sao nằm trong
[hướng dẫn công cụ trình duyệt](SECURITY_EXTENSIONS.md#crypto-workbench).

### Tùy chọn thêm: mã hóa tệp — 2 phút

Chuẩn bị một tệp thử nhỏ không chứa dữ liệu thật, chẳng hạn `.txt` với dòng
`Tệp giả cho buổi demo SCAP`. Giữ cặp khóa đã tạo và bản sao khóa riêng ở bước
trước; thao tác trong cùng tab để tránh khóa bị xóa khi trang bị ẩn.

1. Ở phần **4 · Mã hóa & giải mã tệp**, chọn tệp thử. Đối chiếu tên, số byte
   và cấu hình AES-256-GCM / nonce 96 bit / thẻ 128 bit / không padding.
2. Nhập ngữ cảnh công khai `demo-tep`, bấm **Mã hóa & tải tệp .scapenc**.
   Gói tải xuống dùng tên `scap-encrypted-file.scapenc`; không có tệp tải lên API.
3. Chọn lại gói vừa tải, bấm **Giải mã & tải tệp .bin**. Đối chiếu tên gốc,
   SHA-256 và nội dung tệp `scap-restored.bin` với tệp thử. Đổi tên bản tải
   nếu cần; chỉ mở dữ liệu giả đã tự tạo cho demo.
4. Đổi tệp đang chọn hoặc đăng xuất: kết quả cũ trên giao diện bị xóa. Các
   tệp đã tải về máy vẫn còn; nút khóa không xóa tệp trên ổ đĩa.

**Nói:** “Công cụ xử lý cả tệp nhị phân tối đa 5 MiB ở trình duyệt, có khóa và
nonce mới cho mỗi lần mã hóa. Toàn vẹn được kiểm tra trước khi tải bản rõ,
nhưng điều đó không chứng minh danh tính người gửi hoặc tệp không chứa mã độc.”

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

<a id="demo-private-e2ee-voi-hai-client"></a>
## Demo Private E2EE với hai client

Đây là luồng 1:1 riêng dùng Olm/Double Ratchet qua `vodozemac`, không gọi AI.
Hai client giữ khóa riêng, pin fingerprint và giải mã tại máy của mình.
Server là tiến trình riêng, chỉ nhận public material và ciphertext. Không dùng
dữ liệu nhạy cảm thật trong buổi demo.

### Diễn tập tự động trước buổi phỏng vấn

```powershell
uv sync --frozen --group dev --extra e2ee-client
uv run --frozen --extra e2ee-client python -m scripts.demo_e2ee --check --output-dir reports/e2ee-rehearsal
```

Runner tạo server và hai kho client tạm, kiểm tra gửi/nhận hai chiều, export
ciphertext, cursor và refill prekey, rồi dọn môi trường thử. JSON kết quả nằm
trong thư mục đã chọn. Lệnh không kết nối server local/VPS đang vận hành.

### Thao tác trực tiếp trong khoảng 4 phút

Giữ launcher `uv run --frozen python -m scripts.demo_local` chạy. Mở hai
terminal khác nhau, mỗi terminal dùng một profile riêng:

```powershell
# Terminal A
uv run --frozen --extra e2ee-client python -m clients.private_chat --username demo.user --profile client_data/interview-alice

# Terminal B
uv run --frozen --extra e2ee-client python -m clients.private_chat --username demo.mod --profile client_data/interview-bob
```

Nhập mật khẩu kho client riêng, ít nhất 16 byte; sau đó nhập mật khẩu SCAP
`Phenikaa-Vault#2026-Lab`. Các mật khẩu được nhập ẩn. Kho giữ khóa và trạng thái
được mã hóa; bearer chỉ nằm trong bộ nhớ tiến trình.

1. Trên cả hai terminal gõ `register`, rồi `fingerprint`. Ghi nhận Device UUID
   và **toàn bộ fingerprint** của mỗi bên, đối chiếu trực tiếp hoặc qua kênh
   độc lập. Fingerprint và Device UUID là dữ liệu công khai.
2. A gõ `pin demo.mod`, nhập fingerprint và Device UUID của B. B gõ
   `pin demo.user`, nhập fingerprint và Device UUID của A. Không tự chấp nhận
   fingerprint mới khi danh tính thay đổi.
3. A gõ `new demo.mod`; lấy Session UUID được trả về.
4. A gõ `send <session-uuid> <device-uuid-của-B>`, nhập một câu hỏi ở prompt
   kế tiếp. B gõ `receive <session-uuid>` để giải mã cục bộ.
5. B gõ `send <session-uuid> <device-uuid-của-A>`, nhập câu trả lời. A gõ
   `receive <session-uuid>`. Gõ lại `receive` phải không phát lại tin đã nhận.
6. Gõ `refill 20` để minh họa bổ sung public prekey có chữ ký sở hữu thiết bị.
   Nếu step-up đã hết hạn, gõ `stepup` rồi thử lại. Nếu mất phản hồi, gõ lại
   `refill`; client giữ batch public key đang chờ để xác nhận an toàn. Gõ
   `quit` khi xong.

`send` ghi ratchet và ciphertext đang chờ xuống kho trước khi gửi HTTP. Nếu
mất mạng, `retry` gửi lại đúng ciphertext đó; không tạo tin mới để thay thế.
Client từ chối mở cùng một profile ở hai tiến trình. Nếu không lưu được trạng
thái, client đóng và yêu cầu mở lại profile; không tiếp tục dùng ratchet chỉ
còn trong RAM. Khi một đợt nhận bị dừng, các tin hợp lệ trước đó vẫn được hiển
thị và tin lỗi chưa được đánh dấu đã nhận.

Muốn mở lại, dùng cùng profile, tài khoản và server. Launcher demo mới có DB
và account ID mới nên cần **profile demo mới**; không dùng lại profile đã gắn
với lượt demo trước. Không sao chép, chia sẻ hoặc phục hồi ratchet cũ để tiếp
tục gửi. `client_data/` đã bị loại khỏi Git và Docker build context.

**Nói:** “Tôi dùng thư viện Olm thay vì tự viết ratchet. Test chứng minh hai
client SCAP gửi/nhận được và server export chỉ có ciphertext. Tích hợp này
chưa được audit độc lập; kiểm chứng tương thích với ứng
dụng bên ngoài là phạm vi phát triển tiếp.”

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

## Demo nhóm MLS và bảo vệ tài khoản mở rộng

Chuẩn bị native helper trước buổi demo, với Docker Desktop ở chế độ Linux
containers trên máy client:

```powershell
docker build -t scap-mls-client:local clients/mls_native
uv run --frozen --extra e2ee-client python -m scripts.demo_mls --check
```

Runner dùng ba client và server loopback riêng. Chỉ ra ba bằng chứng trong
`reports/mls-demo/mls-demo.json`: các thành viên giải mã được tin nhóm, người
bị loại không thể dùng private state cũ giải mã epoch mới, export của server
chỉ chứa ciphertext. Để nhập tin trực tiếp, làm theo
[hướng dẫn terminal MLS](../clients/mls_native/README.md); cần đối chiếu đầy đủ
fingerprint và trao đổi KeyPackage public có chữ ký. Phạm vi hiện tại là nhóm
do owner quản lý, một thiết bị mỗi tài khoản.

Trong **Tài khoản**, có thể trình bày xác thực lại bằng passkey và đăng ký số
điện thoại bằng mã SMS trong outbox demo. Dùng `localhost` cho WebAuthn. Màn
hình trạng thái cho biết kênh đang tắt, outbox hay provider; không mô tả outbox
là SMS/Push đã giao tới thiết bị. GeoIP chỉ hoạt động khi có City MMDB hợp lệ,
mới; thiếu database phải hiện chưa khả dụng. Xem
[cấu hình và phạm vi kiểm chứng](SECURITY_EXTENSIONS.md).

**Nói:** “Tôi sử dụng thư viện OpenMLS và kiểm tra vòng đời thành viên bằng
ba client riêng. Đây là kiểm chứng tích hợp trong SCAP; tương thích với client
bên ngoài và kiểm toán độc lập vẫn cần thực hiện trước khi dùng production.”
