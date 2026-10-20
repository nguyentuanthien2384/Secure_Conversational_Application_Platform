# Passkey step-up, Push/SMS, GeoIP và nhóm MLS

Các phần mở rộng này dùng chung quyền sở hữu, kiểm tra phiên, audit và giới hạn
tài nguyên của SCAP. Gói local demo dùng dữ liệu tạm; việc bật nhà cung cấp thật
cần cấu hình riêng và không tự gửi thông báo khi chỉ cài dependency.

## Chạy và kiểm tra local

```powershell
uv sync --frozen --group dev --all-extras
uv run --frozen python -m scripts.demo_local --check
uv run --frozen python -m scripts.demo_local
```

Trong **Tài khoản**, thêm passkey rồi dùng **Xác thực lại bằng passkey**. Chuẩn
bị yêu cầu trước, bấm xác nhận trên thiết bị sau để giữ yêu cầu có thao tác trực
tiếp của người dùng. Dùng `http://localhost:8000` cho WebAuthn, hoặc HTTPS với
đúng RP ID/origin đã cấu hình. Passkey phải thực hiện xác minh người dùng (UV).

**Thông báo bảo mật qua Push / SMS** cho biết từng kênh đang tắt, dùng outbox
hay có nhà cung cấp. Launcher demo bật outbox: mã xác minh SMS nằm trong `.eml`
tại thư mục `security-notification-outbox` được in trong terminal. Không có SMS
thật được gửi. Mã 8 số hết hạn sau 5 phút, chỉ dùng một lần và gắn đúng phiên.

Push cần HTTPS/localhost, trình duyệt hỗ trợ Push API và quyền do người dùng
bấm cấp. Nếu cùng trình duyệt đã gắn với tài khoản khác, dùng thao tác gỡ đăng
ký trên trình duyệt rồi đăng ký lại. Không tự cấp quyền hoặc chuyển subscription
từ tài khoản khác ở phía server. Service worker không cache tài nguyên hay API.

## Bật Web Push thật

```powershell
uv run --frozen python -m scripts.generate_vapid_key --output local_data/push/vapid.pem
```

Công cụ chỉ in public key, không in private key, và từ chối ghi đè key cũ.
Cấu hình `.env` cho local có lưu dữ liệu:

```dotenv
PUSH_BACKEND=webpush
VAPID_PRIVATE_KEY_FILE=local_data/push/vapid.pem
VAPID_SUBJECT=mailto:security@example.com
```

Dùng địa chỉ liên hệ thật thay địa chỉ mẫu. Cặp VAPID phải giữ ổn định qua các
lần deploy; đổi public key có thể yêu cầu trình duyệt đăng ký lại. Mỗi tài khoản
có tối đa 8 subscription. Endpoint chỉ được chấp nhận cho các dịch vụ Push được
hỗ trợ; kết nối kiểm tra địa chỉ DNS công khai, ghim IP, xác minh TLS với SNI gốc,
không theo redirect hoặc proxy môi trường. Payload chỉ chứa cảnh báo cố định.

## Bật SMS thật

```dotenv
SMS_BACKEND=twilio
TWILIO_ACCOUNT_SID=AC<account-sid>
TWILIO_AUTH_TOKEN_FILE=local_data/sms/twilio-token
TWILIO_FROM=+<so-gui-da-duoc-nha-cung-cap-cap>
```

Tạo token file riêng tư, không đưa vào Git hoặc build context. Tài khoản Twilio,
sender và quyền gửi tới quốc gia đích phải có sẵn; phí và hạn chế trial thuộc
nhà cung cấp. Chỉ số E.164 đã chứng minh sở hữu mới nhận cảnh báo. SMS không
được dùng để bỏ qua MFA hoặc khôi phục tài khoản. Provider accepted chỉ xác nhận
dịch vụ chấp nhận yêu cầu, chưa xác nhận người nhận đã nhận hay đọc SMS.

Các kênh tùy chọn được xếp hàng sau commit. Lỗi gửi không đảo ngược thao tác tài
khoản đã hoàn tất. Hàng đợi, worker, timeout và tần suất gửi đều có giới hạn.
Chế độ `outbox` bị từ chối ngoài development/test. Khi khôi phục PostgreSQL,
quarantine gỡ các địa chỉ thông báo và challenge để người dùng đã rà soát đăng
ký lại, tránh khôi phục nhầm kênh cũ.

## Bật cảnh báo di chuyển bất thường

Mỗi lần đăng nhập thành công, SCAP tra IP trong một cơ sở dữ liệu City MMDB nằm
ngay trên máy chủ (không gửi IP tới dịch vụ định vị nào) và so với các lần đăng
nhập thành công trong `GEOIP_HISTORY_HOURS` giờ trước. Nếu hai vị trí cách nhau
trên `GEOIP_MIN_DISTANCE_KM` và tốc độ di chuyển cần thiết vượt
`GEOIP_MAX_SPEED_KMH`, hệ thống ghi **Đăng nhập xa bất thường** vào Hoạt động bảo
mật và gửi thông báo. Chỉ cảnh báo, không tự khóa tài khoản.

**Nguồn dữ liệu mặc định:** DB-IP "IP to City Lite": miễn phí, cập nhật hằng
tháng, giấy phép CC BY 4.0, không cần tài khoản. Giao diện ghi nguồn "IP
Geolocation by DB-IP" như giấy phép yêu cầu. Tải và cài (script kiểm tra file
trước khi thay, chỉ dùng thư viện chuẩn của Python):

```powershell
uv run python -m scripts.update_geoip --dir local_data/geoip
```

Muốn dùng MaxMind GeoLite2-City (cần tài khoản và license riêng), tải file
`.mmdb`/`.mmdb.gz` về rồi cài bằng `--source-file <đường dẫn>`. Cả hai đều theo
định dạng MaxMind DB nên `GEOIP_BACKEND=maxmind` dùng chung cho mọi nguồn.

```dotenv
GEOIP_BACKEND=maxmind
GEOIP_DATABASE_FILE=local_data/geoip/geoip-city.mmdb
GEOIP_MAX_DATABASE_AGE_DAYS=90
GEOIP_HISTORY_HOURS=24
GEOIP_MIN_DISTANCE_KM=500
GEOIP_MAX_SPEED_KMH=900
GEOIP_DEFAULT_ACCURACY_KM=200
```

Docker local tự mount `local_data/geoip` chỉ đọc vào container
(`docker-compose.local.yml`), nên chỉ cần đặt `GEOIP_BACKEND=maxmind` trong
`.env` rồi tạo lại container app. Trên máy cá nhân, IP đăng nhập là địa chỉ nội
bộ (127.0.0.1, mạng Docker) nên không định vị được; tính năng thực sự đánh giá
khi chạy trên VPS với IP công khai của người dùng. File test trong
`tests/fixtures/maxmind` là dữ liệu tổng hợp, không dùng để định vị thật.

Khoảng cách được trừ bán kính sai số của cả hai vị trí. DB-IP không có bán kính
sai số nên dùng `GEOIP_DEFAULT_ACCURACY_KM` (mặc định 200 km mỗi đầu), để khoảng
cách luôn là cận dưới. Không lưu tọa độ hay tên thành phố vào audit, chỉ lưu mã
quốc gia và khoảng cách làm tròn. VPN hoặc mạng di động có thể làm vị trí ước
lượng sai. App nạp file lúc khởi động; dữ liệu quá `GEOIP_MAX_DATABASE_AGE_DAYS`
ngày thì tạm dừng đánh giá (báo "chưa khả dụng") chứ không chặn đăng nhập. Kiểm
tra trong **Tài khoản → Hoạt động bảo mật gần đây → Kiểm tra đánh giá vị trí
đăng nhập**: hiện nguồn dữ liệu, ngày cập nhật, ngưỡng cảnh báo và vị trí ước
lượng của chính IP bạn đang dùng (chỉ hiển thị cho bạn, không lưu).

## Đóng gói cho Docker/VPS

Image app và migration đã chứa SDK cho Push và GeoIP. Đặt các file cần dùng vào
một thư mục riêng tư đã tồn tại trên máy chủ: `vapid.pem`, `twilio-token`,
`geoip-city.mmdb`; chỉ cần file tương ứng với kênh được bật. File GeoIP do
`scripts.update_geoip` tạo với quyền 644 để user `app` trong container đọc được. File bí mật phải
đọc được bởi UID app trong container và không cấp quyền đọc công khai.

Đặt `SCAP_SECURITY_FILES_DIR` thành đường dẫn tuyệt đối của thư mục đó trong
`deploy/.env.vps`. `deploy/vps-compose.sh` tự thêm overlay
`docker-compose.security-channels.yml`, mount chỉ đọc vào `/run/scap-security`
và không tự tạo thư mục host còn thiếu. Các biến backend và thông tin public
provider vẫn nằm trong env file; private key/token chỉ đọc từ file. Với Docker
không dùng wrapper VPS, thêm `-f docker-compose.security-channels.yml` khi gọi
Compose. Không đưa thư mục chứa key hoặc MMDB vào archive triển khai.

## Demo nhóm MLS

```powershell
docker build -t scap-mls-client:local clients/mls_native
uv run --frozen --extra e2ee-client python -m scripts.demo_mls --check
```

Demo dùng OpenMLS 0.9.1 với Cargo.lock, ba client riêng và server loopback tạm.
Nó kiểm tra Commit/Welcome, gửi nhóm, loại một thành viên, thay epoch và từ chối
giải mã tin mới bằng toàn bộ private state cũ của người đã bị loại. Cùng lúc,
server export chỉ chứa ciphertext. Hướng dẫn nhập tin trực tiếp và trao đổi
KeyPackage public có chữ ký nằm trong [native MLS client](../clients/mls_native/README.md).

Client hiện hỗ trợ nhóm do owner quản lý, một thiết bị mỗi tài khoản. Mọi
thành viên phải đối chiếu fingerprint và pin roster. Native helper giữ mạng,
mount và container log ở trạng thái tắt; private state đi qua pipe và chỉ được
lưu trong kho client mã hóa. Hệ điều hành và Docker daemon vẫn thuộc môi trường
client cần tin cậy. Không phục hồi ratchet cũ để tiếp tục gửi.

Các test và demo không thay thế kiểm toán độc lập cho tích hợp SCAP, kiểm chứng
tương thích với client MLS khác hoặc kiểm tra nhà cung cấp/hạ tầng thật.

<a id="crypto-workbench"></a>
## Công cụ mã hóa/giải mã cục bộ trong trình duyệt

Mở **Dữ liệu mã hóa** trên HTTPS hoặc localhost. Phần **Thông số mã hóa hội
thoại** đọc metadata của hội thoại thuộc tài khoản: thuật toán lưu trữ, epoch,
loại provider, trường AAD và số bản ghi theo định dạng. Thao tác này không giải
mã hoặc kiểm tra tính toàn vẹn ciphertext; `integrity_verification` vẫn là
`not_performed`. Private E2EE để client xác định bộ mật mã và kiểm tra bản mã,
không suy ra khóa AES của client từ metadata máy chủ.

Phần **Mã hóa & giải mã trong trình duyệt** là công cụ riêng, sử dụng RSA-OAEP
3072/SHA-256 để bọc khóa AES-256-GCM ngẫu nhiên cho từng gói văn bản. Nó không
dùng khóa hội thoại, master key hoặc private state E2EE của tài khoản. Mật khẩu
bản sao khóa, văn bản gốc và nội dung giải mã là các trường DOM cục bộ, không
được nối tới callback Gradio, API hoặc AI.

1. Nhập mật khẩu sao lưu riêng ít nhất 16 ký tự và xác nhận để tạo cặp khóa.
2. Tải **khóa riêng đã mã hóa**, giữ mật khẩu ở nơi riêng biệt. Không có chức
   năng khôi phục khi mất bản sao hoặc mật khẩu. Private key đang mở không cho
   xuất dạng rõ; chỉ public key có nút sao chép và xuất PEM.
3. Nhập public key người nhận và đối chiếu toàn bộ fingerprint SHA-256 qua kênh
   tin cậy. Nhấn **Dùng public key người nhận**, nhập văn bản rồi mã hóa. Khóa
   vừa tạo cũng được chọn làm người nhận ban đầu để thử tự mã hóa/giải mã.
4. Người nhận mở bản sao khóa riêng bằng mật khẩu của mình, dán gói JSON và
   nhấn giải mã. Trường ngữ cảnh AAD là thông tin công khai trong gói, không
   điền bí mật vào đó. Gói bị sửa, sai khóa hoặc sai mật khẩu bị từ chối.

Giới hạn là 64 KiB văn bản UTF-8 và 256 byte ngữ cảnh. Khóa và nội dung chỉ ở
tab hiện tại, không tự lưu vào web storage hoặc database. Công cụ bỏ trạng
thái và xóa trường hiển thị khi đăng xuất, trang bị ẩn/rời đi, tải lại, sau
5 phút không thao tác hoặc bấm **Khóa & xóa dữ liệu tại tab**. Lưu bản sao
trước khi đổi cửa sổ/tab. Việc này không bảo đảm xóa vật lý mọi bản sao trong
bộ nhớ do trình duyệt quản lý. Gói mã hóa không chứng minh danh tính người
gửi, không chống phát lại và không có forward secrecy như giao thức Olm/MLS.
Kiểm tra toàn vẹn phát hiện gói bị sửa nhưng không xác thực ai đã tạo gói.
Private key không xuất dạng rõ vẫn có thể bị mã độc cùng origin hoặc trình
duyệt bị xâm nhập dùng để giải mã. Bản sao mã hóa cũng không làm mật khẩu dễ
đoán trở nên an toàn; chọn mật khẩu sao lưu dài, riêng biệt. Công cụ không
thay thế giao thức chat E2EE Olm/MLS.

### Mã hóa và giải mã tệp nhị phân

Ở phần **4 · Mã hóa & giải mã tệp**, chọn một tệp gốc tối đa **5 MiB
(5.242.880 byte)**. Tên và kích thước được hiển thị trước thao tác, chưa phải
kết quả xác minh. Nhập ngữ cảnh công khai nếu cần, xác nhận public key người
nhận ở phần 2 rồi bấm **Mã hóa & tải tệp .scapenc**. Mỗi lần mã hóa sinh khóa
AES 256 bit và nonce 96 bit mới, dùng GCM với thẻ xác thực 128 bit. Cấu hình
được hiển thị cố định; GCM không dùng padding. Khóa AES không được đưa vào
ô văn bản hoặc xuất riêng; nó được bọc bằng RSA-OAEP 3072/SHA-256 của người nhận.

Tệp được đọc dưới dạng byte, không chuyển qua UTF-8 và không dùng thành phần
upload của Gradio. Không có API upload, kho tệp hoặc bước gửi AI trong luồng
này. Tên gốc, kích thước gốc và SHA-256 nội dung nằm trong phần mã hóa; ngữ
cảnh AAD, fingerprint người nhận và định dạng gói là thông tin công khai.
Độ dài gói vẫn cho biết xấp xỉ dung lượng tệp, không có cơ chế che giấu lưu lượng.
Gói có overhead, giới hạn tối đa **5.246.380 byte**; định dạng này chỉ đọc
gói `.scapenc` phiên bản 1 của SCAP, không nhập tệp AES/ECB/PKCS5 từ công cụ khác.

Để giải mã, mở khóa riêng ở phần 1, chọn gói `.scapenc` rồi bấm **Giải mã &
tải tệp .bin**. Công cụ kiểm tra định dạng, toàn vẹn, độ dài và SHA-256 trước
khi tải bất kỳ kết quả nào. Sai khóa, gói bị sửa/cắt ngắn, sai phiên bản hoặc
quá giới hạn đều bị từ chối. Không có bản rõ tải xuống khi xác minh thất bại.
Ngữ cảnh được đọc từ gói đã xác thực, không lấy từ ô ngữ cảnh mã hóa hiện tại.

Kết quả dùng tên cố định **scap-restored.bin** và kiểu
`application/octet-stream`, không tự mở hoặc xem trước. Đối chiếu tên gốc và
SHA-256 hiển thị, chỉ đổi tên/mở tệp nếu tin cậy nguồn gửi. Kiểm tra toàn vẹn
không xác thực người gửi hoặc chứng minh tệp không chứa mã độc. Các bản tải
xuống nằm ngoài trạng thái tab và không bị xóa bởi nút khóa/đăng xuất; tự quản
lý các bản rõ đã tải. Buffer tạm được ghi đè theo khả năng của JavaScript,
không bảo đảm xóa mọi bản sao trong bộ nhớ trình duyệt.
