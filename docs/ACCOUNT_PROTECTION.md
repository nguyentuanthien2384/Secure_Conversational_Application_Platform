# Bảo vệ tài khoản theo mô hình của các nhà cung cấp danh tính lớn

Đợt này xuất phát từ một câu hỏi: SCAP đã bảo vệ tài khoản giống các trang lớn
(Google, Microsoft, GitHub) chưa? Khi rà soát, ba lỗ hổng thực tế được tìm thấy
và chứng minh bằng thực nghiệm trước khi sửa; sau đó bổ sung ba tính năng mà các
trang đó đều có.

## 1. Lỗ hổng đã sửa: mọi người dùng giao diện chung một địa chỉ IP

Giao diện Gradio chạy trong cùng tiến trình và gọi REST API qua
`http://127.0.0.1` ([gradio_ui.py](../src/app/gradio_ui.py)). API do đó thấy **mọi**
người dùng web với cùng địa chỉ loopback. Kiểm chứng trên bản trước khi sửa:

| Kịch bản | Kết quả trước khi sửa |
| :--- | :--- |
| Kẻ tấn công đăng nhập sai 5 lần (tên bất kỳ) | Nạn nhân đăng nhập đúng nhận **429** |
| Kẻ tấn công tìm kiếm 3 lần với chuỗi SQLi | IDS chặn `127.0.0.1`: nạn nhân nhận **403** |
| Thiết bị, audit, bộ tương quan bất thường | Chỉ thấy `127.0.0.1` và `python-httpx` |

**Cách sửa** ([audit.py](../src/app/audit.py)): khi xử lý một sự kiện, UI đọc
IP và User-Agent của trình duyệt từ `gradio.context.LocalContext.request`, rồi gửi
kèm bốn header `X-SCAP-UI-Client-*` có chữ ký
`HMAC-SHA256(khóa, "v1" ‖ thời điểm ‖ IP ‖ UA)`. Khóa dẫn xuất từ `APP_SECRET_KEY`
với nhãn riêng (`secure-chat:ui-client-context:v1:`), giống cách dẫn xuất khóa audit,
nên mọi worker có cùng khóa nhưng khóa này khác khóa ký JWT.

API chỉ tin header khi chữ ký đúng, thời điểm lệch không quá 60 giây và IP hợp lệ;
nếu không, API dùng địa chỉ peer như trước. Client bên ngoài không có khóa nên
không thể tự khai IP để né rate limit hay đầu độc audit log. Kết quả xác minh được
lưu cho cả request, nên IDS ở middleware và handler luôn thấy cùng một nguồn.

## 2. Lỗ hổng đã sửa: đăng nhập thành công xóa sạch bộ đếm theo IP

Trước đây mỗi lần đăng nhập thành công gọi `reset()` trên bucket `login:ip:{ip}`.
Kẻ tấn công có một tài khoản hợp lệ xen kẽ một lần đăng nhập của chính mình sau
vài lần đoán, nên thử được **24 mật khẩu từ một IP** trong khi giới hạn là 5
(password spraying). Nay lượt thành công chỉ `refund()` đúng suất của nó
([security.py](../src/app/security.py), có bản Redis dùng `ZPOPMAX`); các lần sai
trước đó vẫn nằm trong cửa sổ.

## 3. Smart lockout (tham khảo Microsoft Entra ID)

Khóa cứng sau N lần sai cho phép người lạ biết tên đăng nhập khóa chủ tài khoản vô
thời hạn với 5 yêu cầu mỗi 15 phút. [Microsoft Entra Smart Lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
phân biệt vị trí quen và lạ. SCAP áp dụng cùng ý tưởng
([account_security.py](../src/app/account_security.py)):

- Địa chỉ **quen** là địa chỉ đã hoàn tất đăng nhập (kể cả bước 2FA) cho đúng tài
  khoản trong `SIGN_IN_HISTORY_DAYS` ngày (mặc định 90). Lịch sử lấy từ audit
  log có chuỗi băm, vì bảng phiên bị dọn khi hết hạn để giảm lưu trữ PII.
- Khóa trong cơ sở dữ liệu chỉ **áp dụng** với nguồn lạ. Nguồn quen có bucket riêng
  `login:account-familiar:{user}:{ip}`, giới hạn 5 lần mỗi `LOGIN_LOCKOUT_SECONDS`.
- Lần sai từ nguồn quen **vẫn được đếm** và vẫn có thể đặt khóa đối với nguồn lạ;
  khóa bền vững qua lần khởi động lại không bị yếu đi.
- Đăng nhập từ nguồn quen không gỡ khóa đang hiệu lực; nếu không, mỗi lần chủ
  tài khoản đăng nhập sẽ trao thêm lượt đoán cho người lạ. Khi không có khóa, nó
  xóa các lần gõ nhầm cũ.
- Khóa của quản trị viên dùng `is_active`, tách biệt với cơ chế này nên không thể
  bị vượt qua bằng nguồn quen.

Giới hạn: người tấn công ở **cùng mạng** với nạn nhân (cùng NAT) được coi là nguồn
quen. Họ vẫn bị bucket riêng và bucket theo IP giới hạn.

## 4. Cảnh báo đăng nhập từ thiết bị mới (tham khảo Google)

Mỗi lần đăng nhập hoàn tất được phân loại trước khi ghi audit của chính nó:
`first_sign_in`, `familiar`, `new_location` (thiết bị quen, IP mới) hoặc
`new_device` (họ trình duyệt/hệ điều hành chưa từng thấy). Phân loại được ghi vào
`details.sign_in_source` của `auth.login`/`auth.mfa.verify`. Riêng `new_device` sinh
thêm sự kiện `auth.login.new_device` vào audit và SIEM.

Thiết bị được rút gọn thành cặp *(trình duyệt, hệ điều hành)*, ví dụ
`Chrome · Windows`, nên cập nhật phiên bản trình duyệt không bị coi là thiết bị
mới. User-Agent có thể giả mạo; muốn ràng buộc thiết bị chắc chắn cần passkey/WebAuthn
hoặc device cookie (xem mục 6).

## 5. Trang "Hoạt động bảo mật" cho người dùng (tham khảo GitHub security log)

`GET /api/auth/security-activity?limit=30` trả nhật ký của **chính người gọi**:

- Đăng nhập thành công/thất bại, kể cả lần **người khác** thử vào tài khoản (kèm IP
  và thiết bị), bật/tắt 2FA, đổi mật khẩu, thu hồi thiết bị, thiết bị E2EE.
- Thao tác của quản trị viên lên tài khoản (đổi vai trò, khóa/mở) được hiển thị
  nhưng **ẩn IP và trình duyệt của quản trị viên**.
- Tóm tắt "kể từ lần đăng nhập trước": thời điểm, IP, thiết bị của lần trước; số lần
  thất bại; số lần **nhập đúng mật khẩu nhưng sai 2FA** (mức `critical`, nghĩa là
  mật khẩu nhiều khả năng đã lộ); số lần đăng nhập từ thiết bị mới.

Tab **Tài khoản** có khối *Hoạt động bảo mật gần đây*; ngay sau khi đăng nhập, UI
hiện cảnh báo nổi nếu có dấu hiệu bất thường. Không cần bảng hay cột mới; dữ liệu
lấy từ `audit_events` hiện có.

## 6. Passkey (WebAuthn / FIDO2)

Passkey là khóa riêng nằm trong thiết bị (Windows Hello, Touch ID, Android, khóa
USB). Trình duyệt ký challenge của máy chủ **kèm origin của trang**, nên passkey tạo
cho trang này không dùng được trên trang giả mạo; đây là điểm mà mật khẩu và mã TOTP
không làm được ([FIDO Alliance](https://fidoalliance.org/passkeys/)). Việc xác minh
CBOR/COSE/chữ ký dùng thư viện `py_webauthn` (Duo Labs); chính sách phía máy chủ
nằm trong [passkeys.py](../src/app/passkeys.py):

- Bắt buộc **xác minh người dùng** (PIN/sinh trắc), vì vậy đăng nhập bằng passkey là
  hai yếu tố và không cần TOTP sau đó.
- Challenge ngẫu nhiên 32 byte, hết hạn sau 3 phút và bị **tiêu thụ trước khi xác
  minh**, nên mỗi lượt chỉ thử được một lần. Passkey đồng bộ đám mây thường báo bộ
  đếm luôn bằng 0, nên với chúng đây là lớp chống replay duy nhất.
- Chỉ chấp nhận origin và RP ID đã cấu hình; RP ID không được là địa chỉ IP, và chỉ
  `localhost` được phép dùng HTTP. Cấu hình sai thì ứng dụng từ chối khởi động.
- Bộ đếm chữ ký đi lùi ⇒ nghi authenticator bị nhân bản: từ chối và ghi audit cho chủ tài khoản.
- Đăng nhập không hỏi tên người dùng (*discoverable credential*), nên không lộ tài
  khoản nào tồn tại. Thêm/xóa passkey cần xác thực lại gần đây và gửi email cảnh báo.
- Chỉ lưu public key, bộ đếm, AAGUID và cờ đồng bộ. Xóa tài khoản sẽ xóa passkey theo.

Trên giao diện, script tĩnh [passkey.js](../src/app/ui_assets/passkey.js) gọi
`navigator.credentials` **ngay trong cú click** của người dùng (Safari bắt buộc điều
này). Khi đăng nhập, script tự lấy options từ API công khai; khi tạo passkey, máy chủ
chuẩn bị options trước, rồi người dùng bấm *Xác nhận trên thiết bị này*. Script không
dùng `eval`, không bao giờ thấy bearer token, và chỉ trả kết quả công khai cho máy chủ.

## 7. Khôi phục mật khẩu qua email và email cảnh báo

- Email khôi phục chỉ được gắn sau khi chủ hộp thư nhập đúng mã. Đổi hoặc gỡ email cần
  xác thực lại và gửi thông báo về **địa chỉ cũ**. Mỗi địa chỉ chỉ gắn với một tài khoản.
- Mã gồm 10 ký tự (khoảng 49 bit) từ bảng chữ không có ký tự dễ nhầm, hiệu lực
  `PASSWORD_RESET_MINUTES`, tối đa 5 lần nhập; mã mới hủy mã cũ. Cơ sở dữ liệu chỉ lưu
  HMAC-SHA256 với khóa dẫn xuất riêng.
- `POST /api/auth/password-reset/request` luôn trả **cùng một phản hồi 202** dù tài khoản
  có tồn tại hay có email hay không. Thư được gửi ở luồng nền nên thời gian phản hồi cũng
  không lộ thông tin.
- Đặt lại thành công thì thu hồi mọi phiên, gỡ khóa đăng nhập, xóa bộ đếm theo tài khoản
  (giữ bộ đếm theo IP) và gửi email thông báo. **2FA vẫn được giữ nguyên**: kẻ chiếm
  được hộp thư vẫn cần mã TOTP hoặc passkey.
- Email cảnh báo được gửi khi có: thiết bị mới, đổi hoặc đặt lại mật khẩu, tắt 2FA, đổi
  email, thêm/xóa passkey, token bị dùng lại. Thư không chứa mật khẩu hay token.
- `MAIL_BACKEND=smtp` dùng TLS bắt buộc (STARTTLS hoặc SSL) và xác minh chứng chỉ;
  `outbox` ghi file `.eml` cho demo (production từ chối); `disabled` khiến các chức năng
  email trả 503.

## 8. Phát hiện dùng lại token đã xoay (RFC 9700 §4.14.2)

Mỗi lần `/api/auth/refresh`, token cũ bị thu hồi. Nếu token cũ đó **quay lại sau
`TOKEN_REUSE_GRACE_SECONDS`** (mặc định 30 giây), máy chủ không biết ai mới là chủ thật,
nên thu hồi cả họ phiên của thiết bị đó. Kẻ trộm mất token, còn người dùng thật chỉ cần
đăng nhập lại. Sự kiện `auth.session.token_reuse` (T1550.001) được ghi vào audit/SIEM, hiện
ở mức *critical* trong trang hoạt động và được gửi email. Các thiết bị khác không bị ảnh
hưởng; token quay lại sau khi đăng xuất không bị báo nhầm.

Giao diện có nhiều tab dùng chung một phiên: khi một tab gia hạn, kho phiên ghi lại
"token kế nhiệm" và mọi lời gọi API của UI tự dùng token mới nhất. Nhờ vậy tab cũ không
bao giờ gửi token đã xoay và không bị nhận nhầm là kẻ trộm.

## 9. Cookie nhận diện thiết bị (OWASP device cookie)

Sau mỗi lần đăng nhập, máy chủ cấp token `v1.<mã thiết bị>.<thời điểm>.<HMAC>`, gắn
với đúng tài khoản. UI lưu token này trong cookie `scap_device` (HttpOnly, SameSite=Strict,
`DEVICE_TOKEN_DAYS`); client API nhận nó trong `device_token` và gửi lại qua header
`X-SCAP-Device`. Cookie chỉ dùng để **nhận diện**, không bao giờ cấp quyền truy cập.

- Smart lockout: trình duyệt có token hợp lệ được coi là quen ngay cả khi đổi mạng.
- Cảnh báo thiết bị mới: khi tài khoản đã dùng cơ chế này, client **không có** token
  hợp lệ là thiết bị mới, dù IP và User-Agent giống hệt chủ tài khoản. Chỉ tài khoản
  chưa có lịch sử token mới so sánh theo họ trình duyệt/hệ điều hành như trước.

## 10. Còn lại so với các trang lớn

| Tính năng | Trạng thái |
| :--- | :--- |
| Passkey làm yếu tố thứ hai và cho bước xác thực lại (step-up) | Chưa có — step-up vẫn dùng mật khẩu + TOTP |
| Thông báo đẩy (push) / SMS | Chưa có — chỉ email và cảnh báo trong ứng dụng |
| Đánh giá rủi ro theo vị trí địa lý (impossible travel) | Chưa có — cần cơ sở dữ liệu GeoIP |
| CSP không `unsafe-inline` | Chưa có — giới hạn của Gradio (README §14) |

## 11. Kiểm chứng

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_account_protection.py tests/test_passkeys.py tests/test_account_recovery.py tests/test_token_reuse_and_devices.py tests/test_account_ui.py
```

- Test passkey dùng [authenticator phần mềm](../tests/webauthn_soft.py) tạo cấu trúc
  WebAuthn thật (khóa P-256, CBOR, chữ ký ECDSA), nên đi qua toàn bộ đường xác minh của
  `py_webauthn` chứ không mock.
- **Kiểm tra đột biến:** gỡ riêng từng biện pháp làm đỏ test tương ứng: refund theo IP,
  xác minh header UI, smart lockout, UV bắt buộc, kiểm tra bộ đếm, challenge một lần,
  phát hiện dùng lại token, lịch sử cookie thiết bị, ràng buộc mã khôi phục với tài khoản,
  phản hồi chống dò tài khoản, thu hồi phiên sau khi đặt lại.
- **Trình duyệt thật:** Chrome headless điều khiển qua DevTools Protocol với bộ xác thực
  WebAuthn ảo đã chạy qua cả giao diện Gradio: tạo tài khoản, đăng nhập, kiểm tra cookie
  thiết bị (HttpOnly, script trang không đọc được), xác minh email khôi phục bằng mã trong
  outbox, tạo passkey, đăng xuất, đăng nhập lại bằng passkey (nhận đúng là trình duyệt
  quen), quên mật khẩu qua email rồi đăng nhập bằng mật khẩu mới, và gợi ý `localhost` khi
  mở bằng IP.
