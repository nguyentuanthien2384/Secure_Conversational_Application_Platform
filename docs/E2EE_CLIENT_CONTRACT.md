# Hợp đồng client Private E2EE

Đây là ranh giới bắt buộc giữa client mật mã và máy chủ SCAP. Module server
`src/app/e2ee.py` chỉ canonicalize/validate public proof và opaque envelope. Nó
không triển khai Double Ratchet, MLS, X3DH, sinh khóa riêng, mã hóa hay giải mã.

Client terminal 1:1 đã triển khai tại `clients/e2ee_client.py` và
`clients/private_chat.py`, dùng Olm của `vodozemac==0.10.0`. Chạy thử hai client
qua HTTP thật bằng `uv run --frozen --extra e2ee-client python -m scripts.demo_e2ee --check`.
Kho client dùng AES-GCM/Scrypt, khóa liên tiến trình, ghi nguyên tử, outbox
bền vững và cursor lưu cùng ratchet. Bearer và mật khẩu SCAP không lưu vào kho.
Đây là tích hợp tham chiếu của SCAP, chưa phải kết quả kiểm toán độc lập.

## Yêu cầu client

Client phải dùng thư viện đã được kiểm toán, còn được duy trì, cho Signal-style
Double Ratchet (1:1) hoặc RFC 9420 MLS (nhóm). Khóa riêng identity, prekey secret,
message key, skipped-key cache, ratchet state và MLS tree state chỉ nằm trong
secure storage của thiết bị. Không gửi chúng vào API, log, crash report,
analytics, clipboard hoặc backup không E2EE.

Client phải pin protocol/version, chống downgrade, xóa message key sau sử dụng,
giới hạn skipped keys, xử lý out-of-order/replay theo thư viện, cảnh báo identity
key thay đổi và yêu cầu người dùng xác minh safety fingerprint lại. Web UI
Gradio hiện tại không phải E2EE client và không được gắn nhãn Private E2EE.

## Đăng ký thiết bị

1. Đăng nhập và gọi `POST /api/e2ee/devices/challenge` sau step-up.
2. Client sinh UUID thiết bị canonical, Ed25519 identity keypair và protocol
   prekeys cục bộ.
3. Identity key ký statement trả bởi
   `build_device_possession_message(account_id, device_id, identity_key,
   challenge)`. Identity key cũng ký raw 32-byte signed prekey.
4. Gửi public material, chữ ký, challenge ID + challenge và tối đa 100 one-time
   public prekeys tới `POST /api/e2ee/devices`.
5. Thiết bị đầu tiên được tin cậy sau password/MFA step-up. Thiết bị tiếp theo
   phải có chữ ký phê duyệt từ một thiết bị đang trusted, tạo bằng
   `build_device_approval_message`. Challenge hết hạn sau 5 phút, lưu dạng hash
   và bị tiêu thụ đúng một lần kể cả proof sai.

Server chỉ trả fingerprint, trạng thái trust và public bundle. Thu hồi thiết bị
qua `DELETE /api/e2ee/devices/{device_id}` cần step-up và làm tăng routing epoch
của các nhóm liên quan; client phải phát MLS remove/commit tương ứng.

### Bổ sung prekey và xoay signed prekey

`POST /api/e2ee/devices/{device_id}/prekeys` cần step-up, challenge mới và chữ
ký identity. Payload gồm `challenge_id`, `challenge`, `one_time_prekeys`,
`signed_prekey`, `signed_prekey_signature`, `update_signature`; hai trường
signed prekey cùng có hoặc cùng vắng mặt. Ký canonical JSON schema
`scap.e2ee.prekey-update` của `{account_id, device_id, challenge,
one_time_prekeys, signed_prekey, signed_prekey_signature}`; trường tùy chọn
vắng mặt được ký dưới dạng `null`. Dùng `canonical_json_bytes` trong
`src/app/e2ee.py` như `PrivateClient.refill` để tạo đúng dữ liệu ký.

Server giữ tối đa 100 prekey chưa dùng và 10.000 public prekey đã từng tải
lên mỗi thiết bị, cấm tái tải key đã tiêu thụ. Thay đổi key, tiêu thụ challenge
và audit bắt buộc cùng transaction. Client phải lưu private prekey trước khi
gửi public key; lệnh `refill` trong client tham chiếu thực hiện việc này.
Nếu server đã nhận key nhưng phản hồi bị mất, client giữ batch đang chờ trên
đĩa và dùng challenge mới để thử lại; chỉ phản hồi chính xác về key đã đăng
ký của batch đã gửi mới được coi là xác nhận. Không tái kích hoạt prekey đã
tiêu thụ và không coi lỗi quota, challenge hay lỗi khác là thành công.

## Thiết lập 1:1

Caller lấy bundle qua
`GET /api/e2ee/users/{username}/prekey-bundle?device_id=...`. One-time prekey được
đánh dấu consumed trong transaction; khi cạn, response vẫn có identity key và
signed prekey nhưng client nên cảnh báo giảm forward secrecy và chờ bổ sung
prekey. Luôn xác minh chữ ký signed prekey và fingerprint trước khi tạo session.

Mỗi thiết bị nhận cần một envelope Double Ratchet riêng:

```json
{
  "version": 1,
  "protocol": "double-ratchet",
  "recipient": "<recipient-device-uuid>",
  "recipient_device_id": "<recipient-device-uuid>",
  "epoch": 2,
  "client_message_id": "<idempotency-id>",
  "sender_device_id": "<sender-device-uuid>",
  "message_kind": "application",
  "header": "<base64url opaque ratchet header>",
  "ciphertext": "<base64url authenticated ciphertext>"
}
```

## Nhóm MLS

Owner tạo session `security_mode=private_e2ee`; owner là member epoch 1. Thêm/xóa
member qua API làm tăng epoch. Client owner/committer phải tạo và phân phối MLS
commit/welcome bằng thư viện RFC 9420; server không tự tạo group secret.

- `application`/`commit`: `recipient` bằng session UUID, không có
  `recipient_device_id`.
- `welcome`: `recipient` và `recipient_device_id` bằng UUID thiết bị đích.
- `epoch` phải bằng `current_crypto_epoch`; member đã bị xóa hoặc device revoked
  không thể gửi/nhận epoch mới.

Gửi qua `POST /api/sessions/{id}/e2ee/envelopes`; nhận qua
`GET /api/sessions/{id}/e2ee/envelopes?recipient_device_id=...`. Server giới hạn
header 16 KiB, ciphertext 1 MiB, số envelope mỗi session và unique replay key
trên sender + recipient + client message ID. Client vẫn phải xác thực ciphertext
và replay theo protocol; server-side guard chỉ là defense in depth.

Phân trang nhận dùng `after=<created_at>&after_id=<envelope-uuid>` từ bản ghi
cuối đã xác thực và lưu thành công, với thứ tự `(created_at, id)`. Chỉ dùng
thời điểm có thể trùng và bị từ chối với 409 ở ranh giới không duy nhất;
`after_id` không có `after` bị từ chối với 422. API
`GET /api/sessions/{id}/e2ee/state` cho active member đọc session ID, epoch và
owner để gửi đúng routing state, không mở quyền đọc plaintext.

## Điều cấm ở API

Payload có trường lạ bị từ chối; đặc biệt không có trường plaintext, private
key, chain key, root key, message key, recovery seed hoặc MLS secret. API
plaintext `/messages`, search và AI không hoạt động với Private E2EE. Export của
phiên E2EE chỉ chứa opaque ciphertext.

Safety fingerprint được tính ổn định từ public identity keys bằng
`safety_fingerprint`; hiển thị toàn bộ digest cho hai bên so sánh qua kênh khác.
Thay key/protocol phải làm fingerprint thay đổi và hiện cảnh báo, không tự động
tin cậy.

## Cổng phát hành client

Phải có known-answer/interoperability vectors, test mất gói/out-of-order,
skipped-key bounds, replay, identity change, multi-device fanout, add/remove MLS,
concurrent commit, backup/restore secure storage và memory/log inspection. Cần
review mật mã độc lập/pentest trước khi tuyên bố E2EE production. Repository
cung cấp server boundary, client Olm 1:1, client nhóm OpenMLS và test gửi/nhận,
tamper/replay, durable outbox, mất kết nối, khóa kho, prekey và loại thành viên
khỏi epoch mới. Client MLS hiện hỗ trợ nhóm do owner quản lý, một thiết bị mỗi
tài khoản; các bên pin fingerprint và trao đổi KeyPackage public có chữ ký.
Welcome được kiểm tra danh tính người tạo bằng giao thức MLS, không chỉ dựa
vào nhãn relay. Xem [native MLS client](../clients/mls_native/README.md) và
[demo nhóm](SECURITY_EXTENSIONS.md#demo-nhóm-mls). Chưa có bộ vector liên thông
với ứng dụng bên ngoài hoặc kiểm toán độc lập cho tích hợp SCAP.

