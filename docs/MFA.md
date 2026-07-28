# Xác thực hai lớp (MFA/TOTP)

Tính năng bổ sung một yếu tố "cái bạn có" (thiết bị chạy authenticator app) bên
cạnh "cái bạn biết" (mật khẩu), giảm rủi ro chiếm tài khoản khi mật khẩu bị lộ.

## Thuật toán

TOTP theo **RFC 6238** trên nền **HOTP (RFC 4226)**, cài trực tiếp bằng thư viện
chuẩn trong `src/app/security.py::TotpService` (HMAC-SHA1 trên bộ đếm 8 byte →
dynamic truncation → modulo `10**digits`). Tham số mặc định: 6 chữ số, chu kỳ 30s.
Cài từ đầu để báo cáo giải thích được cơ chế thay vì phụ thuộc thư viện đóng hộp.

## Luồng nghiệp vụ

1. **Enroll** — `POST /api/auth/mfa/enroll` (đã đăng nhập): sinh secret base32, trả
   về `secret` và `otpauth://` provisioning URI để quét QR hoặc nhập tay. MFA vẫn ở
   trạng thái *pending* (`mfa_enabled = false`).
2. **Activate** — `POST /api/auth/mfa/activate` với một mã TOTP hợp lệ: bật MFA, phát
   sinh 10 mã khôi phục dùng một lần (trả về đúng một lần), và thu hồi mọi phiên cũ.
3. **Đăng nhập hai bước** — `POST /api/auth/login` khi đúng mật khẩu và MFA bật sẽ
   trả `{"mfa_required": true, "mfa_token": ...}` thay vì access token. Client gọi
   tiếp `POST /api/auth/mfa/verify` với `mfa_token` và mã TOTP (hoặc mã khôi phục) để
   nhận access token thật kèm bản ghi `AuthSession`.
4. **Disable** — `POST /api/auth/mfa/disable` yêu cầu cả mật khẩu và mã hợp lệ; xóa
   secret, xóa mã khôi phục và thu hồi mọi phiên.

## Quyết định bảo mật

- **Seed mã hóa tại chỗ.** Secret TOTP không lưu plaintext; nó được mã hóa AES-256-GCM
  với AAD gắn `mfa:{user_id}` (`CryptoService.encrypt_secret`). Rò rỉ database đơn
  thuần không đủ để tái tạo mã, và ciphertext không thể "dán" sang người dùng khác.
- **Mã khôi phục chỉ lưu hash.** Băm Argon2id giống mật khẩu, đánh dấu `used_at` để
  đảm bảo dùng một lần.
- **Chống replay.** Server lưu `mfa_last_counter`; một mã đã chấp nhận trong một bước
  thời gian không thể dùng lại (kể cả khi bị nghe lén trong ~30s).
- **Cách ly phạm vi token.** `mfa_token` mang audience `secure-chat-mfa` khác với
  audience `secure-chat-api` của access token, nên nó không ủy quyền được bất kỳ API
  nào và ngược lại.
- **Chống dò và lạm dụng.** `/mfa/verify` bị rate-limit theo người dùng
  (`MFA_MAX_ATTEMPTS`/`MFA_WINDOW_SECONDS`); mọi bước enroll/activate/verify/disable
  đều ghi audit.

## Cấu hình (.env)

| Biến | Mặc định | Ý nghĩa |
| --- | --- | --- |
| `MFA_ISSUER` | `Secure Chat Course` | Tên hiển thị trong authenticator app |
| `MFA_CHALLENGE_MINUTES` | `5` | Thời hạn `mfa_token` |
| `MFA_RECOVERY_CODES` | `10` | Số mã khôi phục sinh khi bật |
| `MFA_WINDOW_SECONDS` | `300` | Cửa sổ rate-limit cho `/mfa/verify` |
| `MFA_MAX_ATTEMPTS` | `5` | Số lần thử tối đa trong cửa sổ |

## Kiểm thử

`tests/test_mfa.py` phủ: enroll→activate, đăng nhập hai bước, mã sai bị từ chối,
chống replay mã TOTP, mã khôi phục dùng một lần, disable cần mật khẩu + mã, và
challenge token không truy cập được API.
