# Threat Model — DFD + STRIDE

## Tài sản cần bảo vệ

- Mật khẩu và thông tin xác thực.
- JWT access token.
- Nội dung hội thoại.
- Gemini API key và master encryption key.
- Quyền admin và audit trail.
- Tính sẵn sàng của login/chat endpoint.

## Tác nhân

- Người dùng hợp lệ.
- Admin.
- Kẻ tấn công chưa đăng nhập.
- Người dùng hợp lệ cố truy cập dữ liệu người khác.
- Dependency/CI bị xâm nhập.
- Nhà cung cấp AI bên ngoài.

## STRIDE

| ID | Nhóm | Tình huống | Control đã triển khai | Test/minh chứng |
|---|---|---|---|---|
| S-01 | Spoofing | Brute-force tài khoản | Argon2id, generic error, rate limit | `test_generic_login_error_and_rate_limit` |
| S-02 | Spoofing | JWT giả/hết hạn | HS256, issuer/audience, exp/nbf/jti | API trả 401 |
| T-01 | Tampering | Sửa ciphertext/nonce | AES-GCM authentication tag | `test_aes_gcm_roundtrip_and_tamper_detection` |
| T-02 | Tampering | Chép ciphertext sang session khác | AAD ràng buộc session/role/version | `test_aad_prevents_ciphertext_copy_to_another_session` |
| R-01 | Repudiation | Phủ nhận hành vi login/xóa phiên | Structured audit + request ID | `/api/admin/audit` |
| I-01 | Information Disclosure | IDOR xem chat người khác | Ownership check, 404 giảm enumeration | `test_idor_is_blocked...` |
| I-02 | Information Disclosure | Stack trace/secret lộ qua lỗi | Generic 500 handler, không trả exception text | Manual test |
| I-03 | Information Disclosure | API key trong client/repo | Env secret, Gitleaks workflow | CI |
| D-01 | Denial of Service | Flood login/chat | Sliding-window limiter, body limit | 429 + Retry-After |
| E-01 | Elevation of Privilege | User gọi admin audit | Role dependency | `test_normal_user_cannot...` |
| E-02 | Elevation of Privilege | Sửa owner/session ID | Resource-level authorization | IDOR test |

## OWASP-oriented mapping

| Nhóm rủi ro | Phần dự án |
|---|---|
| Broken Access Control | Owner check, admin role, 404 cho resource không thuộc quyền |
| Security Misconfiguration | `.env.example`, production secret checks, security headers, CORS allowlist |
| Software Supply Chain | `pip-audit`, Dependabot/CI, Trivy, Gitleaks |
| Cryptographic Failures | Argon2id, AES-256-GCM, key ngoài DB/repo |
| Injection | Pydantic validation, ORM parameterization, safe DOM `textContent` |
| Insecure Design | DFD, trust boundaries, STRIDE, legacy-vs-secure comparison |
| Authentication Failures | Generic errors, rate limit, short-lived token |
| Integrity Failures | AES-GCM tags; image/dependency scan trong CI |
| Logging & Alerting Failures | Audit events cho auth/authz/admin/chat |
| Exceptional Conditions | Generic error response + request ID |

## Rủi ro còn lại

- In-memory limiter mất trạng thái khi restart và không chia sẻ giữa nhiều instance.
- JWT đã có thu hồi phía máy chủ: mỗi token có bản ghi `AuthSession`, kèm `RevokedToken` denylist và `token_version`; logout, logout-all, đổi mật khẩu/vai trò/trạng thái và bật/tắt MFA đều thu hồi phiên. Rủi ro còn lại là cửa sổ tối đa bằng thời hạn token nếu chỉ dựa vào `exp`.
- Một master key mã hóa mọi message; cần envelope encryption/KMS nếu triển khai thật.
- Metadata DB vẫn lộ số lượng, thời gian, chủ sở hữu và kích thước xấp xỉ bản mã.
- Nội dung plaintext phải tồn tại trong RAM để gửi AI; đây là giới hạn của mô hình tích hợp provider.
