# Đề cương báo cáo đồ án

## Chương 1. Tổng quan

- Lý do chọn đề tài.
- Mục tiêu và phạm vi.
- So sánh dự án gốc với phiên bản phát triển.
- Phương pháp: secure SDLC, threat modeling, attack–defense testing.

## Chương 2. Cơ sở lý thuyết

- Authentication và authorization.
- Password hashing/Argon2id.
- Xác thực hai lớp TOTP (HOTP RFC 4226, TOTP RFC 6238).
- Authenticated encryption/AES-GCM.
- OWASP Top 10, ASVS, WSTG.
- Security logging và incident response.

## Chương 3. Phân tích và thiết kế

- Use case và yêu cầu bảo mật.
- DFD, trust boundaries.
- STRIDE và risk register.
- Kiến trúc FastAPI–database–AI provider.
- Mô hình dữ liệu và quyết định kỹ thuật.

## Chương 4. Cài đặt

- User/Auth/JWT.
- MFA/TOTP: enroll, activate, đăng nhập hai bước, recovery code, chống replay.
- RBAC và ownership authorization.
- Crypto service và key handling.
- Chat/AI service.
- Audit, middleware, security headers, validation.
- Docker/PostgreSQL/CI.

## Chương 5. Kiểm thử và đánh giá

- Unit, integration, security regression tests.
- Kết quả coverage.
- Bandit/pip-audit/Gitleaks/Trivy/ZAP.
- PoC IDOR, brute force, XSS, ciphertext tampering.
- Bảng finding và remediation.

## Chương 6. Kết luận

- Kết quả đạt được.
- Đóng góp học thuật/thực hành.
- Giới hạn không che giấu.
- Hướng phát triển: Redis, KMS, refresh token, SIEM, authenticated DAST.
