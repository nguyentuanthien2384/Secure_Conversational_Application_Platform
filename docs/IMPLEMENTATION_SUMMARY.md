# Implementation Summary

## Kết quả

Dự án gốc đã được mở rộng thành hai tuyến:

1. **Secure application**: FastAPI, multi-user, RBAC, AES-GCM, audit, tests, Docker/CI.
2. **Legacy insecure lab**: Streamlit + Vigenère Autokey để trình diễn lý do không dùng custom crypto trong luồng chính.

## Module mới

- `src/app/config.py`: cấu hình, production guards và secret handling.
- `src/app/db.py`, `models.py`: SQLAlchemy, SQLite/PostgreSQL.
- `src/app/security.py`: Argon2id, JWT, AES-GCM, rate limiter.
- `src/app/services.py`: chat/AI/crypto service layer.
- `src/app/audit.py`: structured audit events.
- `src/app/main.py`: API, AuthN/AuthZ, middleware, error handling.
- `src/app/templates/index.html`: web demo không dùng `innerHTML` cho user content.

## Security evidence

- AES-GCM round-trip và tamper detection.
- AAD chặn copy ciphertext giữa các session.
- IDOR test giữa hai tài khoản.
- Generic authentication error.
- Brute-force rate limiting.
- Admin RBAC/audit access.
- Security header, invalid token và request body limit tests.

Kết quả cuối được lưu tại `reports/pytest-coverage.txt`.

## Những phần cần làm thêm nếu triển khai thật

- Redis/distributed rate limiting.
- Refresh token rotation và revocation store.
- KMS/Vault + envelope encryption + key rotation migration.
- Reverse proxy TLS, centralized logging/SIEM.
- PostgreSQL least-privilege accounts, backup/restore drills.
- DAST/authenticated ZAP scan và manual WSTG evidence.
