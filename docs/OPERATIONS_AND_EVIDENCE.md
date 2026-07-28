# Vận hành và bộ minh chứng nộp đồ án

Tài liệu này chốt các kiểm soát bổ sung sau khi hoàn thiện dự án theo đề xuất trong PDF. Chỉ chạy pentest hoặc DAST trên local lab/staging do nhóm sở hữu hoặc được cấp quyền.

## Các luồng bảo mật đã hoàn thiện

| Luồng | Kiểm soát | Minh chứng |
|---|---|---|
| Đổi mật khẩu | Xác nhận mật khẩu hiện tại, Argon2id rehash, tăng `token_version` để vô hiệu mọi JWT cũ | `test_password_change_invalidates_existing_tokens_and_logout_revokes_token` |
| Đăng xuất | `jti` được ghi vào bảng `revoked_tokens`; các request tiếp theo bị từ chối | Cùng test ở trên |
| Khóa/mở khóa | Chỉ admin được gọi endpoint quản trị; khóa tài khoản tăng `token_version` để thu hồi token hiện có | `test_admin_can_lock_account_and_view_security_alerts` |
| Cảnh báo | Admin xem các burst login failure, authorization denied và rate-limit block từ audit trail theo cửa sổ thời gian/ngưỡng | `GET /api/admin/security-alerts` |
| Tìm kiếm chat | Chỉ giải mã sau owner/RBAC check; tìm trong một phiên được phép, không tạo chỉ mục plaintext toàn cục | `test_authorized_message_search_decrypts_only_owned_session` |

## API quản trị mới

| Endpoint | Quyền | Mục đích |
|---|---|---|
| `POST /api/auth/logout` | User đã đăng nhập | Thu hồi JWT hiện tại. |
| `PATCH /api/auth/password` | User đã đăng nhập | Đổi mật khẩu và thu hồi các JWT cũ. |
| `GET /api/admin/users` | Admin | Danh sách tối đa 500 người dùng. |
| `PATCH /api/admin/users/{user_id}/status` | Admin | Khóa/mở khóa tài khoản. Admin không thể tự khóa mình. |
| `GET /api/admin/security-alerts` | Admin | Tổng hợp dấu hiệu bất thường từ audit log; nhận `window_minutes` và `threshold`. |

## Quy trình tạo evidence bundle

```bash
uv sync --group dev
uv run pytest --cov=src.app --cov-report=term-missing --cov-report=xml | Tee-Object reports/pytest.txt
uvx semgrep scan --config auto --json --output reports/semgrep.json src/app
uv run bandit -r src/app -f json -o reports/bandit.json
uv run pip-audit -f json -o reports/pip-audit.json
```

Khi Docker/staging đã chạy, bổ sung Trivy và ZAP theo `docs/PENTEST_PLAN.md`. Không commit database, token, API key, ciphertext mẫu của người dùng thật hoặc bất kỳ report có dữ liệu nhạy cảm.

## Tiêu chí release của nhóm

- Toàn bộ pytest pass; coverage tổng thể tối thiểu 70% và module `src/app/security.py` tối thiểu 90%.
- Không còn finding Critical; finding High phải có bản vá hoặc risk acceptance có người chịu trách nhiệm.
- Thực hiện lại PT-01 đến PT-16 sau mỗi thay đổi auth, crypto, middleware hoặc schema.
- Đưa ảnh/screenshot IDOR bị chặn, rate-limit, audit alert và ciphertext AES-GCM vào phụ lục báo cáo.
