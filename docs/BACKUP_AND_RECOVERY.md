# Backup và khôi phục dữ liệu

Bản đánh giá bảo mật nêu backup/restore là khoảng trống lớn nhất về vận hành. Tài
liệu này định nghĩa chính sách tối thiểu cần có trước khi đưa hệ thống ra môi trường
xử lý dữ liệu thật.

## Mục tiêu (RPO/RTO)

| Chỉ tiêu | Mục tiêu |
| --- | --- |
| RPO (mất dữ liệu tối đa) | ≤ 24 giờ (khuyến nghị ≤ 1 giờ nếu có WAL/PITR) |
| RTO (thời gian khôi phục) | ≤ 4 giờ cho môi trường demo/pilot |
| Chu kỳ kiểm thử restore | Hằng quý, có biên bản |

## Phạm vi sao lưu

- **PostgreSQL**: toàn bộ schema (`users`, `auth_sessions`, `revoked_tokens`,
  `chat_sessions`, `secure_messages`, `audit_events`, `mfa_recovery_codes`).
- **Bí mật/khóa**: KHÔNG sao lưu chung với dữ liệu ứng dụng. `MASTER_ENCRYPTION_KEY`
  và khóa ký JWT do KMS/Vault quản lý và có quy trình khôi phục riêng. Mất master key
  đồng nghĩa mất khả năng giải mã message — đây là rủi ro then chốt cần diễn tập.
- **Cấu hình triển khai**: `docker-compose.yml`, `Caddyfile`, biến môi trường (trừ
  secret) lưu trong kho cấu hình có version.

## Nguyên tắc

- **Mã hóa khi lưu trữ**: mọi bản sao lưu được mã hóa (ví dụ AES-256) trước khi rời máy chủ.
- **Off-site + immutable**: giữ ít nhất một bản ở vị trí tách biệt, bật object-lock/immutable
  để chống ransomware và thao tác xóa của kẻ tấn công.
- **Tách khóa khỏi dữ liệu**: bản sao lưu DB và khóa giải mã không nằm cùng một nơi lưu trữ
  hay cùng một tài khoản IAM.
- **Least-privilege**: tài khoản chạy backup chỉ có quyền đọc DB và ghi vào kho backup.

## Ví dụ sao lưu PostgreSQL

```bash
# Dump nén, sau đó mã hóa bằng khóa backup tách biệt (không phải master key ứng dụng)
pg_dump --format=custom "$DATABASE_URL" \
  | gpg --encrypt --recipient backup@secure-chat > backup-$(date +%F).dump.gpg
```

## Kiểm thử khôi phục (bắt buộc hằng quý)

1. Khôi phục bản mã hóa vào một instance cô lập.
2. Chạy migration khởi động (`Database.create_all`) và xác minh ứng dụng khởi động.
3. Đăng nhập thử, giải mã một message cũ để xác nhận master key + dữ liệu khớp.
4. Ghi lại thời gian khôi phục thực tế và so với RTO; lưu biên bản làm bằng chứng.

Một bản backup chưa từng được restore thử thì coi như **chưa tồn tại**.
