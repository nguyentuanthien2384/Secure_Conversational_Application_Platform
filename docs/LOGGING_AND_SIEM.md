# Logging tập trung và SIEM

Ứng dụng đã ghi audit vào bảng `audit_events` với `request_id` tương quan. Tài liệu
này mô tả cách nâng từ "có log" lên "giám sát vận hành được", theo khuyến nghị của bản
đánh giá và hướng dẫn SIEM/SOAR của CISA.

## Lớp nguồn log cần thu thập

- **Ứng dụng**: các sự kiện audit (`auth.*`, `authorization.denied`, `admin.*`,
  `privacy.ai_consent`, `auth.mfa.*`), kèm `request_id`, IP, user agent.
- **Reverse proxy (Caddy)**: access log, mã trạng thái, thời gian phản hồi.
- **CSDL**: lỗi kết nối, truy vấn chậm, thay đổi quyền.
- **Hạ tầng/CI**: kết quả scan, sự kiện triển khai.

## Lớp sự kiện phải cảnh báo (alert)

| Sự kiện | Điều kiện gợi ý |
| --- | --- |
| Lạm dụng đăng nhập | nhiều `auth.login` outcome `failure`/`blocked` theo IP hoặc user |
| Từ chối phân quyền | `authorization.denied` tăng đột biến từ một tài khoản |
| Thay đổi nhạy cảm | `auth.mfa.disabled`, đổi vai trò, đổi trạng thái tài khoản |
| Bất thường phiên | phát hành/thu hồi phiên bất thường, đăng nhập từ vị trí lạ |
| Lỗi nhà cung cấp AI | tăng lỗi egress hoặc từ chối do thiếu consent |

## Đường ống gợi ý

```
App/Caddy/DB logs → collector (Fluent Bit/Vector) → SIEM (Elastic Security / Microsoft Sentinel)
                                                  → alert routing (email/Slack/on-call)
```

- **Định dạng**: xuất log dạng JSON có cấu trúc để SIEM parse; giữ nguyên `request_id`
  để truy vết xuyên lớp.
- **Chống giả mạo**: chuyển log ra ngoài host càng sớm càng tốt; hạn chế quyền xóa/sửa
  bảng `audit_events`; cân nhắc ký hoặc ghi append-only ở phía SIEM.
- **Retention**: định nghĩa thời hạn lưu (ví dụ 90 ngày nóng, 1 năm lạnh) phù hợp
  nghĩa vụ tuân thủ và Nghị định 13.

## Kiểm chứng phát hiện (purple-team)

Định kỳ tạo tấn công mô phỏng và xác nhận cảnh báo thực sự kích hoạt: login spraying,
thử phân quyền chéo (BOLA/BFLA), bật/tắt MFA, và revoke phiên. Một control phát hiện
chưa được thử kích hoạt thì chưa thể coi là hoạt động.
