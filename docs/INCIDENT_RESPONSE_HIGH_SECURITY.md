# Runbook sự cố bảo mật cao

## Nguyên tắc chung

Không xóa log hoặc tự “sửa” chuỗi audit đang gãy. Cô lập workload, bảo toàn
snapshot/log WORM, ghi thời gian UTC và người phê duyệt. Mọi secret mới phải cấp
qua kênh khác với kênh nghi bị xâm nhập. Khôi phục dịch vụ chỉ sau khi bằng chứng
cho thấy nguyên nhân đã được chặn.

## Nghi lộ token/JWT

Thu hồi auth session hoặc `logout-all`, tăng `token_version` qua quy trình quản
trị, xoay `APP_SECRET_KEY` nếu khóa ký có thể lộ và buộc đăng nhập lại toàn bộ.
Kiểm tra audit/SIEM cho IP, user-agent, export ticket, thay role, tắt MFA, đăng ký
device và truy cập prekey bất thường. Export ticket hết hạn tối đa 60 giây,
single-use và mất hiệu lực ngay khi phiên đăng nhập cha/tài khoản bị thu hồi;
nhưng vẫn coi dữ liệu đã tải thành công là có khả năng lộ.

## Nghi lộ thiết bị E2EE

Từ thiết bị còn tin cậy, thu hồi device; không thu hồi thiết bị cuối cùng nếu
chưa hoàn tất account-recovery được phê duyệt. Với nhóm MLS, phát remove commit,
tăng epoch và xác minh mọi thành viên nhận state mới. Với 1:1, tạo session/ratchet
mới, cảnh báo safety fingerprint đổi. Thu hồi server metadata không thể xóa
plaintext đã từng giải mã trên thiết bị bị chiếm.

## Nghi lộ DEK/KEK hoặc Vault/KMS identity

Cô lập workload identity, chặn grant và lấy audit log nhà cung cấp. Lộ KEK nhưng
không lộ wrapped DEK/database vẫn là sự cố; xoay KEK và chạy rewrap. Nếu attacker
có cả KEK và wrapped DEK, giả định mọi ciphertext trong phạm vi đã lộ: tạo DEK
mới, tái mã hóa theo kế hoạch được review, thông báo pháp lý phù hợp và không chỉ
rewrap. Kiểm thử restore trước khi hủy key version cũ.

## DLP/AI egress sai chính sách

Tắt connector/provider hoặc egress network, giữ request ID và category audit
không chứa nội dung. Thu hồi consent version bằng cách tăng
`AI_CONSENT_VERSION`; đánh giá log vendor theo DPA/retention, thông báo người dùng
và cơ quan liên quan khi cần. Không chép prompt nhạy cảm vào ticket/SIEM.

## Chuỗi audit/checkpoint gãy

So sánh `last_event_id`, root hash và timestamp với WORM receiver độc lập. Nếu
local chain gãy nhưng WORM còn, lấy WORM làm bằng chứng chuẩn. Nếu checkpoint
ngừng đến, kiểm tra network/credential nhưng coi đây là sự cố giám sát cho tới
khi loại trừ phá hoại. `repair_audit_chain.py` chỉ dành cho tail legacy chưa seal;
không dùng để băm lại lịch sử đã seal.

## Kết thúc sự cố

Ghi root cause, phạm vi dữ liệu, timeline, chỉ dấu xâm nhập, quyết định thông báo,
khóa/token đã xoay, test hồi quy và chủ sở hữu action item. Chạy lại CI/security
scan, restore drill, audit verification và pentest có mục tiêu trước khi mở lại
high-security traffic.
