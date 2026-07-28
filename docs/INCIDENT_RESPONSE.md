# Mini Incident Response Playbook

## Sự cố mẫu: nghi lộ JWT hoặc brute-force tài khoản

### 1. Phát hiện

Dấu hiệu:

- Nhiều `auth.login` failure/blocked cùng IP hoặc username.
- `authorization.denied` tăng bất thường.
- Token hợp lệ xuất hiện từ IP/user-agent lạ.

### 2. Phân loại

- Mức thấp: vài lần sai mật khẩu thông thường.
- Mức trung bình: rate-limit liên tục, enumeration/IDOR thử nghiệm.
- Mức cao: tài khoản admin bị dùng trái phép hoặc dữ liệu chat bị đọc.

### 3. Cô lập

- Vô hiệu hóa user nghi bị chiếm quyền (`is_active=false`).
- Chặn IP ở reverse proxy/WAF.
- Đổi `APP_SECRET_KEY` khi nghi lộ signing key; việc này vô hiệu hóa toàn bộ JWT hiện hành.
- Đổi `MASTER_ENCRYPTION_KEY` chỉ theo kế hoạch migration; không đổi tùy tiện nếu chưa có quy trình re-encrypt.
- Thu hồi Gemini API key nếu bị lộ.

### 4. Điều tra

- Xuất audit theo request ID, actor, IP, thời gian.
- Kiểm tra CI logs/Gitleaks và lịch sử commit.
- Xác định session/endpoint bị truy cập.
- Không đưa plaintext chat/password/token vào ticket hoặc báo cáo công khai.

### 5. Khắc phục và phục hồi

- Vá nguyên nhân gốc, thêm regression test.
- Rotate secret liên quan.
- Khôi phục dịch vụ, theo dõi audit tăng cường.
- Thông báo người dùng/giảng viên theo phạm vi bài lab.

### 6. Postmortem

Ghi timeline, tác động, nguyên nhân gốc, control thất bại, hành động phòng ngừa, người phụ trách và thời hạn.
