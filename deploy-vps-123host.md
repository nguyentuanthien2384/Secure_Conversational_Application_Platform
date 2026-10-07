# Triển khai JobFind lên VPS 123HOST bằng Docker

Tổng hợp quá trình chọn phương án, xây dựng bộ triển khai và đưa JobFind lên VPS 123HOST (05–07/10/2026). File không chứa mật khẩu hay khóa bí mật.

Hướng dẫn kỹ thuật đầy đủ, luôn được cập nhật: [deploy/README.md](../deploy/README.md).

## 1. Các quyết định chính

| Câu hỏi | Kết luận | Lý do |
| --- | --- | --- |
| Deploy theo cách thủ công (Node + PM2 + Nginx) hay bằng Docker? | **Docker Compose** | Hệ thống có 17 thành phần: React, backend Express, 9 microservice, MariaDB, PostgreSQL, MongoDB, Elasticsearch, Redis, RabbitMQ, Caddy. Cài tay từng phần trên Linux dễ sai và khó nâng cấp |
| Mua Hosting hay VPS ở 123HOST? | **VPS (Cloud VPS, ảo hóa KVM)** | Hosting (WordPress/Personal/Business) không có quyền root, không cài được Docker |
| Gói VPS nào? | **4GB** (2 vCPU, 4 GB + 2 GB tặng, 40 GB SSD). Khuyến nghị **Cheap-Rocket-4G, 420.000đ/tháng** | Đo thực tế, stack dùng khoảng 2–2,5 GB RAM (Elasticsearch khoảng 1 GB, mỗi microservice khoảng 40 MB). Gói 1–2 GB không đủ. Rocket-4G (550.000đ) có cùng cấu hình, chỉ thêm dịch vụ quản trị |
| Có cần đưa frontend/backend lên Render không? | **Không** | Gói miễn phí của Render tự ngủ sau 15 phút và chỉ có 512 MB RAM. Render không có MongoDB, Elasticsearch, RabbitMQ, MySQL. Tách frontend và backend ra hai domain còn làm hỏng cookie phiên (thiết kế theo một origin) |
| Có bắt buộc tên miền không? | Không bắt buộc, nhưng **cần HTTPS** | Backend production chỉ đặt cookie phiên `Secure`. Chạy HTTP theo IP thì cứ F5 là bị đăng xuất. Tạm dùng `https://61-14-233-122.sslip.io` (sslip.io tự trỏ về IP, có HTTPS miễn phí), sau đổi sang tên miền riêng |
| Tên miền riêng? | `.id.vn` miễn phí 2 năm (công dân 18–23 tuổi, đăng ký ở iNET/Tenten/Nhân Hòa/BKNS), hoặc `.com` khoảng 270.000đ/năm tại 123HOST | Gợi ý: `jobfind.<tên-bạn>.id.vn` |

## 2. Những gì đã thêm vào dự án

Thư mục `deploy/` (bộ triển khai production):

| File | Vai trò |
| --- | --- |
| `docker-compose.yml` | 17 dịch vụ. Chỉ Caddy mở cổng 80/443; mọi kho dữ liệu đều nội bộ |
| `Caddyfile`, `web.Dockerfile` | Build React, phục vụ bằng Caddy, tự xin chứng chỉ HTTPS (Let's Encrypt), chuyển `/api` và `/socket.io` vào API Gateway |
| `backend.Dockerfile` | Image backend Express |
| `.env.example` | Mô tả mọi biến cấu hình. File thật là `deploy/.env`, không commit |
| `scripts/make-env.mjs` (`npm run vps:env`) | Tạo `deploy/.env`: sinh mật khẩu mới, chép khóa AI, email, Cloudinary, PayPal, Auth0 từ `.env` local |
| `scripts/export-local-data.mjs` (`npm run vps:export-data`) | Xuất MySQL (XAMPP), PostgreSQL, MongoDB kèm checksum |
| `scripts/import-data.sh` | Nạp dữ liệu trên VPS. Kiểm tra checksum, từ chối ghi đè CSDL đang có dữ liệu nếu không có `--force` |
| `scripts/backup.sh` | Sao lưu định kỳ, cùng định dạng, khôi phục bằng `import-data.sh` |

Các sửa đổi quan trọng (thiếu thì lên Linux sẽ lỗi):

- **MariaDB cấu hình giống XAMPP**: `lower_case_table_names=1`, múi giờ `+07:00`, `sql_mode` không strict, `utf8mb4_general_ci`. Không có các tùy chọn này, Sequelize gọi `AuthSessions` nhưng bảng thật tên `authsessions`, gây lỗi "table doesn't exist".
- **Profile `production`** trong `backend/src/config/config.json` được bổ sung `query.raw` và `timezone`.
- **Image backend** kèm `frontend/src/data` (danh sách việc làm ngoài mà chatbot dùng).
- `.gitignore` bỏ qua `deploy/.env`, `deploy/data-export/`, `deploy/backups/`. `.gitattributes` giữ LF cho file `.sh`.

Đã kiểm thử toàn bộ stack production trên Docker Desktop trước khi lên VPS. Kết quả:

- 17/17 dịch vụ healthy.
- Đăng nhập admin, cookie `__Host-` và làm mới phiên hoạt động.
- Tìm kiếm tiếng Việt chạy (Elasticsearch tự dựng lại chỉ mục từ MySQL).
- Socket.IO hoạt động.
- `/metrics` không lộ ra ngoài.
- Sao lưu và khôi phục `--force` đúng dữ liệu.

## 3. Thông tin VPS

| Mục | Giá trị |
| --- | --- |
| Nhà cung cấp | 123HOST Cloud VPS |
| Hostname | `vps-nnbpg.cloud.tld` (tên nội bộ, không dùng làm địa chỉ web) |
| Public IPv4 | `61.14.233.122` |
| **Cổng SSH** | **2018** (không phải 22) |
| Hệ điều hành | Ubuntu 22.04 x86_64 **minimal** (thiếu sẵn tmux, ufw…) |
| RAM / Swap | 5,8 GB / 4,5 GB |
| Docker | 29.8.2, Compose v2.40.2 |
| Thư mục dự án | `/root/DALN_JobFind`, chạy lệnh compose trong `/root/DALN_JobFind/deploy` |
| Công cụ dùng | Termius (SSH), PowerShell (`scp`) |

Mật khẩu root xem và đặt lại ở trang quản lý VPS của 123HOST. Mật khẩu này khác mật khẩu tài khoản 123HOST.

## 4. Các bước đã thực hiện

### Trên máy Windows

```powershell
cd D:\job_find
npm run vps:env -- 61-14-233-122.sslip.io --force   # tạo deploy\.env với IP thật
npm start                                           # bật XAMPP MySQL trước
npm run vps:export-data                             # -> deploy\data-export\2026-10-07T06-43-02-002Z (26,7 MB)

cd D:\job_find\deploy
scp -P 2018 .env root@61.14.233.122:/root/DALN_JobFind/deploy/.env
scp -P 2018 -r data-export root@61.14.233.122:/root/DALN_JobFind/deploy/
```

### Trên VPS (Termius, trong `tmux`)

Chạy từng khối, đợi khối trước xong mới chạy khối sau:

```bash
# Công cụ thiếu trên bản minimal + tmux
apt-get update && apt-get install -y curl git tmux netcat-openbsd ca-certificates
tmux new -s deploy                     # lần sau: tmux attach -t deploy

# Cập nhật hệ thống (khi được hỏi về sshd_config: chọn 2 = giữ bản hiện tại)
apt-get -y upgrade
grep -i '^Port' /etc/ssh/sshd_config   # phải là Port 2018

# Giải phóng cổng 80/443 (Caddy của addon FlashVPS)
systemctl disable --now caddy nginx apache2 2>/dev/null
ss -tlnp | grep -E ':(80|443) ' || echo "OK: cong 80/443 dang trong"

# Docker
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
curl -fsSL https://get.docker.com | sh
docker --version && docker compose version

# Elasticsearch, swap, tường lửa (mở cổng 2018 TRƯỚC khi bật)
echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-elasticsearch.conf && sysctl --system
fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
apt-get install -y ufw
ufw allow 2018/tcp && ufw allow 80/tcp && ufw allow 443 && ufw --force enable

# Mã nguồn
cd /root && git clone https://github.com/nguyentuanthien2384/DALN_JobFind.git

# Build (khoảng 10–20 phút)
cd /root/DALN_JobFind/deploy
docker compose build                   # kết quả: 3 image "Built"
```

### Các bước tiếp sau build

```bash
cd /root/DALN_JobFind/deploy
sh scripts/import-data.sh data-export/2026-10-07T06-43-02-002Z
docker compose run --rm backend node /app/scripts/migrate-auth.mjs --from-env
docker compose ps                      # đợi các dịch vụ "healthy"
```

Mở `https://61-14-233-122.sslip.io` (hoặc tên miền riêng sau khi đổi, xem mục 6).

## 5. Sự cố đã gặp và cách xử lý

| Hiện tượng | Nguyên nhân | Cách xử lý |
| --- | --- | --- |
| `tmux: command not found` | Ubuntu bản minimal | `apt-get install -y tmux` |
| `duplicate session: deploy` | Phiên tmux đã tồn tại | `tmux attach -t deploy` |
| Dùng nhầm IP `103.57.220.15` | Đó là IP ví dụ | Lấy *Public IPv4* trong trang quản lý VPS, chạy lại `vps:env ... --force` (chỉ an toàn khi VPS chưa tạo CSDL) |
| `scp: stat local "deploy/.env": No such file` | PowerShell đang ở `D:\job_find\deploy` | Dùng `.env` và `data-export` (bỏ tiền tố `deploy/`) |
| `Permission denied (publickey,password)` | Sai mật khẩu root | Nhập đúng mật khẩu đang dùng cho Termius, hoặc "Đặt lại mật khẩu" trên trang quản lý VPS |
| Kéo thả file vào Termius chỉ ra đường dẫn dạng chữ | Thả vào cửa sổ terminal, không phải màn hình SFTP | Dùng `scp` trong PowerShell, hoặc màn hình SFTP của Termius |
| `What do you want to do about modified configuration file sshd_config?` | `apt-get upgrade` hỏi về file SSH mà 123HOST đã sửa (cổng 2018); các lệnh dán sau đó bị nuốt làm câu trả lời | Gõ `2` (giữ bản hiện tại). Không chọn 1, sẽ mất quyền SSH |
| Cổng 80 bị chiếm bởi `caddy` | Caddy cài sẵn theo addon FlashVPS | `systemctl disable --now caddy` |
| `fallocate failed: Text file busy` | Swap đã được tạo từ trước | Bỏ qua. Kiểm tra `/etc/fstab` không có dòng swap lặp |
| `ufw: command not found` | Ubuntu bản minimal | `apt-get install -y ufw` |

## 6. Đổi sang tên miền riêng

1. Đăng ký tên miền (`.id.vn` miễn phí hoặc `.com`).
2. Ở trang quản lý DNS, tạo bản ghi **A**: host `jobfind` (hoặc `@`), giá trị `61.14.233.122`. Kiểm tra bằng `nslookup <tên-miền>`.
3. Trên VPS, chỉ đổi 2 dòng rồi khởi động lại. **Không** chạy lại `vps:env --force`, vì lệnh đó sinh mật khẩu CSDL mới không khớp với CSDL đang chạy.

   ```bash
   cd /root/DALN_JobFind/deploy
   sed -i 's|^SITE_ADDRESS=.*|SITE_ADDRESS=jobfind.tenban.id.vn|; s|^PUBLIC_URL=.*|PUBLIC_URL=https://jobfind.tenban.id.vn|' .env
   grep -E '^(SITE_ADDRESS|PUBLIC_URL)=' .env
   docker compose up -d
   ```

4. Nếu dùng đăng nhập qua Auth0: thêm `https://<tên-miền>/api/auth/sso/auth0/callback` vào *Allowed Callback URLs*.

## 7. Vận hành

| Việc | Lệnh (trong `/root/DALN_JobFind/deploy`) |
| --- | --- |
| Xem trạng thái | `docker compose ps` |
| Xem log | `docker compose logs --tail 80 <dịch-vụ>` |
| Cập nhật code | `git pull && docker compose build && docker compose run --rm backend node /app/scripts/migrate-auth.mjs --from-env && docker compose up -d` |
| Sao lưu | `sh scripts/backup.sh` |
| Khôi phục | `sh scripts/import-data.sh backups/<thời-điểm> --force` |
| Dừng (giữ dữ liệu) | `docker compose down`. **Không bao giờ** dùng `down -v` (xóa toàn bộ CSDL) |

Sao lưu tự động lúc 3 giờ sáng (`crontab -e`):

```
0 3 * * * cd /root/DALN_JobFind/deploy && sh scripts/backup.sh >> backups/backup.log 2>&1
```

Tắt máy tính, Termius, XAMPP hay `npm start` không ảnh hưởng website. VPS chạy 24/7, và các container tự chạy lại khi VPS khởi động lại. Chỉ website sập khi tắt VPS trên trang 123HOST, khi chạy `docker compose down`, hoặc khi **VPS hết hạn chưa gia hạn**. Từ khi deploy, dữ liệu trên máy dev và trên VPS là hai bản riêng.

## 8. Việc cần làm trước khi demo với nhà tuyển dụng

- [ ] Xác nhận `import-data.sh` chạy xong, `docker compose ps` đều healthy, website mở được bằng HTTPS từ điện thoại dùng 4G.
- [ ] **Đổi mật khẩu admin** `0795095049`. Mật khẩu `123456` đang công khai trong README trên GitHub.
- [ ] Tài khoản demo cho nhà tuyển dụng (mật khẩu `Demo@123456`):
  - Ứng viên `0928800001`: tìm việc, nộp CV, theo dõi ứng tuyển, chatbot.
  - Nhà tuyển dụng `0918800001`: Kanban 6 cột, AI sàng lọc hồ sơ, chat realtime.
- [ ] Đặt cron sao lưu. Theo dõi website bằng UptimeRobot (miễn phí).
- [ ] Đổi sang tên miền riêng (mục 6).
- [ ] Đặt nhắc gia hạn VPS hằng tháng (tab *Thanh Toán* trong trang quản lý VPS).
- [ ] Theo dõi quota `ANTHROPIC_API_KEY`, vì chatbot và AI giờ ai cũng dùng được.
- [ ] Quay sẵn video demo 3–5 phút để dự phòng khi mạng hoặc server trục trặc.

Câu giới thiệu khi phỏng vấn: *"Hệ thống microservices được container hóa bằng Docker và triển khai bằng Docker Compose trên VPS Ubuntu, với HTTPS tự động qua Caddy, sao lưu định kỳ và dữ liệu chuyển từ môi trường dev có kiểm tra checksum."*
