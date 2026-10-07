# Chuẩn bị SCAP để triển khai demo trên VPS

Hồ sơ này dành cho **VPS Linux 1 CPU, 3 GB RAM, khoảng 3–4 người dùng demo**.
Nó giữ PostgreSQL, Redis và HTTPS qua Caddy, dùng một tiến trình ứng dụng và
giới hạn tài nguyên nhỏ hơn bản mặc định. Đây là cấu hình để thử trên VPS thật;
chưa có số đo để cam kết tốc độ hoặc khả năng chịu DDoS.

Các file được dùng:

- `docker-compose.yml`: nền tảng production và mạng nội bộ.
- `docker-compose.vps-demo.yml`: lớp phủ tài nguyên cho demo nhỏ.
- `deploy/vps.env.example`: mẫu công khai, không chứa bí mật thật.
- `deploy/.env.vps`: cấu hình riêng được sinh bằng `scripts.prepare_vps`.

**Không cần mua thêm hosting WordPress.** VPS phục vụ cả giao diện và API.
Chuẩn bị này chưa mua dịch vụ, mở cổng hoặc khởi động ứng dụng trên server.
SQLite, tài khoản mẫu và dữ liệu local hiện tại không được chuyển sang VPS.

## Cách nhanh: deploy bằng `deploy/deploy.ps1`

Script chạy trên Windows và tự động hóa các mục 1–4 bên dưới: build image trên
máy cá nhân, gửi qua SSH, chạy Docker Compose trên VPS. Cần Docker Desktop
(Linux containers) đang chạy, `.venv` đã cài bằng `setup.ps1` và VPS Ubuntu
22.04/24.04 x86_64 (kể cả bản *minimal* của 123HOST).

### Hai chế độ biên

| `SCAP_EDGE_MODE` | Khi nào dùng | Ai giữ cổng 80/443 |
| --- | --- | --- |
| `direct` (mặc định) | VPS riêng cho SCAP | Caddy của SCAP |
| `shared-proxy` | VPS đã chạy ứng dụng khác bằng Docker + Caddy, ví dụ VPS 123HOST đang chạy JobFind | Caddy của ứng dụng kia |

Ở chế độ `shared-proxy`:

```
Internet ─HTTPS, TLS 1.3─► Caddy JobFind :443 ─┬─ 61-14-233-122.sslip.io ───► JobFind
                                                └─ scap.61-14-233-122.sslip.io
                                                     │ HTTP, mạng vps-shared-edge (172.30.47.0/28)
                                                     ▼
                                                Caddy SCAP 172.30.47.3: lọc đường dẫn, header, giới hạn body
                                                     ▼ mạng edge của SCAP
                                                app ─► mạng backend nội bộ ─► PostgreSQL, Redis
```

- Caddy SCAP ([Caddyfile.shared-proxy](../Caddyfile.shared-proxy)) giữ nguyên mọi
  luật của [Caddyfile](../Caddyfile) (test `tests/test_shared_proxy.py` so từng
  dòng), chỉ tin `X-Forwarded-For` từ đúng `172.30.47.2` (Caddy JobFind) và chỉ
  chuyển IP người dùng cho app. Nhờ vậy giới hạn theo IP và audit vẫn tính riêng
  từng người, client không giả được IP bằng header.
- SCAP không vào mạng nội bộ của JobFind; hai bên không thấy CSDL của nhau.
- Đánh đổi: Caddy JobFind giữ chứng chỉ HTTPS của SCAP và thấy nội dung đã giải
  mã TLS. Chấp nhận được cho demo; dữ liệu thật nên chạy `direct` trên VPS riêng.

### Triển khai lên VPS 123HOST đang chạy JobFind (`61.14.233.122`)

VPS này dùng **cổng SSH 2018**, đăng nhập `root` bằng mật khẩu xem/đặt lại ở trang
quản lý VPS (khác mật khẩu tài khoản 123HOST). Docker và swap đã có sẵn.

**Bước 1 — cập nhật JobFind (một lần).** Commit và push thay đổi trong
`D:\job_find\deploy` (`Caddyfile`, `docker-compose.yml`, `README.md`): Caddy của
JobFind tham gia mạng `vps-shared-edge`, mount volume `vps-shared-sites` và
`import sites/*.caddy`. Trên VPS (JobFind gián đoạn vài giây, không build lại React):

```bash
cd /root/DALN_JobFind && git pull && cd deploy
docker compose up -d web
```

**Bước 2 — chuẩn bị VPS cho SCAP (một lần).**

```powershell
$env:SCAP_VPS_PORT = "2018"
.\deploy\deploy.ps1 setup-server -Server root@61.14.233.122
```

Lệnh tạo SSH key nếu máy chưa có rồi chạy [server-setup.sh](../deploy/server-setup.sh):
cập nhật OS không hỏi lại (giữ `sshd_config` cổng 2018 của 123HOST), bỏ qua
Docker/swap đã có, tạo user `deploy` đăng nhập bằng key (thuộc nhóm `docker`,
tương đương root trên host), cài `cron`, giữ UFW mở 2018/80/443 và báo cổng
80/443 đang do container JobFind giữ. Script không dừng dịch vụ hay container nào.

**Bước 3 — cấu hình.** `scap.61-14-233-122.sslip.io` tự phân giải về IP VPS, không
cần tạo bản ghi DNS. Email hiển thị công khai trong `/.well-known/security.txt`.

```powershell
.\deploy\deploy.ps1 configure -Domain scap.61-14-233-122.sslip.io -Email <email-cua-ban> -EdgeMode shared-proxy
```

Lệnh ghi domain/email/chế độ biên vào `deploy/.env.vps`, ghim digest SHA-256 của
4 image nền, giữ nguyên khóa bí mật và chạy `check`.

**Bước 4 — deploy và tạo admin.**

```powershell
$env:SCAP_VPS = "deploy@61.14.233.122"
$env:SCAP_VPS_PORT = "2018"
.\deploy\deploy.ps1 deploy
.\deploy\deploy.ps1 admin -AdminUser operator
```

`deploy` build image `linux/amd64`, upload image nén (khoảng 360 MB), gói cấu hình,
script vận hành và `deploy/.env.vps`. Trên VPS, [remote-deploy.sh](../deploy/remote-deploy.sh)
kiểm tra cấu hình, nạp image, chạy `migrate → app → caddy`, rồi ở chế độ
`shared-proxy`:

1. kiểm tra mạng, volume và dòng `import` của Caddy JobFind đã sẵn sàng;
2. kiểm tra cú pháp site SCAP ([shared-proxy-site.caddy](../deploy/shared-proxy-site.caddy))
   bằng Caddy **trước khi** chạm vào JobFind;
3. ghi `scap.caddy` vào volume và `caddy reload` Caddy JobFind (không khởi động
   lại; reload lỗi thì gỡ file ra để JobFind giữ nguyên);
4. chờ `https://scap.61-14-233-122.sslip.io/api/health`. Caddy JobFind tự xin chứng
   chỉ Let's Encrypt cho tên miền SCAP.

Nếu chỉ sửa `.env.vps` hoặc Caddyfile, thêm `-SkipBuild` để không upload lại image.

### VPS riêng (`direct`)

Trên trang quản lý VPS: cài Ubuntu 22.04/24.04 LTS; nếu có tường lửa phía nhà cung
cấp, mở cổng SSH, 80 và 443. Tạo bản ghi `A` của tên miền trỏ về IP VPS, hoặc dùng
tạm `<IP-nối-bằng-gạch>.sslip.io`. Gói hosting (cPanel) không dùng được cho Docker.

```powershell
.\deploy\deploy.ps1 setup-server -Server root@IP_VPS
.\deploy\deploy.ps1 configure -Domain demo.tenmiencuaban.vn -Email ban@tenmiencuaban.vn
.\deploy\deploy.ps1 deploy -Server deploy@IP_VPS
.\deploy\deploy.ps1 admin -Server deploy@IP_VPS
```

Nếu `setup-server` báo cổng 80/443 do dịch vụ trên host giữ (ví dụ Caddy của addon
FlashVPS), tắt nó bằng `systemctl disable --now caddy` trước khi deploy.

### Vận hành

| Việc | Trên Windows | Trên VPS (user `deploy`, thư mục `~/scap-vps`) |
| --- | --- | --- |
| Cập nhật code | `deploy.ps1 deploy` | |
| Chỉ đổi cấu hình | `deploy.ps1 deploy -SkipBuild` | |
| Trạng thái, RAM, ổ đĩa | `deploy.ps1 status` | `./vps-compose.sh ps` |
| Xem log | `deploy.ps1 logs -Follow` | `./vps-compose.sh logs --tail 80 app caddy` |
| Sao lưu ngay, tải về máy | `deploy.ps1 backup` → `backups\vps\<thời-điểm>` | `bash backup.sh` |
| Sao lưu tự động | | cron 03:00 hằng ngày, giữ 14 bản (deploy tự cài) |
| Khôi phục | | `bash restore.sh backups/<thời-điểm>`, thêm `--force` nếu DB đã có dữ liệu |
| Dừng, giữ dữ liệu | | `./vps-compose.sh down`. **Không bao giờ** thêm `-v` |

[backup.sh](../deploy/backup.sh) tạo `pg_dump` kèm SHA-256;
[restore.sh](../deploy/restore.sh) kiểm tra checksum và từ chối ghi đè DB đã có
người dùng nếu thiếu `--force`. Nội dung tin nhắn trong bản dump được mã hóa bằng
khóa trong `deploy/.env.vps`, nên **giữ file đó trên máy cá nhân cùng bản sao lưu**
và không để nó trong `backups/`. **Không xóa hoặc tạo lại `deploy/.env.vps`.**

### Sự cố thường gặp

| Hiện tượng | Cách xử lý |
| --- | --- |
| `ssh: connect to host … port 22: Connection refused` | VPS 123HOST dùng cổng 2018: `$env:SCAP_VPS_PORT = "2018"` |
| `Permission denied (publickey,password)` khi `setup-server` | Dùng mật khẩu root ở trang quản lý VPS hoặc đặt lại tại đó |
| `Chua co mang Docker vps-shared-edge` hoặc `chua co dong 'import sites/*.caddy'` | Chưa làm Bước 1 (cập nhật JobFind) |
| `port is already allocated` khi deploy `direct` | VPS đã có ứng dụng khác giữ 80/443: `configure -EdgeMode shared-proxy` |
| `MAIL_FROM: use a sender with a dotted domain` | File `.env.vps` tạo từ mẫu cũ: sửa thành `MAIL_FROM='SCAP <no-reply@scap.local>'` |
| `Chua truy cap duoc https://…` sau deploy | Xem `deploy.ps1 logs`; chế độ `shared-proxy` xem thêm log Caddy JobFind: `docker compose logs --tail 50 web` trong `/root/DALN_JobFind/deploy` |
| `curl` trên Windows 10 báo `SEC_E_UNSUPPORTED_FUNCTION` | Windows 10 không có TLS 1.3 mà SCAP yêu cầu; mở bằng Chrome/Edge/Firefox |
| PowerShell chặn script | `powershell -ExecutionPolicy Bypass -File deploy\deploy.ps1 <lệnh> …` |

Các mục bên dưới mô tả chi tiết từng bước khi muốn làm thủ công ở chế độ `direct`.

## 1. Chuẩn bị ngay trên máy cá nhân

Tại thư mục dự án, dùng PowerShell:

```powershell
.\.venv\Scripts\python.exe -m scripts.prepare_vps init --project .
```

Lệnh tạo **file mới** `deploy/.env.vps` với bí mật ngẫu nhiên và quyền truy cập
riêng. Nó không ghi đè file đã tồn tại hoặc sửa `.env` đang dùng local. Chưa có
tên miền thì giữ cấu hình ở trạng thái chờ; không dùng domain ví dụ để public.
Nếu chưa tạo file và đã có tên miền/email thật, có thể truyền ngay:

```powershell
.\.venv\Scripts\python.exe -m scripts.prepare_vps init --project . --domain chat.tenmiencuaban.vn --email admin@tenmiencuaban.vn
```

Sau khi đã tạo file, sửa **file riêng** `deploy/.env.vps` bằng trình soạn thảo.
Không chạy lại `init` để thay khóa. Không đưa file này vào Git, tin nhắn,
ảnh chụp hoặc công cụ so sánh cấu hình. Giữ các giá trị:

```dotenv
COMPOSE_PROJECT_NAME=scap-vps-demo
SCAP_ENV_FILE=./deploy/.env.vps
SCAP_APP_IMAGE=scap:vps-demo
```

Hồ sơ dùng `APP_ENV=production`, `SECURITY_PROFILE=standard`, tắt tài khoản seed,
tắt tài liệu API và giữ các kiểm soát bảo mật. Khóa mã hóa local được dùng cho
demo, cần backup riêng; đây chưa phải hồ sơ `high` có Vault/KMS và WORM ngoài.
Không ghép với `docker-compose.local.yml` khi public.

## 2. Hoàn tất tên miền và image trước khi build

Trong `deploy/.env.vps`, điền domain thật vào `PUBLIC_DOMAIN` và email nhận
thông báo chứng chỉ vào `CADDY_EMAIL`. Đồng bộ `PUBLIC_BASE_URL`,
`ALLOWED_ORIGINS` với `https://domain-thật`; `ALLOWED_HOSTS` chỉ gồm domain này
và các loopback cần cho UI. `WEBAUTHN_RP_ID` là domain, `WEBAUTHN_ORIGINS` là
origin HTTPS tương ứng. Nếu triển khai sau thời gian dài, cập nhật
`SECURITY_TXT_EXPIRES` thành ngày UTC tương lai trong vòng một năm.
Không thêm wildcard hoặc tin mọi proxy.

Pin bốn image bằng digest SHA-256 đã kiểm tra. Trên máy có Docker Desktop
chạy Linux containers, xem thông tin image từ registry:

```powershell
docker buildx imagetools inspect python:3.12-slim
docker buildx imagetools inspect postgres:17-alpine
docker buildx imagetools inspect redis:7.4-alpine
docker buildx imagetools inspect caddy:2.10-alpine
```

Đối chiếu đúng repository/tag và kiến trúc VPS; điền digest hiển thị vào
`BASE_IMAGE`, `POSTGRES_IMAGE`, `REDIS_IMAGE`, `CADDY_IMAGE` theo dạng
`repository:tag@sha256:<64-ký-tự-hex>`. Không chép digest ví dụ hoặc tự chế.
Xem [lệnh inspect chính thức của Docker](https://docs.docker.com/reference/cli/docker/buildx/imagetools/inspect/).

Kiểm tra trước khi tiếp tục:

```powershell
.\.venv\Scripts\python.exe -m scripts.prepare_vps check --project .
docker compose --env-file deploy/.env.vps -p scap-vps-demo -f docker-compose.yml -f docker-compose.vps-demo.yml config --quiet
```

`check` phải đạt. Khi chưa điền đủ, nó báo tên khóa cần sửa mà không in giá trị
bí mật. `config --quiet` kiểm tra Compose mà không xuất toàn bộ environment.

AI mặc định là **AI demo ngoại tuyến có nhãn DEMO**, không phát sinh phí API.
Muốn dùng nhà cung cấp thật, điền khóa riêng, đặt `ALLOW_DEMO_AI=false`, kiểm tra
hạn mức/chi phí và đồng thuận gửi dữ liệu trước buổi demo. Không đưa khóa vào image.
Email mặc định tắt: xác minh email/khôi phục mật khẩu qua email chưa hoạt động.
Muốn demo các chức năng đó phải cấu hình SMTP có TLS và kiểm tra gửi thư thật.

## 3. Build trên máy cá nhân, chuyển lên VPS qua SSH

VPS cần cùng kiến trúc với image đã build; hướng dẫn dưới đây giả định cả hai
đều `linux/amd64`. Build trên máy cá nhân tránh tăng đột biến RAM khi cài thư
viện trên VPS nhỏ:

```powershell
docker compose --env-file deploy/.env.vps -p scap-vps-demo -f docker-compose.yml -f docker-compose.vps-demo.yml build app
docker image save -o deploy/scap-image.tar scap:vps-demo
tar -cf deploy/scap-deploy.tar --exclude=__pycache__ --exclude=*.pyc docker-compose.yml docker-compose.vps-demo.yml Caddyfile Dockerfile .dockerignore pyproject.toml uv.lock README.md run_app.py scripts src deploy/vps.env.example
```

Gói mã nguồn dùng danh sách file/thư mục cụ thể; không chứa `.env`,
`deploy/.env.vps`, database local, outbox hay thư mục `.venv`. Thư mục `deploy`
trên máy cá nhân chứa cả mẫu công khai; chỉ `.env.vps` được công cụ đặt quyền
riêng. Chuyển cấu hình bí mật riêng qua SSH.
Thay `deploy@VPS_IP` bằng tài khoản SSH thật có quyền vận hành Docker.

Xác minh fingerprint SSH bằng thông tin đáng tin cậy từ nhà cung cấp khi kết
nối lần đầu; giữ kiểm tra `known_hosts`. Sau đó:

```powershell
ssh deploy@VPS_IP 'install -d -m 700 ~/scap-vps ~/scap-vps/deploy'
scp .\deploy\scap-deploy.tar .\deploy\scap-image.tar deploy@VPS_IP:scap-vps/
scp .\deploy\.env.vps deploy@VPS_IP:scap-vps/deploy/.env.vps
```

## 4. Chuẩn bị VPS và khởi động khi đủ điều kiện

Dùng Ubuntu LTS 64 bit còn được hỗ trợ, cập nhật OS và cài Docker Engine cùng
plugin Compose theo [tài liệu Docker cho Ubuntu](https://docs.docker.com/engine/install/ubuntu/).
Không cần cài cPanel/DirectAdmin cho stack này. Có Python 3 để chạy kiểm tra
cấu hình; không cần cài thư viện ứng dụng vào Python của host.

Trỏ DNS A của domain về IPv4 VPS; chỉ tạo AAAA khi IPv6 thật sự hoạt động.
Dùng SSH key; kiểm tra đăng nhập bằng key và đường truy cập console dự phòng
trước khi sửa SSH/firewall. Ở firewall nhà cung cấp/host, cho phép TCP 80/443,
giới hạn SSH theo IP quản trị nếu phù hợp. Docker có quy tắc firewall riêng;
không mặc định rằng UFW sẽ chặn mọi cổng container đã publish.

Trong phiên SSH, chạy tại thư mục triển khai (dùng `sudo docker` nếu tài khoản
chưa được cấp quyền Docker):

```bash
cd ~/scap-vps
set -e
# Postgres/Caddy đọc file bind-mount bằng user khác, nên cấu hình công khai cần
# quyền đọc 644; chỉ thư mục deploy và .env.vps được giữ riêng tư.
(umask 022 && tar -xf scap-deploy.tar --no-same-owner)
chmod 700 deploy
chmod 600 deploy/.env.vps
python3 -m scripts.prepare_vps check --project .
docker compose --env-file deploy/.env.vps -p scap-vps-demo -f docker-compose.yml -f docker-compose.vps-demo.yml config --quiet
docker image load -i scap-image.tar
docker compose --env-file deploy/.env.vps -p scap-vps-demo -f docker-compose.yml -f docker-compose.vps-demo.yml up -d --no-build
docker compose --env-file deploy/.env.vps -p scap-vps-demo -f docker-compose.yml -f docker-compose.vps-demo.yml ps
```

Dừng quy trình nếu `check`/`config` lỗi. Migration chạy một lần trước ứng dụng;
Caddy chờ ứng dụng healthy rồi xin chứng chỉ. Chỉ Caddy publish 80/443;
không mở 8000, 5432 hoặc 6379 ra Internet.

Sau khi PostgreSQL đang chạy và migration đã hoàn tất thành công, tạo tài khoản
quản trị **mới**, nhập mật khẩu ẩn hai lần:

```bash
docker compose --env-file deploy/.env.vps -p scap-vps-demo -f docker-compose.yml -f docker-compose.vps-demo.yml run --rm --no-deps app /app/.venv/bin/python scripts/create_admin.py --username operator
```

Lệnh không nhận mật khẩu qua argument/env, không ghi đè tài khoản đã tồn tại
và ghi audit cho việc cấp admin. Không dùng mật khẩu/tài khoản mẫu local hoặc
`BOOTSTRAP_ADMIN_PASSWORD` trên VPS. Tạo tài khoản riêng cho từng người demo;
bật MFA cho tài khoản quản trị, giữ recovery code ở nơi riêng.

## 5. Kiểm tra trước buổi bảo vệ và bảo toàn dữ liệu

- Mở `https://domain-thật`, kiểm tra chứng chỉ và `/api/health` trả 200.
  Caddy chủ động trả 404 cho `/api/ready` từ Internet; readiness được kiểm tra
  nội bộ bằng healthcheck của app. Các service phải healthy trong `compose ps`,
  migration thoát thành công.
- Thử đăng nhập/đăng xuất, MFA/passkey, quyền user/admin, tạo hội thoại và AI
  demo. Nếu bật SMTP/provider thật, kiểm tra chúng riêng.
- Chạy thử **3–4 trình duyệt trên cùng mạng lớp học** để kiểm tra các quota theo
  IP, hàng đợi và stream; theo dõi `docker stats`, RAM host, dung lượng SSD,
  lỗi 429/503 và container restart. Không suy ra sức chịu tải từ số lượng tài khoản.
- Đặt lịch backup PostgreSQL mã hóa ra nơi ngoài VPS; giữ riêng `.env.vps`, các
  phiên bản khóa mã hóa cần thiết và quyền truy cập bản backup. Diễn tập restore
  vào môi trường cô lập, đối chiếu audit và thu hồi tài khoản/phiên sau snapshot.
  `scripts.secure_backup` chỉ dùng cho SQLite; PostgreSQL trên VPS dùng
  `deploy/backup.sh` và `deploy/restore.sh` (mục Vận hành).
- Khi nâng cấp, backup trước, giữ nguyên file bí mật, tên project `scap-vps-demo` và
  volume; thay image sau khi thử bản mới. Không chạy `docker compose down -v`,
  seed/reset database hoặc sinh lại khóa để xử lý lỗi triển khai.

Giới hạn tài nguyên trong lớp phủ là mức trần, không phải RAM/CPU được đặt chỗ.
Vẫn cần phần tài nguyên cho OS và đỉnh migration/khởi động. Nếu VPS bị OOM,
restart hoặc không đạt kịch bản thử 3–4 người, điều chỉnh tải/tăng cấu hình trước
buổi demo; chưa coi cấu hình này là bằng chứng sẵn sàng cho dữ liệu thật.
