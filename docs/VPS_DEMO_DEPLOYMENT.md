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

## Cách nhanh: deploy bằng Termius hoặc `deploy/deploy.ps1`

Có hai cách: làm hoàn toàn trong **Termius** (VPS tự `git clone` và build, giống
JobFind), hoặc chạy `deploy.ps1` trên Windows (build trên máy cá nhân rồi gửi qua SSH;
cần Docker Desktop và `.venv` từ `setup.ps1`). VPS: Ubuntu 22.04/24.04 x86_64, kể cả
bản *minimal* của 123HOST.

### Hai chế độ biên

| `SCAP_EDGE_MODE` | Khi nào dùng | Ai giữ cổng 80/443 |
| --- | --- | --- |
| `direct` (mặc định) | VPS riêng cho SCAP | Caddy của SCAP |
| `shared-proxy` | VPS đã chạy ứng dụng khác bằng Docker + Caddy, ví dụ VPS 123HOST đang chạy JobFind | Caddy của ứng dụng kia |

Ở chế độ `shared-proxy` (VPS 123HOST hiện tại):

```
Internet ─HTTPS─► Caddy JobFind :443 ─┬─ thiennt.id.vn ──────► JobFind
                                       └─ scap.thiennt.id.vn (TLS 1.3)
                                            │ HTTP, mạng vps-shared-edge (172.30.47.0/28)
                                            ▼
                                       Caddy SCAP 172.30.47.3: lọc đường dẫn, header, giới hạn body
                                            ▼ mạng edge của SCAP
                                       app ─► mạng backend nội bộ ─► PostgreSQL, Redis
```

- Mỗi ứng dụng cần **hostname riêng** dưới cùng tên miền (`scap.thiennt.id.vn`),
  không dùng đường dẫn kiểu `thiennt.id.vn/scap`: SCAP chạy giao diện ở `/` và API
  ở `/api/*` (trùng JobFind), cookie phiên `path=/`, passkey gắn với hostname. Chung
  một origin thì mã JavaScript của JobFind đọc được dữ liệu phiên SCAP.
- Caddy SCAP ([Caddyfile.shared-proxy](../Caddyfile.shared-proxy)) giữ nguyên mọi
  luật của [Caddyfile](../Caddyfile) (test `tests/test_shared_proxy.py` so từng
  dòng), chỉ tin `X-Forwarded-For` từ đúng `172.30.47.2` (Caddy JobFind) và chỉ
  chuyển IP người dùng cho app. Nhờ vậy giới hạn theo IP và audit vẫn tính riêng
  từng người, client không giả được IP bằng header.
- SCAP không vào mạng nội bộ của JobFind; hai bên không thấy CSDL của nhau.
- Đánh đổi: Caddy JobFind giữ chứng chỉ HTTPS của SCAP và thấy nội dung đã giải
  mã TLS. Chấp nhận được cho demo; dữ liệu thật nên chạy `direct` trên VPS riêng.

### Triển khai `scap.thiennt.id.vn` lên VPS 123HOST đang chạy JobFind (Termius)

Cách làm giống JobFind: VPS tự lấy code từ GitHub (repo công khai), tự build và chạy.
Mọi lệnh dưới đây gõ trong **Termius**, phiên `root@vps-nnbpg`, trừ bước DNS.

| Mục | Giá trị |
| --- | --- |
| VPS | `61.14.233.122`, **cổng SSH 2018**, Ubuntu 22.04 minimal, Docker đã có |
| JobFind | `https://thiennt.id.vn`, thư mục `/root/DALN_JobFind/deploy` |
| SCAP | `https://scap.thiennt.id.vn`, thư mục `/root/scap` |
| DNS | iNET (`ns1–3.inet.vn`) |

**Bước 1 — DNS ở iNET.** Đăng nhập trang quản lý tên miền iNET → `thiennt.id.vn` →
*Quản lý DNS* → thêm bản ghi: loại `A`, tên/host `scap`, giá trị `61.14.233.122`, TTL
mặc định. Không sửa các bản ghi `@`/`www` của JobFind. Kiểm tra (gõ được cả trong
Termius lẫn cmd của Windows): `nslookup scap.thiennt.id.vn` phải ra `61.14.233.122`.

**Bước 2 — kiểm tra JobFind có mạng dùng chung.**

```bash
docker network inspect vps-shared-edge --format '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{"\n"}}{{end}}'
```

Kết quả có dòng `jobfind-web-1 172.30.47.2/28` là xong. Nếu báo `No such network`,
cập nhật JobFind rồi kiểm tra lại: `cd /root/DALN_JobFind/deploy && sh scripts/update.sh`.

**Bước 3 — lấy code SCAP về VPS (một lần).**

```bash
git --version && python3 --version && docker compose version
cd /root && git clone https://github.com/nguyentuanthien2384/Secure_Conversational_Application_Platform.git scap
```

**Bước 4 — đưa `deploy/.env.vps` lên VPS (một lần).** File này chứa khóa bí mật, chỉ có
trên máy Windows (`D:\btl\scap\deploy\.env.vps`) và **không** có trên GitHub.

1. Termius → mục **SFTP** ở thanh bên trái → một bên chọn **Local**, bên kia chọn host VPS.
2. Bên Local mở `D:\btl\scap\deploy`. Nếu không thấy `.env.vps`, bật *Show hidden files*.
3. Bên VPS mở `/root/scap/deploy`, rồi kéo file `.env.vps` từ Local sang.

Không kéo thả được trong Termius thì dùng terminal PowerShell của VS Code (dấu nhắc
`PS D:\btl\scap>`), nhập mật khẩu root khi được hỏi:

```powershell
scp -P 2018 deploy/.env.vps root@61.14.233.122:/root/scap/deploy/.env.vps
```

Quay lại terminal của Termius, khóa quyền file, điền email (hiển thị công khai trong
`/.well-known/security.txt`) và kiểm tra:

```bash
cd /root/scap
chmod 600 deploy/.env.vps
python3 -m scripts.prepare_vps configure --project . --email <email-cua-ban>
python3 -m scripts.prepare_vps check --project .
```

`check` báo `Configuration checks passed` là được. Từ đây bản trên VPS là bản dùng để
chạy; bản trên Windows giữ cùng các khóa bí mật, đừng xóa vì đó là bản sao lưu khóa.

**Bước 5 — deploy.**

```bash
cd /root/scap && bash deploy/update.sh
```

[update.sh](../deploy/update.sh) sao lưu CSDL (nếu SCAP đang chạy), `git pull`, kiểm
tra cấu hình, build image (lần đầu vài phút; JobFind vẫn chạy bình thường) rồi gọi
[remote-deploy.sh](../deploy/remote-deploy.sh):

1. chạy `migrate → app → caddy` của SCAP;
2. kiểm tra mạng, volume và dòng `import` của Caddy JobFind đã sẵn sàng;
3. kiểm tra cú pháp site SCAP ([shared-proxy-site.caddy](../deploy/shared-proxy-site.caddy))
   bằng Caddy **trước khi** chạm vào JobFind;
4. ghi `scap.caddy` vào volume và `caddy reload` Caddy JobFind (không khởi động
   lại; reload lỗi thì gỡ file ra để JobFind giữ nguyên);
5. chờ `https://scap.thiennt.id.vn/api/health`; Caddy JobFind tự xin chứng chỉ
   Let's Encrypt cho `scap.thiennt.id.vn`;
6. cài cron sao lưu PostgreSQL lúc 03:00 hằng ngày.

**Bước 6 — tạo tài khoản quản trị** (nhập mật khẩu 15–128 ký tự hai lần, không hiển thị):

```bash
cd /root/scap
bash deploy/vps-compose.sh run --rm --no-deps app /app/.venv/bin/python scripts/create_admin.py --username operator
```

Mở `https://scap.thiennt.id.vn`, đăng nhập rồi bật MFA. Kiểm tra lại
`https://thiennt.id.vn` vẫn là JobFind.

**Dùng lại các tài khoản quen thuộc khi chạy local** (thay hoặc thêm cho bước 6): một
lệnh tạo `demo.user`, `demo.mod`, `demo.boss` (admin) và 8 tài khoản `lab.*` cùng hội
thoại mẫu đã mã hóa, với **một mật khẩu riêng** nhập ẩn hai lần (15–128 ký tự).
Mật khẩu công khai trong README bị từ chối vì website ai cũng truy cập được.
Tài khoản đã tồn tại không bị đổi; chạy lại không tạo trùng.

```bash
cd /root/scap
bash deploy/vps-compose.sh run --rm --no-deps app /app/.venv/bin/python scripts/seed_vps_accounts.py
```

Thêm `--with-sample-alerts` nếu muốn dashboard IDS có sẵn các cảnh báo tấn công giả
lập. Mặc định không thêm, vì smart lockout đọc bảng audit nên các lần đăng nhập sai
giả lập có thể tạm khóa `demo.user`/`lab.alice` với IP thật của bạn. Đăng nhập
`demo.boss` và bật MFA ngay, vì đây là tài khoản admin.

**Cập nhật code sau này:** trên Windows commit và push lên GitHub (VS Code →
*Source Control* → *Commit* → *Sync*), rồi trong Termius:
`cd /root/scap && bash deploy/update.sh`.

#### Cách khác: deploy từ Windows bằng `deploy.ps1`

Không cần push code; build trên máy cá nhân rồi upload qua SSH (chạy trong PowerShell
của VS Code, dấu nhắc `PS D:\btl\scap>`; SCAP nằm ở `/home/deploy/scap-vps`, user `deploy`):

```powershell
$env:SCAP_VPS_PORT = "2018"
.\deploy\deploy.ps1 setup-server -Server root@61.14.233.122   # một lần, hỏi mật khẩu root
.\deploy\deploy.ps1 configure -Email <email-cua-ban>
$env:SCAP_VPS = "deploy@61.14.233.122"
.\deploy\deploy.ps1 deploy
.\deploy\deploy.ps1 admin -AdminUser operator
```

Chọn **một** trong hai cách cho mỗi VPS: hai cách dùng chung tên project Docker
`scap-vps-demo` và volume dữ liệu, nhưng thư mục cấu hình khác nhau.

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

| Việc | Termius (trong `/root/scap`) | Nếu deploy bằng `deploy.ps1` (Windows) |
| --- | --- | --- |
| Cập nhật code (sau khi push) | `bash deploy/update.sh` | `deploy.ps1 deploy` |
| Áp dụng thay đổi `.env.vps` | `bash deploy/remote-deploy.sh` | `deploy.ps1 deploy -SkipBuild` |
| Trạng thái | `bash deploy/vps-compose.sh ps` | `deploy.ps1 status` |
| Xem log | `bash deploy/vps-compose.sh logs --tail 80 app caddy` | `deploy.ps1 logs -Follow` |
| Sao lưu ngay | `bash deploy/backup.sh` → `backups/<thời-điểm>` | `deploy.ps1 backup` (tải về `backups\vps`) |
| Sao lưu tự động | cron 03:00 hằng ngày, giữ 14 bản (`crontab -l`) | như bên trái |
| Khôi phục | `bash deploy/restore.sh backups/<thời-điểm>`, thêm `--force` nếu DB đã có dữ liệu | chạy trên VPS trong `~/scap-vps` |
| Dừng, giữ dữ liệu | `bash deploy/vps-compose.sh down`. **Không bao giờ** thêm `-v` | như bên trái |

Nên định kỳ tải thư mục `/root/scap/backups/` về máy bằng SFTP của Termius.
[backup.sh](../deploy/backup.sh) tạo `pg_dump` kèm SHA-256;
[restore.sh](../deploy/restore.sh) kiểm tra checksum và từ chối ghi đè DB đã có
người dùng nếu thiếu `--force`. Nội dung tin nhắn trong bản dump được mã hóa bằng
khóa trong `deploy/.env.vps`, nên **giữ file đó cùng bản sao lưu** và không để nó
trong `backups/`. **Không xóa hoặc tạo lại `deploy/.env.vps`.**

### Sự cố thường gặp

| Hiện tượng | Cách xử lý |
| --- | --- |
| `ssh: connect to host … port 22: Connection refused` | VPS 123HOST dùng cổng 2018: `$env:SCAP_VPS_PORT = "2018"` |
| `Permission denied (publickey,password)` khi `setup-server` | Dùng mật khẩu root ở trang quản lý VPS hoặc đặt lại tại đó |
| `Chua co mang Docker vps-shared-edge` hoặc `chua co dong 'import sites/*.caddy'` | JobFind trên VPS chưa có phần dùng chung: Bước 2 (`sh scripts/update.sh`) |
| `cd: D:\btl\scap: No such file or directory` trong Termius | Lệnh `deploy.ps1` chạy trên Windows; trong Termius dùng `cd /root/scap && bash deploy/update.sh` |
| `Chua co deploy/.env.vps` khi chạy `update.sh` | Bước 4: kéo file `.env.vps` vào `/root/scap/deploy/` bằng SFTP của Termius |
| `configuration missing, unsafe or inaccessible` | `chmod 600 /root/scap/deploy/.env.vps` rồi chạy lại |
| `... chua co ban ghi A` hoặc `dang tro ve ..., khong phai VPS` | Bước 1: bản ghi `A` `scap` → `61.14.233.122` ở iNET, đợi vài phút, `ipconfig /flushdns` |
| `port is already allocated` khi deploy `direct` | VPS đã có ứng dụng khác giữ 80/443: `configure -EdgeMode shared-proxy` |
| `MAIL_FROM: use a sender with a dotted domain` | File `.env.vps` tạo từ mẫu cũ: sửa thành `MAIL_FROM='SCAP <no-reply@scap.local>'` |
| `Chua truy cap duoc https://…` sau deploy | Xem `deploy.ps1 logs`; chế độ `shared-proxy` xem thêm log Caddy JobFind: `docker compose logs --tail 50 web` trong `/root/DALN_JobFind/deploy` |
| Trang chỉ hiện `Loading...` mãi, console trình duyệt báo 503 cho `/assets/*.js` | Bản trước 12/10: qua HTTP/2 Gradio tải ~110 file cùng lúc và vượt giới hạn đồng thời theo IP. Đã sửa (Caddyfile `@frontend_assets`, file tĩnh không chiếm slot theo IP): push code rồi `bash deploy/update.sh` |
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
