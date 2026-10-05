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
umask 077
tar -xf scap-deploy.tar
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
  `scripts.secure_backup` hiện chỉ dùng cho SQLite, **không backup PostgreSQL**.
- Khi nâng cấp, backup trước, giữ nguyên file bí mật, tên project `scap-vps-demo` và
  volume; thay image sau khi thử bản mới. Không chạy `docker compose down -v`,
  seed/reset database hoặc sinh lại khóa để xử lý lỗi triển khai.

Giới hạn tài nguyên trong lớp phủ là mức trần, không phải RAM/CPU được đặt chỗ.
Vẫn cần phần tài nguyên cho OS và đỉnh migration/khởi động. Nếu VPS bị OOM,
restart hoặc không đạt kịch bản thử 3–4 người, điều chỉnh tải/tăng cấu hình trước
buổi demo; chưa coi cấu hình này là bằng chứng sẵn sàng cho dữ liệu thật.
