#!/usr/bin/env bash
# Chạy trên VPS trong ~/scap-vps; deploy/deploy.ps1 tải file này lên cùng các
# script vận hành, gói cấu hình (scap-deploy.tar), image ứng dụng
# (scap-image.tar.gz, tùy chọn) và deploy/.env.vps rồi gọi nó.
# Không tạo lại khóa, không xóa volume dữ liệu, không đụng image/container khác.
set -euo pipefail

cd "$(dirname "$0")"
ENV_FILE=deploy/.env.vps

compose() { bash ./vps-compose.sh "$@"; }
die() { echo "  [X] $*" >&2; exit 1; }
setting() { { grep -m1 "^$1=" "$ENV_FILE" || true; } | cut -d= -f2-; }

[ -f "$ENV_FILE" ] || die "Thieu $ENV_FILE tren VPS."
chmod 700 deploy
chmod 600 "$ENV_FILE"

if [ -f scap-deploy.tar ]; then
  echo "==> Giai nen cau hinh"
  # Postgres và Caddy đọc file bind-mount bằng user khác và không có
  # CAP_DAC_OVERRIDE, nên cấu hình công khai phải đọc được (644/755).
  (umask 022 && tar -xf scap-deploy.tar --no-same-owner)
  chmod -R u=rwX,go=rX docker-compose.yml docker-compose.vps-demo.yml docker-compose.shared-proxy.yml \
    Caddyfile Caddyfile.shared-proxy deploy/shared-proxy-site.caddy scripts src
  rm -f scap-deploy.tar
fi

if python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
  PYTHONDONTWRITEBYTECODE=1 python3 -m scripts.prepare_vps check --project . \
    || die "Cau hinh chua dat; sua deploy/.env.vps tren may ca nhan roi deploy lai."
else
  echo "  [!] VPS khong co Python >= 3.10; bo qua kiem tra cau hinh phia server." >&2
fi

APP_IMAGE=$(setting SCAP_APP_IMAGE)
[ -n "$APP_IMAGE" ] || die "Thieu SCAP_APP_IMAGE trong $ENV_FILE."
old_image_id=$(docker image inspect --format '{{.Id}}' "$APP_IMAGE" 2>/dev/null || true)
if [ -f scap-image.tar.gz ]; then
  echo "==> Nap image ung dung $APP_IMAGE"
  docker image load -i scap-image.tar.gz
  rm -f scap-image.tar.gz
fi
docker image inspect "$APP_IMAGE" >/dev/null 2>&1 \
  || die "VPS chua co image $APP_IMAGE; chay deploy khong kem -SkipBuild."
image_arch=$(docker image inspect --format '{{.Architecture}}' "$APP_IMAGE")
host_arch=$(uname -m)
case "$host_arch" in x86_64) host_arch=amd64 ;; aarch64) host_arch=arm64 ;; esac
[ "$image_arch" = "$host_arch" ] \
  || die "Image $image_arch khong khop kien truc VPS $host_arch; build lai voi -Platform linux/$host_arch."

DOMAIN=$(setting PUBLIC_DOMAIN)
EDGE_MODE=$(setting SCAP_EDGE_MODE)
EDGE_MODE=${EDGE_MODE:-direct}
if [ "$EDGE_MODE" = shared-proxy ]; then
  # Ứng dụng kia (front proxy) sở hữu mạng và volume dùng chung; SCAP chỉ tham gia.
  NETWORK=$(setting SCAP_SHARED_EDGE_NETWORK)
  SITES_VOLUME=$(setting SCAP_SHARED_SITES_VOLUME)
  SHARED_CADDY_IPV4=$(setting SCAP_SHARED_CADDY_IPV4)
  CADDY_IMAGE=$(setting CADDY_IMAGE)
  hint="Cap nhat front proxy (JobFind: docs/VPS_DEMO_DEPLOYMENT.md, muc chung VPS) roi deploy lai."
  docker network inspect "$NETWORK" >/dev/null 2>&1 || die "Chua co mang Docker $NETWORK. $hint"
  docker volume inspect "$SITES_VOLUME" >/dev/null 2>&1 || die "Chua co volume $SITES_VOLUME. $hint"
  FRONT=$(docker ps -q --filter "volume=$SITES_VOLUME" | head -n1)
  [ -n "$FRONT" ] || die "Khong co container nao dang mount $SITES_VOLUME (front proxy chua chay?). $hint"
  docker exec "$FRONT" grep -q 'sites/\*\.caddy' /etc/caddy/Caddyfile \
    || die "Caddyfile cua front proxy chua co dong 'import sites/*.caddy'. $hint"
  echo "  Front proxy: $(docker inspect --format '{{.Name}}' "$FRONT" | tr -d /)"
fi

echo "==> Khoi dong stack (migrate -> app -> caddy), che do bien: $EDGE_MODE"
compose config --quiet
if ! compose up -d --no-build --remove-orphans; then
  compose ps -a
  compose logs --tail 80 migrate app caddy
  if [ "$EDGE_MODE" = direct ]; then
    echo "  [!] Neu cong 80/443 da thuoc ung dung khac tren VPS (vd JobFind), chuyen sang" >&2
    echo "      che do dung chung: deploy.ps1 configure -EdgeMode shared-proxy" >&2
  fi
  die "Khoi dong that bai; xem log o tren."
fi
compose ps

if [ "$EDGE_MODE" = shared-proxy ]; then
  echo "==> Gan $DOMAIN vao front proxy"
  site=$(sed -e "s/__PUBLIC_DOMAIN__/$DOMAIN/g" -e "s/__SCAP_CADDY__/$SHARED_CADDY_IPV4/g" \
    deploy/shared-proxy-site.caddy)
  # Kiểm tra riêng trước: một file hỏng trong volume sẽ làm Caddy của ứng dụng
  # kia không khởi động lại được.
  if ! output=$(printf '%s\n' "$site" | docker run --rm -i --network none "$CADDY_IMAGE" \
      sh -c 'cat > /tmp/Caddyfile && caddy validate --config /tmp/Caddyfile --adapter caddyfile' 2>&1); then
    printf '%s\n' "$output" >&2
    die "Cau hinh site SCAP cho front proxy khong hop le; chua thay doi gi."
  fi
  printf '%s\n' "$site" | docker run --rm -i --network none -v "$SITES_VOLUME:/sites" "$CADDY_IMAGE" \
    sh -c 'cat > /sites/.scap.caddy.tmp && mv /sites/.scap.caddy.tmp /sites/scap.caddy'
  if ! docker exec "$FRONT" caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile; then
    docker run --rm --network none -v "$SITES_VOLUME:/sites" "$CADDY_IMAGE" rm -f /sites/scap.caddy
    docker exec "$FRONT" caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile || true
    die "Front proxy tu choi site SCAP; da go ra de ung dung kia giu nguyen."
  fi
fi

echo "==> Kiem tra https://$DOMAIN/api/health (cho Caddy xin chung chi)"
healthy=0
command -v curl >/dev/null || die "VPS thieu curl; chay lai setup-server."
for _ in $(seq 1 30); do
  if curl -fsS -o /dev/null --max-time 5 "https://$DOMAIN/api/health"; then
    healthy=1
    break
  fi
  sleep 4
done
if [ "$healthy" -eq 1 ]; then
  echo "  [OK] https://$DOMAIN dang hoat dong."
else
  echo "  [!] Chua truy cap duoc https://$DOMAIN. Kiem tra ban ghi DNS A tro ve IP VPS," >&2
  echo "      cong 80/443 va log Caddy: deploy.ps1 logs" >&2
fi

# Sao lưu PostgreSQL hằng ngày lúc 03:00 (giờ VPS) bằng crontab của tài khoản này.
if command -v crontab >/dev/null; then
  entry="0 3 * * * bash $PWD/backup.sh >> $PWD/backup.log 2>&1"
  { crontab -l 2>/dev/null | grep -vF "$PWD/backup.sh" || true; echo "$entry"; } | crontab -
else
  echo "  [!] VPS chua co cron nen chua bat sao luu tu dong; chay lai setup-server." >&2
fi

# Chỉ xóa image ứng dụng SCAP cũ vừa bị thay; không prune image của dự án khác.
new_image_id=$(docker image inspect --format '{{.Id}}' "$APP_IMAGE")
if [ -n "$old_image_id" ] && [ "$old_image_id" != "$new_image_id" ]; then
  docker image rm "$old_image_id" >/dev/null 2>&1 || true
fi
