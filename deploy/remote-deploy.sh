#!/usr/bin/env bash
# Khởi động/cập nhật SCAP trên VPS. Hai cách gọi:
#  - Repo git (Termius): deploy/update.sh build image rồi gọi file này.
#  - Gói upload: deploy/deploy.ps1 tải lên ~/scap-vps cùng scap-deploy.tar,
#    scap-image.tar.gz (tùy chọn) và deploy/.env.vps rồi gọi file này.
# Không tạo lại khóa, không xóa volume dữ liệu, không đụng image/container khác.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
if [ "$(basename "$HERE")" = deploy ] && [ -f "$HERE/../docker-compose.yml" ]; then
  ROOT=$(dirname "$HERE")
else
  ROOT=$HERE
fi
cd "$ROOT"
ENV_FILE=deploy/.env.vps

compose() { bash "$HERE/vps-compose.sh" "$@"; }
die() { echo "  [X] $*" >&2; exit 1; }
setting() { { grep -m1 "^$1=" "$ENV_FILE" || true; } | cut -d= -f2-; }

[ -f "$ENV_FILE" ] || die "Thieu $ENV_FILE tren VPS."
[ ! -f deploy/.restore-pending ] \
  || die "Snapshot dang offline/quarantine; doi chieu bang restore.sh truoc --resume-reviewed."
chmod 700 deploy
chmod 600 "$ENV_FILE"
# scp từ Windows không giữ bit thực thi; repo git thì để nguyên để git pull không vướng.
if [ ! -d .git ]; then
  chmod u+x "$HERE/remote-deploy.sh" "$HERE/vps-compose.sh" "$HERE/backup.sh" "$HERE/restore.sh"
fi

if [ -f scap-deploy.tar ]; then
  echo "==> Giai nen cau hinh"
  # Postgres và Caddy đọc file bind-mount bằng user khác và không có
  # CAP_DAC_OVERRIDE, nên cấu hình công khai phải đọc được (644/755).
  (umask 022 && tar -xf scap-deploy.tar --no-same-owner)
  chmod -R u=rwX,go=rX docker-compose.yml docker-compose.vps-demo.yml docker-compose.shared-proxy.yml \
    Caddyfile Caddyfile.shared-proxy deploy/shared-proxy-site.caddy scripts src
  if [ -f docker-compose.security-channels.yml ]; then
    chmod u=rw,go=r docker-compose.security-channels.yml
  fi
  rm -f scap-deploy.tar
fi

if python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
  PYTHONDONTWRITEBYTECODE=1 python3 -m scripts.prepare_vps check --project . \
    || die "Cau hinh chua dat; sua deploy/.env.vps theo danh sach tren roi chay lai."
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
  || die "VPS chua co image $APP_IMAGE; chay bash deploy/update.sh (hoac deploy.ps1 deploy khong kem -SkipBuild)."
expected_image_id=$(docker image inspect --format '{{.Id}}' "$APP_IMAGE")
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
# Caddyfile được bind-mount theo từng file: git pull/tar ghi file mới (inode mới) nên
# container đang chạy vẫn thấy bản cũ. Tạo lại Caddy của SCAP (vài giây) để luôn dùng
# bản vừa cập nhật; dữ liệu và chứng chỉ nằm trong volume nên không mất.
compose up -d --no-deps --force-recreate caddy
compose ps

# A mutable tag can hide a stale app/migration container. Compare the actual
# content IDs after Compose has run, and require the matching migration to
# have completed successfully before accepting the deployment.
verify_service_image() {
  local service=$1 expected_state=$2 containers container image_id state exit_code
  containers=$(compose ps --all --quiet "$service")
  [ -n "$containers" ] || die "Khong tim thay container $service sau deploy."
  for container in $containers; do
    read -r image_id state exit_code <<< "$(docker inspect --format '{{.Image}} {{.State.Status}} {{.State.ExitCode}}' "$container")"
    [ "$image_id" = "$expected_image_id" ] \
      || die "Container $service khong dung image vua deploy; kiem tra migrate/app truoc khi tiep tuc."
    [ "$state" = "$expected_state" ] \
      || die "Container $service co trang thai $state, can $expected_state."
    if [ "$service" = migrate ] && [ "$exit_code" != 0 ]; then
      die "Migration that bai (ma loi $exit_code); chua xac nhan deploy thanh cong."
    fi
  done
}
verify_service_image migrate exited
verify_service_image app running
app_containers=$(compose ps --all --quiet app)
[ -n "$app_containers" ] || die "Khong tim thay container app de kiem tra readiness."

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

echo "==> Kiem tra readiness noi bo va https://$DOMAIN/api/health (cho Caddy xin chung chi)"
healthy=0
command -v curl >/dev/null || die "VPS thieu curl; chay lai setup-server."
for _ in $(seq 1 30); do
  ready=1
  for container in $app_containers; do
    # The image HEALTHCHECK probes /api/ready inside the container. Caddy
    # deliberately keeps that dependency endpoint inaccessible publicly.
    health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$container") || health=unknown
    [ "$health" = healthy ] || ready=0
  done
  if [ "$ready" -eq 1 ] && curl -fsS -o /dev/null --max-time 5 "https://$DOMAIN/api/health"; then
    healthy=1
    break
  fi
  sleep 4
done
if [ "$healthy" -eq 1 ]; then
  echo "  [OK] App/migration dung image; readiness va https://$DOMAIN deu dat."
else
  echo "  [!] Readiness noi bo hoac https://$DOMAIN chua dat. Kiem tra DNS va log:" >&2
  echo "      bash $HERE/vps-compose.sh logs --tail 80 caddy app migrate" >&2
  die "Deploy chua san sang; khong bao thanh cong."
fi

# Sao lưu PostgreSQL hằng ngày lúc 03:00 (giờ VPS) bằng crontab của tài khoản này.
if command -v crontab >/dev/null; then
  entry="0 3 * * * bash $HERE/backup.sh >> $ROOT/backup.log 2>&1"
  { crontab -l 2>/dev/null | grep -vF "$HERE/backup.sh" || true; echo "$entry"; } | crontab -
else
  echo "  [!] VPS chua co cron nen chua bat sao luu tu dong: apt-get install -y cron roi chay lai." >&2
fi

# Chỉ xóa image ứng dụng SCAP cũ vừa bị thay; không prune image của dự án khác.
new_image_id=$(docker image inspect --format '{{.Id}}' "$APP_IMAGE")
if [ -n "$old_image_id" ] && [ "$old_image_id" != "$new_image_id" ]; then
  docker image rm "$old_image_id" >/dev/null 2>&1 || true
fi
