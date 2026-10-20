#!/usr/bin/env bash
# Deploy/cập nhật SCAP ngay trên VPS từ code trên GitHub (quản lý bằng Termius):
#   cd /root/scap && bash deploy/update.sh
# Thứ tự: sao lưu DB (nếu đang chạy) -> git pull -> kiểm tra cấu hình -> build image
# -> deploy/remote-deploy.sh (migrate, khởi động, gắn tên miền vào Caddy JobFind).
# Giữ nguyên dữ liệu và khóa trong deploy/.env.vps; website SCAP chỉ gián đoạn lúc
# khởi động lại container. Lần đầu: docs/VPS_DEMO_DEPLOYMENT.md, mục Termius.
set -euo pipefail

# Cả quy trình nằm trong một hàm và "exit" cùng dòng gọi: bash đọc hết trước khi
# chạy, nên git pull sửa chính file này cũng không làm hỏng lần chạy hiện tại.
main() {
  cd "$(dirname "$0")/.."
  die() { echo "  [X] $*" >&2; exit 1; }
  [ -d .git ] || die "Chay trong thu muc git clone cua SCAP (vd /root/scap)."
  [ -f deploy/.env.vps ] \
    || die "Chua co deploy/.env.vps: tai file nay tu may Windows len bang SFTP cua Termius."
  chmod 700 deploy
  chmod 600 deploy/.env.vps

  echo "==> 1/4 Sao luu CSDL"
  if [ -n "$(bash deploy/vps-compose.sh ps -q db 2>/dev/null)" ]; then
    bash deploy/backup.sh
  else
    echo "  Chua co CSDL dang chay (lan deploy dau): bo qua."
  fi

  echo "==> 2/4 Lay code moi tu GitHub"
  git pull --ff-only

  echo "==> 3/4 Kiem tra cau hinh"
  if python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
    PYTHONDONTWRITEBYTECODE=1 python3 -m scripts.prepare_vps check --project . \
      || die "Sua deploy/.env.vps theo danh sach tren roi chay lai."
  else
    echo "  [!] VPS khong co Python >= 3.10; bo qua kiem tra truoc khi build." >&2
  fi

  # GeoIP bat: tai co so du lieu City (DB-IP Lite, hang thang) khi ban hien tai
  # da cu hon 25 ngay. Loi mang chi la canh bao neu file cu van con dung duoc.
  if [ "$({ grep -m1 '^GEOIP_BACKEND=' deploy/.env.vps || true; } | cut -d= -f2-)" = maxmind ]; then
    geoip_dir=$({ grep -m1 '^SCAP_SECURITY_FILES_DIR=' deploy/.env.vps || true; } | cut -d= -f2-)
    echo "==> GeoIP: kiem tra co so du lieu vi tri trong $geoip_dir"
    PYTHONDONTWRITEBYTECODE=1 python3 -m scripts.update_geoip --dir "$geoip_dir" --refresh-after-days 25 \
      || [ -f "$geoip_dir/geoip-city.mmdb" ] \
      || die "Chua co co so du lieu GeoIP; kiem tra Internet roi chay lai, hoac dat GEOIP_BACKEND=disabled."
  fi

  echo "==> 4/4 Build image (vai phut; JobFind van chay binh thuong)"
  bash deploy/vps-compose.sh build app

  bash deploy/remote-deploy.sh
}

main "$@"; exit
