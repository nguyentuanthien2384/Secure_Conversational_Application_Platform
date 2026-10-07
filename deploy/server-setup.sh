#!/usr/bin/env bash
# Chuẩn bị MỘT LẦN cho VPS Ubuntu/Debian (kể cả bản minimal của 123HOST):
# cập nhật OS, cài Docker Engine + Compose plugin từ kho chính thức của Docker,
# tạo tài khoản deploy đăng nhập bằng SSH key, thêm swap cho VPS RAM nhỏ, bật
# UFW chỉ mở cổng SSH thật (vd 2018)/80/443 và báo ai đang giữ cổng 80/443.
# Chạy lại an toàn; không đổi cấu hình SSH, không dừng dịch vụ hay container nào.
#
#   sudo bash server-setup.sh --deploy-user deploy --authorized-key id_ed25519.pub
set -euo pipefail

DEPLOY_USER=deploy
AUTHORIZED_KEY=
while [ $# -gt 0 ]; do
  case "$1" in
    --deploy-user) DEPLOY_USER=${2:?}; shift 2 ;;
    --authorized-key) AUTHORIZED_KEY=${2:?}; shift 2 ;;
    *) echo "Tham so khong hop le: $1" >&2; exit 2 ;;
  esac
done

die() { echo "  [X] $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "Can chay bang root hoac sudo."
[[ "$DEPLOY_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "Ten tai khoan deploy khong hop le."
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in
  ubuntu|debian) ;;
  *) die "Chi ho tro Ubuntu/Debian (VPS dang chay: ${PRETTY_NAME:-khong ro}). Cai lai OS Ubuntu LTS." ;;
esac

# Không hỏi gì giữa chừng: giữ sshd_config 123HOST đã sửa (cổng 2018) và tự
# khởi động lại dịch vụ sau khi nâng cấp thư viện (needrestart của Ubuntu 22.04).
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
APT_OPTS=(-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

echo "==> Cap nhat he dieu hanh"
apt-get update -q
apt-get upgrade "${APT_OPTS[@]}"
apt-get install "${APT_OPTS[@]}" ca-certificates curl python3 ufw cron iproute2

echo "==> Docker Engine + Compose plugin"
if docker compose version >/dev/null 2>&1; then
  echo "  Docker da co san: $(docker --version)"
else
  # Gói docker.io/podman của distro xung đột với gói chính thức.
  for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then apt-get remove "${APT_OPTS[@]}" "$pkg"; fi
  done
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$ID/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  codename=${UBUNTU_CODENAME:-$VERSION_CODENAME}
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$ID $codename stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get install "${APT_OPTS[@]}" docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker

echo "==> Swap"
if [ -n "$(swapon --show --noheadings)" ]; then
  echo "  Swap da co san."
elif [ "$(awk '/MemTotal/ {print int($2 / 1024)}' /proc/meminfo)" -ge 4096 ]; then
  echo "  RAM >= 4 GB, khong tao swap."
elif { fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none; } \
    && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile; then
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo "  Da tao swap 2 GB de giam nguy co OOM khi migrate/khoi dong."
else
  swapoff /swapfile 2>/dev/null || true
  rm -f /swapfile
  echo "  [!] VPS khong cho phep swap file; bo qua." >&2
fi

echo "==> Tai khoan $DEPLOY_USER"
if ! id "$DEPLOY_USER" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "$DEPLOY_USER"
  # '*' = không có mật khẩu nhưng không bị coi là khóa, nên vẫn đăng nhập bằng key.
  usermod -p '*' "$DEPLOY_USER"
fi
# Nhóm docker tương đương root trên host; chỉ cấp cho tài khoản vận hành này.
usermod -aG docker "$DEPLOY_USER"
home=$(getent passwd "$DEPLOY_USER" | cut -d: -f6)
install -d -m 700 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$home/.ssh" "$home/scap-vps"
if [ -n "$AUTHORIZED_KEY" ]; then
  key=$(head -n1 "$AUTHORIZED_KEY" | tr -d '\r')
  case "$key" in
    ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*) ;;
    *) die "File khoa cong khai khong hop le." ;;
  esac
  touch "$home/.ssh/authorized_keys"
  grep -qxF "$key" "$home/.ssh/authorized_keys" || printf '%s\n' "$key" >> "$home/.ssh/authorized_keys"
  chown "$DEPLOY_USER:$DEPLOY_USER" "$home/.ssh/authorized_keys"
  chmod 600 "$home/.ssh/authorized_keys"
fi

echo "==> Tuong lua UFW (SSH, 80, 443)"
ssh_ports=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' || true)
for port in ${ssh_ports:-22}; do ufw allow "$port/tcp" >/dev/null; done
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw --force enable >/dev/null
ufw status

echo "==> Cong 80/443"
listeners=$(ss -Hltnp '( sport = :80 or sport = :443 )' 2>/dev/null || true)
if [ -z "$listeners" ]; then
  echo "  Dang trong: dung SCAP_EDGE_MODE=direct (Caddy cua SCAP giu 80/443)."
elif printf '%s
' "$listeners" | grep -q docker-proxy; then
  echo "  Do container Docker khac giu (vd JobFind): dung SCAP_EDGE_MODE=shared-proxy."
else
  echo "  [!] Dich vu tren host dang giu cong 80/443:"
  printf '%s
' "$listeners" | awk '{print "      " $4 "  " $6}'
  echo "      Neu la addon khong dung (vd Caddy cua FlashVPS): systemctl disable --now caddy"
fi

echo "==> Hoan tat"
docker --version
docker compose version
if [ -f /var/run/reboot-required ]; then
  echo "  [!] Kernel vua cap nhat: nen chay 'reboot' roi moi deploy."
fi
