#!/usr/bin/env bash
# Khôi phục PostgreSQL của SCAP từ một bản của backup.sh. Đường dẫn tính từ gốc
# repo git (hoặc ~/scap-vps với gói upload):
#   bash deploy/restore.sh backups/20261007T030000Z           # chỉ khi DB chưa có người dùng
#   bash deploy/restore.sh backups/20261007T030000Z --force   # ghi đè DB đang có dữ liệu
# Restore luôn giữ app/caddy offline và khóa tài khoản/proof cũ. Sau đối chiếu:
#   bash deploy/restore.sh --activate-reviewed-user ten.admin
#   bash deploy/restore.sh --resume-reviewed
# Cần đúng deploy/.env.vps và các phiên bản khóa lúc sao lưu.
# $POSTGRES_* trong các lệnh db_exec được mở rộng bên trong container db.
# shellcheck disable=SC2016
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
if [ "$(basename "$here")" = deploy ] && [ -f "$here/../docker-compose.yml" ]; then
  cd "$here/.."   # repo git: backups/ nằm ở gốc repo (đã .gitignore)
else
  cd "$here"
fi
die() { echo "  [X] $*" >&2; exit 1; }
compose() { bash "$here/vps-compose.sh" "$@"; }
db_exec() { compose exec -T db sh -c "PGPASSWORD=\"\$POSTGRES_PASSWORD\" exec $1"; }
marker=deploy/.restore-pending
quarantine_job() {
  compose run --rm --no-deps migrate /app/.venv/bin/python \
    -m scripts.quarantine_restored_database "$@"
}

if [ "${1:-}" = --activate-reviewed-user ]; then
  [ $# -eq 2 ] || die "Can dung mot ten tai khoan da doi chieu."
  [ -f "$marker" ] && [ "$(cat "$marker")" = quarantined ] \
    || die "Snapshot chua quarantine thanh cong; khong mo tai khoan."
  quarantine_job activate-reviewed-user -- "$2"
  echo "  [OK] Da bat tai khoan duoc chi dinh; app/caddy van offline."
  exit 0
fi
if [ "${1:-}" = --resume-reviewed ]; then
  [ $# -eq 1 ] || die "--resume-reviewed khong nhan tham so khac."
  [ -f "$marker" ] && [ "$(cat "$marker")" = quarantined ] \
    || die "Snapshot chua quarantine thanh cong; khong mo traffic."
  admins=$(db_exec 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tA -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM users WHERE is_active AND role = '\''admin'\''"')
  [[ "$admins" =~ ^[1-9][0-9]*$ ]] || die "Can doi chieu va bat it nhat mot admin truoc."
  mv "$marker" deploy/.restore-reviewed
  if ! bash "$here/remote-deploy.sh"; then
    mv deploy/.restore-reviewed "$marker"
    compose stop caddy app || true
    die "Readiness/deploy gate chua dat; app/caddy da dung, can --resume-reviewed lai."
  fi
  rm -f deploy/.restore-reviewed
  exit 0
fi

[ $# -ge 1 ] && [ $# -le 2 ] || die "Cach dung: bash deploy/restore.sh backups/<thoi-diem> [--force]"
dir=${1%/}
force=${2:-}
[ -z "$force" ] || [ "$force" = --force ] || die "Tham so thu hai chi co the la --force."
[ -f "$dir/postgres.dump" ] && [ -f "$dir/SHA256SUMS" ] || die "Khong thay $dir/postgres.dump va SHA256SUMS."
(cd "$dir" && sha256sum --check --quiet SHA256SUMS) || die "Checksum khong khop; ban sao luu bi hong."

echo "==> Khoi dong PostgreSQL"
compose up -d db
ready=0
for _ in $(seq 1 30); do
  if db_exec 'pg_isready -q -U "$POSTGRES_USER" -d "$POSTGRES_DB"'; then ready=1; break; fi
  sleep 2
done
[ "$ready" -eq 1 ] || die "PostgreSQL chua san sang; chua restore."
has_users=$(db_exec 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tA -v ON_ERROR_STOP=1 -c "SELECT to_regclass('\''public.users'\'') IS NOT NULL"')
[[ "$has_users" = t || "$has_users" = f ]] || die "Khong xac minh duoc schema DB; chua restore."
users=0
if [ "$has_users" = t ]; then
  users=$(db_exec 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tA -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM users"')
fi
[[ "$users" =~ ^[0-9]+$ ]] || die "Khong xac minh duoc tinh trang DB; chua restore."
if [ "${users:-0}" != 0 ] && [ "$force" != --force ]; then
  die "DB dang co $users nguoi dung. Them --force neu chac chan muon ghi de (nen chay backup.sh truoc)."
fi

echo "==> Dung app/caddy va nap $dir"
umask 077
printf '%s\n' restoring > "$marker"
compose stop caddy app
if ! db_exec 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --single-transaction --exit-on-error' \
    < "$dir/postgres.dump"; then
  die "pg_restore that bai; app/caddy van offline, DB giu trang thai truoc khi nap."
fi

echo "==> Chay migration moi va quarantine credential snapshot"
compose run --rm --no-deps migrate
quarantine_job quarantine
printf '%s\n' quarantined > "$marker"
echo "  [OK] Da nap va quarantine $dir; app/caddy van OFFLINE."
echo "      Doi chieu account/password/MFA/email/passkey, E2EE device/member/epoch va audit/checkpoint."
echo "      Sau do --activate-reviewed-user <ten> va --resume-reviewed de kiem tra readiness/HTTPS."
