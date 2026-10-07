#!/usr/bin/env bash
# Khôi phục PostgreSQL của SCAP từ một bản của backup.sh (chạy trong ~/scap-vps):
#   bash restore.sh backups/20261007T030000Z           # chỉ khi DB chưa có người dùng
#   bash restore.sh backups/20261007T030000Z --force   # ghi đè DB đang có dữ liệu
# Cần đúng deploy/.env.vps đã dùng lúc sao lưu. Sau khi khôi phục, mọi phiên đăng
# nhập/token sinh ra sau thời điểm sao lưu không còn; đối chiếu audit trước khi dùng.
# $POSTGRES_* trong các lệnh db_exec được mở rộng bên trong container db.
# shellcheck disable=SC2016
set -euo pipefail

cd "$(dirname "$0")"
die() { echo "  [X] $*" >&2; exit 1; }
compose() { bash ./vps-compose.sh "$@"; }
db_exec() { compose exec -T db sh -c "PGPASSWORD=\"\$POSTGRES_PASSWORD\" exec $1"; }

[ $# -ge 1 ] && [ $# -le 2 ] || die "Cach dung: bash restore.sh backups/<thoi-diem> [--force]"
dir=${1%/}
force=${2:-}
[ -z "$force" ] || [ "$force" = --force ] || die "Tham so thu hai chi co the la --force."
[ -f "$dir/postgres.dump" ] && [ -f "$dir/SHA256SUMS" ] || die "Khong thay $dir/postgres.dump va SHA256SUMS."
(cd "$dir" && sha256sum --check --quiet SHA256SUMS) || die "Checksum khong khop; ban sao luu bi hong."

echo "==> Khoi dong PostgreSQL"
compose up -d db
for _ in $(seq 1 30); do
  if db_exec 'pg_isready -q -U "$POSTGRES_USER" -d "$POSTGRES_DB"'; then break; fi
  sleep 2
done
users=$(db_exec 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tA -c "SELECT count(*) FROM users"' 2>/dev/null || echo 0)
if [ "${users:-0}" != 0 ] && [ "$force" != --force ]; then
  die "DB dang co $users nguoi dung. Them --force neu chac chan muon ghi de (nen chay backup.sh truoc)."
fi

echo "==> Dung app/caddy va nap $dir"
compose stop caddy app
if ! db_exec 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --single-transaction --exit-on-error' \
    < "$dir/postgres.dump"; then
  compose up -d --no-build
  die "pg_restore that bai; DB giu nguyen trang thai truoc khi nap (single transaction)."
fi

echo "==> Chay migration va khoi dong lai"
compose up -d --no-build
compose ps
echo "  [OK] Da khoi phuc $dir."
