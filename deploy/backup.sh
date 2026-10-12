#!/usr/bin/env bash
# Sao lưu PostgreSQL của SCAP trên VPS (bằng tay hoặc cron):
#   bash deploy/backup.sh  (repo git)  |  bash backup.sh  (~/scap-vps)
#   ->  backups/<thời-điểm UTC>/postgres.dump + SHA256SUMS, giữ 14 bản
# Khôi phục bằng restore.sh. Bản dump chỉ dùng được cùng deploy/.env.vps lúc sao
# lưu (khóa mã hóa nội dung); giữ file đó trên máy cá nhân, không để trong backups/.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
if [ "$(basename "$here")" = deploy ] && [ -f "$here/../docker-compose.yml" ]; then
  cd "$here/.."   # repo git: backups/ nằm ở gốc repo (đã .gitignore)
else
  cd "$here"
fi
umask 077
keep=${SCAP_BACKUP_KEEP:-14}
stamp=$(date -u +%Y%m%dT%H%M%SZ)
dir=backups/$stamp

mkdir -p backups
chmod 700 backups
mkdir "$dir"
# Mật khẩu chủ DB chỉ nằm trong môi trường container db, không qua tham số lệnh.
if ! bash "$here/vps-compose.sh" exec -T db sh -c \
    'PGPASSWORD="$POSTGRES_PASSWORD" exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom' \
    > "$dir/postgres.dump"; then
  rm -rf "$dir"
  echo "  [X] pg_dump that bai; stack SCAP co dang chay khong? (bash $here/vps-compose.sh ps)" >&2
  exit 1
fi
(cd "$dir" && sha256sum postgres.dump > SHA256SUMS)
echo "  [OK] $dir ($(du -h "$dir/postgres.dump" | cut -f1))"

# Tên thư mục là thời điểm UTC nên thứ tự chữ cái cũng là thứ tự thời gian.
find backups -mindepth 1 -maxdepth 1 -type d -name '20*Z' | sort | head -n "-$keep" \
  | while read -r old; do rm -rf "$old"; done
