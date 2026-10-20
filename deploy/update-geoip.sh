#!/usr/bin/env bash
# Lam moi co so du lieu GeoIP (DB-IP City Lite) roi khoi dong lai app khi co ban moi.
# Chay tay trong Termius hoac dat cron hang ngay (chi tai khi ban hien tai > 25 ngay):
#   17 3 * * * cd /root/scap && bash deploy/update-geoip.sh >> /var/log/scap-geoip.log 2>&1
set -euo pipefail

cd "$(dirname "$0")/.."
geoip_dir=$({ grep -m1 '^SCAP_SECURITY_FILES_DIR=' deploy/.env.vps || true; } | cut -d= -f2-)
if [ "$({ grep -m1 '^GEOIP_BACKEND=' deploy/.env.vps || true; } | cut -d= -f2-)" != maxmind ] || [ -z "$geoip_dir" ]; then
  echo "GeoIP dang tat (GEOIP_BACKEND khac maxmind hoac thieu SCAP_SECURITY_FILES_DIR); bo qua."
  exit 0
fi
database="$geoip_dir/geoip-city.mmdb"
before=$(stat -c %Y "$database" 2>/dev/null || echo 0)
PYTHONDONTWRITEBYTECODE=1 python3 -m scripts.update_geoip --dir "$geoip_dir" --refresh-after-days 25
after=$(stat -c %Y "$database" 2>/dev/null || echo 0)
if [ "$before" != "$after" ]; then
  # App doc file luc khoi dong; khoi dong lai de nap ban moi (gian doan vai giay).
  bash deploy/vps-compose.sh restart app
fi
