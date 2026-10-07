#!/usr/bin/env bash
# docker compose cho SCAP trên VPS với đúng env-file, tên project và overlay.
# Chạy trong ~/scap-vps, ví dụ: ./vps-compose.sh ps   |   ./vps-compose.sh logs --tail 50 app
set -euo pipefail

cd "$(dirname "$0")"
files=(-f docker-compose.yml -f docker-compose.vps-demo.yml)
mode=$({ grep -m1 '^SCAP_EDGE_MODE=' deploy/.env.vps || true; } | cut -d= -f2-)
if [ "$mode" = shared-proxy ]; then
  files+=(-f docker-compose.shared-proxy.yml)
fi
exec docker compose --env-file deploy/.env.vps -p scap-vps-demo "${files[@]}" "$@"
