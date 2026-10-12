#!/usr/bin/env bash
# docker compose cho SCAP trên VPS với đúng env-file, tên project và overlay.
#   Repo git (Termius):        bash deploy/vps-compose.sh ps
#   Gói upload (deploy.ps1):   ./vps-compose.sh logs --tail 50 app
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# Repo git để script trong deploy/; gói upload để script cạnh docker-compose.yml.
if [ "$(basename "$here")" = deploy ] && [ -f "$here/../docker-compose.yml" ]; then
  cd "$here/.."
else
  cd "$here"
fi
files=(-f docker-compose.yml -f docker-compose.vps-demo.yml)
mode=$({ grep -m1 '^SCAP_EDGE_MODE=' deploy/.env.vps || true; } | cut -d= -f2-)
if [ "$mode" = shared-proxy ]; then
  files+=(-f docker-compose.shared-proxy.yml)
fi
exec docker compose --env-file deploy/.env.vps -p scap-vps-demo "${files[@]}" "$@"
