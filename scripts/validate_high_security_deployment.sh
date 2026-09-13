#!/bin/sh
set -eu

# Reproducible, secret-safe static validation for the production overlays. This
# script intentionally uses `docker compose config --quiet`: a rendered config
# would place secret-bearing host paths and deployment metadata in CI logs.

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo >&2 "required command is unavailable: $1"
    exit 1
  fi
}

require_digest_ref() {
  variable_name=$1
  case "$variable_name" in
    BASE_IMAGE) image_ref=${BASE_IMAGE:-} ;;
    POSTGRES_IMAGE) image_ref=${POSTGRES_IMAGE:-} ;;
    REDIS_IMAGE) image_ref=${REDIS_IMAGE:-} ;;
    CADDY_IMAGE) image_ref=${CADDY_IMAGE:-} ;;
    *)
      echo >&2 "unsupported image variable: $variable_name"
      exit 1
      ;;
  esac
  if ! printf '%s' "$image_ref" \
    | grep -Eq '^[^[:space:]@]+@sha256:[0-9a-f]{64}$'; then
    echo >&2 "$variable_name must be an immutable name@sha256 reference"
    exit 1
  fi
}

require_command docker
require_command grep
require_digest_ref BASE_IMAGE
require_digest_ref POSTGRES_IMAGE
require_digest_ref REDIS_IMAGE
require_digest_ref CADDY_IMAGE

probe_dir=$(mktemp -d)
case "$probe_dir" in
  /tmp/* | /private/tmp/*) ;;
  *)
    echo >&2 "refusing to use unexpected temporary directory: $probe_dir"
    exit 1
    ;;
esac
cleanup() {
  rm -rf -- "$probe_dir"
}
trap cleanup EXIT HUP INT TERM
umask 077

# Compose only validates paths here; these placeholders are never started or
# printed and contain no production credentials.
for secret_name in \
  app_secret postgres_password app_db_password auditor_db_password \
  redis_password vault_token oidc_proxy_secret audit_worm_token \
  internal_ca_cert postgres_server_cert postgres_server_key \
  redis_server_cert redis_server_key
do
  printf '%s\n' "ci-placeholder-$secret_name" > "$probe_dir/$secret_name"
done

export PUBLIC_DOMAIN=chat.example.test
export CADDY_EMAIL=security@example.test
export SECURITY_TXT_EXPIRES=2027-01-01T00:00:00Z
export VAULT_ADDR=https://vault.example.test
export AUDIT_WORM_ENDPOINT=https://audit.example.test/checkpoints
export APP_SECRET_KEY_FILE_HOST="$probe_dir/app_secret"
export POSTGRES_PASSWORD_FILE_HOST="$probe_dir/postgres_password"
export APP_DB_PASSWORD_FILE_HOST="$probe_dir/app_db_password"
export AUDITOR_DB_PASSWORD_FILE_HOST="$probe_dir/auditor_db_password"
export REDIS_PASSWORD_FILE_HOST="$probe_dir/redis_password"
export VAULT_TOKEN_FILE_HOST="$probe_dir/vault_token"
export OIDC_PROXY_SECRET_FILE_HOST="$probe_dir/oidc_proxy_secret"
export AUDIT_WORM_TOKEN_FILE_HOST="$probe_dir/audit_worm_token"
export INTERNAL_CA_CERT_FILE_HOST="$probe_dir/internal_ca_cert"
export POSTGRES_SERVER_CERT_FILE_HOST="$probe_dir/postgres_server_cert"
export POSTGRES_SERVER_KEY_FILE_HOST="$probe_dir/postgres_server_key"
export REDIS_SERVER_CERT_FILE_HOST="$probe_dir/redis_server_cert"
export REDIS_SERVER_KEY_FILE_HOST="$probe_dir/redis_server_key"

docker compose \
  --env-file /dev/null \
  -f docker-compose.yml \
  -f docker-compose.high-security.yml \
  config --quiet

for shell_script in scripts/*.sh; do
  sh -n "$shell_script"
done

# Validate the real edge policy using the reviewed, digest-pinned Caddy image.
# The validator gets no network and cannot write outside its small tmpfs.
docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges:true \
  -e PUBLIC_DOMAIN="$PUBLIC_DOMAIN" \
  -e CADDY_EMAIL="$CADDY_EMAIL" \
  -e SECURITY_TXT_EXPIRES="$SECURITY_TXT_EXPIRES" \
  --mount "type=bind,src=$repo_dir/Caddyfile,dst=/etc/caddy/Caddyfile,readonly" \
  "$CADDY_IMAGE" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile

echo "High-security Compose, shell entrypoints, and Caddy policy validated."
