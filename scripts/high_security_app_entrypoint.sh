#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo >&2 'high-security entrypoint must start as root to stage file secrets'
  exit 1
fi

secret_dir=/tmp/scap-runtime-secrets
umask 077
mkdir -p "$secret_dir"
chmod 0700 "$secret_dir"

stage_secret() {
  source_path=$1
  target_name=$2
  if [ ! -f "$source_path" ]; then
    echo >&2 "required secret is not mounted: $source_path"
    exit 1
  fi
  cp "$source_path" "$secret_dir/$target_name"
  chmod 0400 "$secret_dir/$target_name"
}

stage_secret /run/secrets/internal_ca_cert internal_ca.crt
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
  cat /etc/ssl/certs/ca-certificates.crt "$secret_dir/internal_ca.crt" \
    > "$secret_dir/combined-ca.crt"
else
  cp "$secret_dir/internal_ca.crt" "$secret_dir/combined-ca.crt"
fi
chmod 0400 "$secret_dir/combined-ca.crt"
database_secret=${DATABASE_PASSWORD_SECRET_NAME:-app_db_password}
stage_secret "/run/secrets/$database_secret" database_password

if [ "${REQUIRE_HIGH_APP_SECRETS:-false}" = "true" ]; then
  stage_secret /run/secrets/app_secret app_secret
  stage_secret /run/secrets/vault_token vault_token
  stage_secret /run/secrets/oidc_proxy_secret oidc_proxy_secret
  stage_secret /run/secrets/audit_worm_token audit_worm_token
  stage_secret /run/secrets/redis_password redis_password
  export APP_SECRET_KEY_FILE="$secret_dir/app_secret"
  export VAULT_TOKEN_FILE="$secret_dir/vault_token"
  export OIDC_PROXY_SECRET_FILE="$secret_dir/oidc_proxy_secret"
  export AUDIT_WORM_TOKEN_FILE="$secret_dir/audit_worm_token"
  export REDIS_PASSWORD_FILE="$secret_dir/redis_password"
fi

export DATABASE_PASSWORD_FILE="$secret_dir/database_password"
export SSL_CERT_FILE="$secret_dir/combined-ca.crt"
chown -R app:app "$secret_dir"

# Remove every bootstrap capability after the read-only copies have been made.
exec /usr/bin/setpriv \
  --reuid app --regid app --init-groups \
  --no-new-privs --inh-caps=-all --ambient-caps=-all \
  -- "$@"
