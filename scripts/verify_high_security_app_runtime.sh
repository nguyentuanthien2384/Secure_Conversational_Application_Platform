#!/bin/sh
set -eu

# Exercise the production secret-staging entrypoint in the image that CI scans.
# No service dependency is contacted; the probe is bounded to a read-only,
# network-isolated container and verifies the final unprivileged process state.

image_ref=${1:-}
if [ -z "$image_ref" ]; then
  echo >&2 "usage: $0 IMAGE_REFERENCE"
  exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
  echo >&2 "required command is unavailable: docker"
  exit 1
fi

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

for secret_name in \
  internal_ca_cert app_db_password app_secret vault_token \
  oidc_proxy_secret audit_worm_token redis_password
do
  printf '%s\n' "ci-runtime-secret-$secret_name-0123456789abcdef" \
    > "$probe_dir/$secret_name"
done

mount_secret() {
  secret_name=$1
  printf '%s' \
    "--mount=type=bind,src=$probe_dir/$secret_name,dst=/run/secrets/$secret_name,readonly"
}

probe_output=$(
  docker run --rm \
    --network none \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --user 0:0 \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add SETUID \
    --cap-add SETGID \
    --cap-add DAC_READ_SEARCH \
    --security-opt no-new-privileges:true \
    -e REQUIRE_HIGH_APP_SECRETS=true \
    -e DATABASE_PASSWORD_SECRET_NAME=app_db_password \
    "$(mount_secret internal_ca_cert)" \
    "$(mount_secret app_db_password)" \
    "$(mount_secret app_secret)" \
    "$(mount_secret vault_token)" \
    "$(mount_secret oidc_proxy_secret)" \
    "$(mount_secret audit_worm_token)" \
    "$(mount_secret redis_password)" \
    --entrypoint /bin/sh \
    "$image_ref" \
    /app/scripts/high_security_app_entrypoint.sh /bin/sh -eu -c '
      test "$(id -un)" = app
      test "$(id -u)" -ne 0
      test "$HOME" = /app
      grep -Eq "^NoNewPrivs:[[:space:]]+1$" /proc/self/status
      for capability_set in CapInh CapPrm CapEff CapAmb; do
        grep -Eq "^${capability_set}:[[:space:]]+0{16}$" /proc/self/status
      done
      for staged_secret in \
        internal_ca.crt combined-ca.crt database_password app_secret \
        vault_token oidc_proxy_secret audit_worm_token redis_password
      do
        test "$(stat -c %a "/tmp/scap-runtime-secrets/$staged_secret")" = 400
        test "$(stat -c %U "/tmp/scap-runtime-secrets/$staged_secret")" = app
      done
      test -z "${APP_SECRET_KEY:-}"
      test -z "${VAULT_TOKEN:-}"
      test -z "${OIDC_PROXY_SECRET:-}"
      test -z "${AUDIT_WORM_TOKEN:-}"
      test -z "${REDIS_PASSWORD:-}"
      printf "%s\n" high-security-app-runtime-ok
    '
)

if [ "$probe_output" != "high-security-app-runtime-ok" ]; then
  echo >&2 "unexpected high-security runtime probe result"
  exit 1
fi
printf '%s\n' "$probe_output"
