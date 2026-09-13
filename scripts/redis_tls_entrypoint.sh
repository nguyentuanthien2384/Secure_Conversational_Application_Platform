#!/bin/sh
set -eu

tls_dir=/tmp/scap-redis-tls
umask 077
mkdir -p "$tls_dir"
chmod 0700 "$tls_dir"
cp /run/secrets/internal_ca_cert "$tls_dir/ca.crt"
cp /run/secrets/redis_server_cert "$tls_dir/server.crt"
cp /run/secrets/redis_server_key "$tls_dir/server.key"
chmod 0644 "$tls_dir/ca.crt" "$tls_dir/server.crt"
chmod 0600 "$tls_dir/server.key"

# Store only a SHA-256 ACL verifier in Redis runtime state. The original
# password remains in the file-backed secret used by the application client.
redis_password=$(tr -d '\r\n' < /run/secrets/redis_password)
if [ "${#redis_password}" -lt 32 ]; then
  echo >&2 'redis_password must contain at least 32 characters'
  exit 1
fi
redis_password_hash=$(printf '%s' "$redis_password" | sha256sum | cut -d ' ' -f 1)
unset redis_password
{
  printf '%s\n' 'user default on nopass ~* resetchannels -@all +ping'
  printf '%s\n' \
    "user scap on #$redis_password_hash ~scap:* resetchannels -@all +ping +eval +evalsha +zremrangebyscore +zcard +zrange +zadd +expire +del"
} > "$tls_dir/users.acl"
chmod 0600 "$tls_dir/users.acl"
chown -R redis:redis "$tls_dir"

exec /usr/local/bin/docker-entrypoint.sh "$@"
