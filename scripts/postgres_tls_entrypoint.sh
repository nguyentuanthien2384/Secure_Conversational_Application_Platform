#!/bin/sh
set -eu

# PostgreSQL refuses a server key that is readable by other users. Compose file
# secrets are bind-mounted with host-dependent permissions, so copy the three
# public/private TLS files into ephemeral container storage with deterministic
# ownership and modes before handing control to the official entrypoint.
tls_dir=/tmp/scap-postgres-tls
umask 077
mkdir -p "$tls_dir"
chown postgres:postgres "$tls_dir"
chmod 0700 "$tls_dir"
cp /run/secrets/internal_ca_cert "$tls_dir/ca.crt"
cp /run/secrets/postgres_server_cert "$tls_dir/server.crt"
cp /run/secrets/postgres_server_key "$tls_dir/server.key"
chown postgres:postgres "$tls_dir/ca.crt" "$tls_dir/server.crt" "$tls_dir/server.key"
chmod 0644 "$tls_dir/ca.crt" "$tls_dir/server.crt"
chmod 0600 "$tls_dir/server.key"

exec /usr/local/bin/docker-entrypoint.sh "$@"
