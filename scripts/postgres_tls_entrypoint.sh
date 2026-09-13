#!/bin/sh
set -eu

# PostgreSQL refuses a server key that is readable by other users. Compose file
# secrets are bind-mounted with host-dependent permissions, so copy the three
# public/private TLS files into ephemeral container storage with deterministic
# ownership and modes before handing control to the official entrypoint.
tls_dir=/tmp/scap-postgres-tls
secret_dir=/tmp/scap-postgres-secrets
umask 077
mkdir -p "$tls_dir"
mkdir -p "$secret_dir"
chmod 0700 "$tls_dir"
chmod 0700 "$secret_dir"
cp /run/secrets/internal_ca_cert "$tls_dir/ca.crt"
cp /run/secrets/postgres_server_cert "$tls_dir/server.crt"
cp /run/secrets/postgres_server_key "$tls_dir/server.key"
chmod 0644 "$tls_dir/ca.crt" "$tls_dir/server.crt"
chmod 0600 "$tls_dir/server.key"

# Compose file secrets may be root-owned 0600 bind mounts. Stage all database
# credentials while the wrapper still has read-search capability, then give
# only the postgres account access before the official image drops privileges.
cp /run/secrets/postgres_password "$secret_dir/postgres_password"
cp /run/secrets/app_db_password "$secret_dir/app_db_password"
cp /run/secrets/auditor_db_password "$secret_dir/auditor_db_password"
chmod 0400 "$secret_dir/postgres_password" \
  "$secret_dir/app_db_password" \
  "$secret_dir/auditor_db_password"
chown -R postgres:postgres "$tls_dir" "$secret_dir"
export POSTGRES_PASSWORD_FILE="$secret_dir/postgres_password"
export APP_DB_PASSWORD_FILE="$secret_dir/app_db_password"
export AUDITOR_DB_PASSWORD_FILE="$secret_dir/auditor_db_password"

# Init hooks only run for a brand-new PGDATA. Re-apply the idempotent HBA guard
# before every start so an older persistent volume cannot retain cleartext host
# rules after the deployment is upgraded to the high-security overlay.
data_dir=${PGDATA:-/var/lib/postgresql/data}
if [ -s "$data_dir/PG_VERSION" ]; then
  gosu postgres /bin/sh /opt/scap/enforce-postgres-tls.sh
fi

exec /usr/local/bin/docker-entrypoint.sh "$@"
