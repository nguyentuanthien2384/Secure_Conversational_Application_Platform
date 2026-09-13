#!/bin/sh
set -eu

# Init scripts run after initdb has generated pg_hba.conf. Put explicit rejects
# before the image's broad `host ... scram-sha-256` records so no client on the
# backend network can downgrade to cleartext TCP. TLS clients fall through to
# the existing SCRAM rules.
hba_file="${PGDATA:?PGDATA is required}/pg_hba.conf"
hba_tmp="${PGDATA}/pg_hba.conf.scap-tls"
marker='# SCAP high-security: reject every non-TLS TCP connection first.'

# The wrapper also calls this script on every restart so upgraded installations
# with an existing data volume receive the policy. Keep that path idempotent.
if grep -Fqx "$marker" "$hba_file"; then
  exit 0
fi

{
  printf '%s\n' "$marker"
  printf '%s\n' 'hostnossl all all 0.0.0.0/0 reject'
  printf '%s\n' 'hostnossl all all ::0/0 reject'
  cat "$hba_file"
} > "$hba_tmp"
chmod 0600 "$hba_tmp"
mv "$hba_tmp" "$hba_file"
