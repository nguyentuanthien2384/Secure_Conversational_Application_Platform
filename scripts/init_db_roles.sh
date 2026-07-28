#!/bin/sh
set -eu

: "${APP_DB_PASSWORD:?APP_DB_PASSWORD is required}"
: "${AUDITOR_DB_PASSWORD:?AUDITOR_DB_PASSWORD is required}"

psql \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  --set app_password="$APP_DB_PASSWORD" \
  --set auditor_password="$AUDITOR_DB_PASSWORD" \
  --file /opt/scap/db_least_privilege.sql
