#!/bin/sh
set -eu

if [ -z "${APP_DB_PASSWORD:-}" ] && [ -n "${APP_DB_PASSWORD_FILE:-}" ]; then
  APP_DB_PASSWORD=$(tr -d '\r\n' < "$APP_DB_PASSWORD_FILE")
fi
if [ -z "${AUDITOR_DB_PASSWORD:-}" ] && [ -n "${AUDITOR_DB_PASSWORD_FILE:-}" ]; then
  AUDITOR_DB_PASSWORD=$(tr -d '\r\n' < "$AUDITOR_DB_PASSWORD_FILE")
fi
: "${APP_DB_PASSWORD:?APP_DB_PASSWORD or APP_DB_PASSWORD_FILE is required}"
: "${AUDITOR_DB_PASSWORD:?AUDITOR_DB_PASSWORD or AUDITOR_DB_PASSWORD_FILE is required}"

export SCAP_APP_DB_PASSWORD="$APP_DB_PASSWORD"
export SCAP_AUDITOR_DB_PASSWORD="$AUDITOR_DB_PASSWORD"
psql \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  --file /opt/scap/db_least_privilege.sql

# This hook may be sourced by the official image when bind-mounted without an
# executable bit. Do not leave plaintext role passwords in that parent shell.
unset APP_DB_PASSWORD AUDITOR_DB_PASSWORD \
  SCAP_APP_DB_PASSWORD SCAP_AUDITOR_DB_PASSWORD
