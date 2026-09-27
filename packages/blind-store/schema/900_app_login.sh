#!/bin/sh
# Gives the service role its login, once, when the database is first created.
# The schema (000_blind_store.sql) creates blind_store_app NOLOGIN; the
# password comes from a secret file (BLIND_STORE_APP_PASSWORD_FILE, a Docker
# secret) or, for an example or a test, the environment
# (BLIND_STORE_APP_PASSWORD). It is passed to psql as a variable, never
# printed and never placed in a SQL string by hand.
set -eu

PW=""
if [ -n "${BLIND_STORE_APP_PASSWORD_FILE:-}" ] && [ -r "$BLIND_STORE_APP_PASSWORD_FILE" ]; then
  PW="$(cat "$BLIND_STORE_APP_PASSWORD_FILE")"
fi
if [ -z "$PW" ] && [ -n "${BLIND_STORE_APP_PASSWORD:-}" ]; then
  PW="$BLIND_STORE_APP_PASSWORD"
fi
if [ -z "$PW" ]; then
  echo "900_app_login: set BLIND_STORE_APP_PASSWORD_FILE (a secret) or BLIND_STORE_APP_PASSWORD; the service role has no login" >&2
  exit 1
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v pw="$PW" <<'SQL'
ALTER ROLE blind_store_app LOGIN PASSWORD :'pw';
SQL
echo "900_app_login: blind_store_app can log in"
