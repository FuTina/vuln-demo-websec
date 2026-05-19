#!/bin/sh
set -eu

APP_PASSWORD="$(cat /run/secrets/postgres_app_password)"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=app_password="$APP_PASSWORD" <<'SQL'
CREATE ROLE app_user LOGIN PASSWORD :'app_password';
CREATE SCHEMA IF NOT EXISTS app AUTHORIZATION app_user;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE playground FROM PUBLIC;
GRANT CONNECT ON DATABASE playground TO app_user;
GRANT USAGE, CREATE ON SCHEMA app TO app_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA app
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
SQL
