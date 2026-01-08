#!/bin/bash
set -e

if [ -z "$GOLYN_DB_PASSWORD" ]; then
  echo "[ERROR] GOLYN_DB_PASSWORD is not set"
  exit 1
fi

psql -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" <<EOSQL

DO
\$\$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_roles WHERE rolname = 'golyn_user'
    ) THEN
        EXECUTE format(
            'CREATE ROLE golyn_user WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT',
            '${GOLYN_DB_PASSWORD}'
        );
    END IF;
END
\$\$;

EOSQL
